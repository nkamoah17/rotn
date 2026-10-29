# -*- coding: utf-8 -*-
"""mcp.py -- the MCP adapter (B4, second): the ``tools/call`` interceptor.

It speaks the JSON-RPC 2.0 surface of the Model Context Protocol (spec
``2025-06-18``) tool-calling half, so an MCP client (or the
``rot runtime serve`` gateway) can point at ROTN:

    request:  {"jsonrpc":"2.0","id":1,"method":"tools/call",
               "params":{"name":"transfer","arguments":{"amount":100},
                         "state":{"completed":0,"inflight":3}}}
    blocked:  {"jsonrpc":"2.0","id":1,"result":
                 {"isError":true,
                  "content":[{"type":"text","text":"<refusal JSON>"}],
                  "structuredContent":{
                      "blocked":true,"rule":"spendcap_within_cap",
                      "why":"3 in-flight requests are invisible to the "
                            "settled-trace monitor",
                      "to_proceed":"complete 1 in-flight (or cap inflight at 1)",
                      "allowed_now":false, ...}}}

The manifest (:mod:`rot.mcp_manifest`) is a **first-class input**: when one
is attached, ``tools/list`` returns the manifest's tool catalog and the
gateway guards *that server's tools* -- the same manifest the offline audit
(``rot check --manifest``) consumed, so the runtime plane and the offline
plane read one document.

Contract
--------

  * **Decision gate.**  The gateway *decides* each call through the
    deterministic core and never performs the tool itself; an ``allowed``
    result means the tool may proceed (the framework performs it).
  * **Fail-closed.**  A tool with no rule (and no default rule) is **blocked**
    with the canonical refusal shape (``rule: "no_rule"``) -- an unruled tool
    is never silently allowed.  Protocol-level failures are JSON-RPC errors.
  * **Auditable.**  Every decision (allow and deny) is appended to the
    optional :class:`~rot.runtime.ledger.DecisionLedger` -- the same ledger
    the LangChain adapter feeds, so ``rot coach --aggregate`` sees both.
  * **Zero dependencies.**  Pure stdlib (no ``mcp`` SDK required); the
    JSON-RPC surface is small and stable, and
    :func:`build_http_server` is a stdlib HTTP server for
    ``rot runtime serve``.

Methods
-------

    ping          -> "pong"
    tools/list    -> the manifest's tool catalog (or the guarded rule names)
    tools/call    -> the guard decision (allow/deny + the refusal JSON)
    rot/decide    -> the guard decision without recording (a probe)
    rot/rules     -> the rules the gateway enforces
    rot/ledger    -> the ledger so far

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from __future__ import print_function

import json

import rot
from .refusal import Refusal, SCHEMA as REFUSAL_SCHEMA
from .core import RuntimeGuard, Rule
from . import ledger as _ledger

__all__ = [
    "JSONRPC",
    "MCP_SCHEMA",
    "PARSE_ERROR",
    "INVALID_REQUEST",
    "METHOD_NOT_FOUND",
    "INVALID_PARAMS",
    "INTERNAL_ERROR",
    "McpError",
    "jsonrpc_error",
    "McpGateway",
    "intercept_tools_call",
    "build_http_server",
    "serve_forever",
]

#: The JSON-RPC version this gateway speaks.
JSONRPC = "2.0"

#: The gateway's own schema tag (for ``rot/rules`` / the HTTP info document).
MCP_SCHEMA = "caravel.mcp-adapter/v1"

# JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class McpError(Exception):
    """A JSON-RPC 2.0 protocol-level failure (code + message + optional data)."""

    def __init__(self, code, message, data=None):
        super(McpError, self).__init__(message)
        self.code = code
        self.message = message
        self.data = data


def jsonrpc_error(req_id, code, message, data=None):
    """A JSON-RPC 2.0 error response (for protocol-level failures)."""
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": JSONRPC, "id": req_id, "error": err}


def _parse_message(message):
    """Parse a JSON-RPC 2.0 message (dict or JSON string) and validate it.

    Raises
    ------
    McpError
        ``PARSE_ERROR`` / ``INVALID_REQUEST`` on a malformed message.
    """
    if isinstance(message, (bytes, bytearray)):
        message = message.decode("utf-8")
    if isinstance(message, str):
        try:
            message = json.loads(message)
        except ValueError:
            raise McpError(PARSE_ERROR, "message is not valid JSON")
    if not isinstance(message, dict):
        raise McpError(INVALID_REQUEST,
                       "a JSON-RPC 2.0 message must be an object")
    if message.get("jsonrpc") != JSONRPC:
        raise McpError(INVALID_REQUEST,
                       'a JSON-RPC 2.0 message requires "jsonrpc": "2.0"')
    method = message.get("method")
    if not isinstance(method, str) or not method:
        raise McpError(INVALID_REQUEST,
                       "a JSON-RPC 2.0 message requires a 'method' string")
    return message


def _tool_name(params, where):
    name = params.get("name") or params.get("tool")
    if not isinstance(name, str) or not name:
        raise McpError(INVALID_PARAMS,
                       "%s requires params.name (the tool name)" % where)
    return name


def _arguments(params, where):
    args = params.get("arguments")
    if args is None:
        args = params.get("args")
    if args is None:
        return {}
    if not isinstance(args, dict):
        raise McpError(INVALID_PARAMS,
                       "%s: params.arguments must be an object" % where)
    return dict(args)


def _state(params, where):
    s = params.get("state")
    if s is None:
        return None
    if not isinstance(s, dict):
        raise McpError(INVALID_PARAMS,
                       "%s: params.state must be an object" % where)
    return dict(s)


def _manifest(manifest):
    """Normalize a manifest (dict or ``McpManifest``) to an ``McpManifest``."""
    if manifest is None:
        return None
    from rot.mcp_manifest import McpManifest

    if isinstance(manifest, dict):
        return McpManifest.from_dict(manifest)
    if isinstance(manifest, McpManifest):
        return manifest
    raise TypeError(
        "manifest must be a dict or an McpManifest (got %r)"
        % type(manifest).__name__)


def _unruled_refusal(name, arguments, state):
    """The canonical refusal for a tool no rule governs (fail-closed)."""
    return Refusal(
        blocked=True,
        rule="no_rule",
        why="no rule governs tool %r; an unruled tool is not allowed "
            "(fail-closed)" % name,
        to_proceed="attach a rule for this tool (rules={%r: Rule}) or a "
                   "default_rule to the gateway" % name,
        allowed_now=False,
        schema=REFUSAL_SCHEMA,
        action=name,
        state=dict(state) if isinstance(state, dict) else None,
    )


class McpGateway(object):
    """The MCP ``tools/call`` interceptor (B4).

    Routes every tool call through the deterministic core::

        tools/call  ->  RuntimeGuard.decide  ->  allow/deny + refusal JSON

    Two construction modes (mirroring
    :class:`rot.runtime.langchain.GuardRunner`):

      * ``McpGateway(rules={"transfer": spendcap_rule(), ...})`` -- one rule
        per tool name; or
      * ``McpGateway(default_rule=spendcap_rule())`` -- one rule for every
        tool.

    A tool matched by neither is **blocked** (``rule: "no_rule"``) and
    recorded -- fail-closed.

    Parameters
    ----------
    rules : dict of str -> Rule, optional
        Per-tool rules (tool name -> :class:`~rot.runtime.core.Rule`).
    default_rule : Rule, optional
        The rule for tools not named in ``rules``.
    manifest : dict | rot.mcp_manifest.McpManifest, optional
        The MCP Manifest v1 (first-class input): ``tools/list`` returns its
        tool catalog and the gateway guards that server's tools.
    ledger : rot.runtime.ledger.DecisionLedger, optional
        Records every decision (append-only, hash-chained) -- the same
        ledger the LangChain adapter feeds.
    state_provider : callable, optional
        ``state_provider(name, arguments) -> dict | None``: computes the
        guard's state from history (e.g. ``(completed, inflight)`` from the
        transfer ledger).  ``params.state`` wins on key collisions.
    """

    def __init__(self, rules=None, default_rule=None, manifest=None,
                 ledger=None, state_provider=None):
        if rules is None and default_rule is None:
            raise ValueError(
                "McpGateway needs rules= or default_rule= (an unruled "
                "gateway is meaningless -- fail-closed)")
        self._guards = {}
        if rules is not None:
            for name, rule in rules.items():
                if not isinstance(rule, Rule):
                    raise TypeError(
                        "rules must map tool names to Rule (got %r for %r)"
                        % (type(rule).__name__, name))
                self._guards[str(name)] = RuntimeGuard(rule)
        if default_rule is not None:
            if not isinstance(default_rule, Rule):
                raise TypeError(
                    "default_rule must be a Rule (got %r)"
                    % type(default_rule).__name__)
            self._default_guard = RuntimeGuard(default_rule)
        else:
            self._default_guard = None
        self._manifest = _manifest(manifest)
        self.ledger = ledger
        self._state_provider = state_provider

    # -- guard resolution ----------------------------------------------------
    def _guard_for(self, name):
        """The guard for ``name`` (per-tool, else the default; ``None`` if neither)."""
        if name is not None and name in self._guards:
            return self._guards[name]
        return self._default_guard

    # -- the interceptor -------------------------------------------------------
    def tools_call(self, params):
        """Intercept one ``tools/call`` request.  Returns the JSON-RPC result.

        The request carries ``params.name`` (the tool), ``params.arguments``
        (its inputs) and optionally ``params.state`` (the guard's state --
        e.g. ``{"completed": 0, "inflight": 3}``).  The decision is made by
        the deterministic core and **recorded** on the ledger (if one is
        attached); the gateway never performs the tool itself -- an
        ``allowed`` result means the call may proceed in the framework.

        Raises
        ------
        McpError
            ``INVALID_PARAMS`` on a malformed request.
        """
        name = _tool_name(params or {}, "tools/call")
        arguments = _arguments(params or {}, "tools/call")
        state = _state(params or {}, "tools/call")
        guard = self._guard_for(name)

        if guard is None:
            refusal = _unruled_refusal(name, arguments, state)
        else:
            state = self._resolve_state(name, arguments, state)
            refusal = guard.decide(
                request={"tool": name, "args": arguments, "state": state},
            ).refusal

        self._record(name, arguments, state, refusal)
        return self._result(name, refusal)

    def _resolve_state(self, name, arguments, state):
        """The guard's state: ``params.state`` over the provider's state."""
        provided = dict(state) if isinstance(state, dict) else {}
        if self._state_provider is not None:
            try:
                s = self._state_provider(name, dict(arguments))
            except Exception:
                s = None  # a failing provider never blocks the decision
            if isinstance(s, dict):
                merged = dict(s)
                merged.update(provided)
                return merged
        return provided

    def _record(self, name, arguments, state, refusal):
        """Append the decision to the ledger (if one is attached)."""
        if self.ledger is not None:
            try:
                self.ledger.record(name, arguments, state, refusal)
            except Exception:
                pass  # a ledger failure never changes the decision

    def _result(self, name, refusal):
        """The MCP ``tools/call`` result for a decision (allow or deny).

        A **deny** is an ``isError`` result whose text content is the exact
        refusal JSON (the same shape the offline coach and the LangChain
        adapter return); ``structuredContent`` carries the same fields as a
        structured payload.  An **allow** is a plain result (the framework
        proceeds to perform the tool).
        """
        r = refusal.to_dict()
        if r.get("blocked") is True:
            return {
                "isError": True,
                "content": [{"type": "text",
                             "text": refusal.to_json(indent=2)}],
                "structuredContent": dict(r),
                "_rotn": {"decision": "blocked", "rule": r.get("rule"),
                          "hash": r.get("hash")},
            }
        return {
            "isError": False,
            "content": [{"type": "text",
                         "text": "allowed: %s" % name}],
            "structuredContent": dict(r),
            "_rotn": {"decision": "allowed", "rule": r.get("rule"),
                      "hash": r.get("hash")},
        }

    # -- the remaining JSON-RPC methods ---------------------------------------
    def tools_list(self, params=None):
        """The tool catalog (the manifest's, else the guarded tool names).

        With a manifest attached (first-class input), this returns exactly the
        manifest's ``tools[]`` -- the same catalog the offline audit
        (``rot check --manifest``) consumed.  Without one, the guarded tool
        names (plus the default rule, if any) are listed.
        """
        if self._manifest is not None:
            tools = [t.to_dict() for t in self._manifest.tools]
            return {"tools": tools}
        tools = [{"name": n} for n in sorted(self._guards)]
        if self._default_guard is not None:
            tools.append({"name": "*",
                          "description": "default rule: %s"
                                         % self._default_guard.rule.rule_id})
        return {"tools": tools}

    def decide(self, params):
        """``rot/decide``: the guard decision for a call, without recording.

        A probe: same decision as ``tools/call`` (allow/deny + refusal JSON)
        but nothing is appended to the ledger and nothing is performed.
        """
        name = _tool_name(params or {}, "rot/decide")
        arguments = _arguments(params or {}, "rot/decide")
        state = _state(params or {}, "rot/decide")
        guard = self._guard_for(name)
        if guard is None:
            refusal = _unruled_refusal(name, arguments, state)
        else:
            state = self._resolve_state(name, arguments, state)
            refusal = guard.decide(
                request={"tool": name, "args": arguments, "state": state},
            ).refusal
        return self._result(name, refusal)

    def rules(self, params=None):
        """``rot/rules``: the rules this gateway enforces."""
        out = []
        for name in sorted(self._guards):
            out.append({"tool": name,
                        "rule": self._guards[name].rule.to_dict()})
        if self._default_guard is not None:
            out.append({"tool": "*",
                        "rule": self._default_guard.rule.to_dict()})
        return {"schema": MCP_SCHEMA,
                "rot_version": rot.__version__,
                "rules": out}

    def ledger_dump(self, params=None):
        """``rot/ledger``: the decisions recorded so far (verified)."""
        if self.ledger is None:
            return {"schema": _ledger.SCHEMA,
                    "entries": [],
                    "note": "no ledger attached to this gateway"}
        self.ledger.verify()
        return self.ledger.to_dict()

    def info(self, params=None):
        """Gateway self-description (schema, version, manifest provenance)."""
        out = {
            "schema": MCP_SCHEMA,
            "rot_version": rot.__version__,
            "manifest": None,
        }
        if self._manifest is not None:
            m = self._manifest
            out["manifest"] = {
                "server": m.server,
                "version": m.version,
                "tenant_scope": m.tenant_scope,
                "n_tools": len(m.tools),
            }
        return out

    # -- dispatch --------------------------------------------------------------
    def _dispatch(self, method, params):
        """Route a JSON-RPC method to its handler (unknown -> McpError)."""
        if method == "ping":
            return "pong"
        if method == "tools/list":
            return self.tools_list(params)
        if method == "tools/call":
            return self.tools_call(params)
        if method == "rot/decide":
            return self.decide(params)
        if method == "rot/rules":
            return self.rules(params)
        if method == "rot/ledger":
            return self.ledger_dump(params)
        if method == "rot/info":
            return self.info(params)
        raise McpError(METHOD_NOT_FOUND, "method not found: %r" % method)

    def handle_message(self, message):
        """Handle one JSON-RPC 2.0 message; return the response dict.

        ``message`` may be a dict or a JSON string.  Protocol-level failures
        (malformed message, unknown method, invalid params) are returned as
        JSON-RPC error responses -- never raised -- so a peer always gets a
        well-formed reply.
        """
        try:
            msg = _parse_message(message)
        except McpError as exc:
            req_id = (message.get("id") if isinstance(message, dict)
                      else None)
            return jsonrpc_error(req_id, exc.code, exc.message, exc.data)
        req_id = msg.get("id")
        params = msg.get("params")
        if params is not None and not isinstance(params, (dict, list)):
            return jsonrpc_error(req_id, INVALID_PARAMS,
                                 "params must be an object or array")
        try:
            result = self._dispatch(msg["method"], params)
        except McpError as exc:
            return jsonrpc_error(req_id, exc.code, exc.message, exc.data)
        return {"jsonrpc": JSONRPC, "id": req_id, "result": result}


# ---------------------------------------------------------------------------
# module-level helpers
# ---------------------------------------------------------------------------

def intercept_tools_call(guard, name, arguments=None, state=None, ledger=None):
    """Intercept one ``tools/call`` through a single :class:`RuntimeGuard`.

    The one-line form of the gateway (for a single-rule deployment): decide
    ``name(arguments)`` in ``state``, optionally record it on ``ledger``, and
    return the MCP result dict (allow/deny + the refusal JSON).
    """
    from .core import RuntimeGuard as _RG

    if not isinstance(guard, _RG):
        raise TypeError(
            "intercept_tools_call expects a RuntimeGuard (got %r)"
            % type(guard).__name__)
    gw = McpGateway(rules={}, ledger=ledger)
    gw._default_guard = guard
    return gw.tools_call({"name": name,
                          "arguments": dict(arguments or {}),
                          "state": state})


def build_http_server(gateway, host="127.0.0.1", port=8765):
    """A stdlib HTTP server exposing the gateway's JSON-RPC surface.

    * ``POST /``  -- one JSON-RPC 2.0 message (the MCP wire format); the
      response is the gateway's JSON-RPC reply.
    * ``GET  /``  -- the gateway's ``rot/info`` document (self-description).

    ``gateway`` is an :class:`McpGateway`.  Returns an
    ``http.server.ThreadingHTTPServer`` ready for ``serve_forever`` (or
    ``serve`` in a test).  Pure stdlib -- no framework required.
    """
    import http.server
    import socketserver

    class _Handler(http.server.BaseHTTPRequestHandler):
        server_version = "rotn-mcp/" + rot.__version__

        def _send(self, code, body):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path.rstrip("/") in ("", "/"):
                self._send(200, json.dumps(
                    gateway.info(), sort_keys=True, indent=2))
            else:
                self._send(404, json.dumps(
                    {"error": "not found"}, sort_keys=True))

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                message = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                message = raw.decode("utf-8", "replace")
            reply = gateway.handle_message(message)
            self._send(200, json.dumps(reply, sort_keys=True))

        def log_message(self, fmt, *args):  # keep the server quiet
            pass

    class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = _Server((host, port), _Handler)
    server.gateway = gateway
    return server


def serve_forever(server):
    """Run an HTTP gateway server until interrupted (Ctrl-C / SIGTERM)."""
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()