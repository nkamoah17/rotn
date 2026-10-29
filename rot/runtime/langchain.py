# -*- coding: utf-8 -*-
"""rot.runtime.langchain -- the LangChain adapter (B3, first).

The motto at the framework boundary: an agent (an LLM, e.g. a LangChain agent)
*proposes* a tool call; the :class:`~rot.runtime.core.RuntimeGuard` *decides*
it.  This module wires that decision into LangChain so that **every** tool call
an agent makes is checked by the deterministic core before it runs, and a
denied call returns the exact refusal JSON::

    {"blocked", "rule", "why", "to_proceed", "allowed_now"}

The adapter is a **``Runnable``-protocol wrapper**: it exposes
:meth:`GuardRunner.invoke`, the method LangChain's ``Runnable`` contract calls,
so it can be used directly as a ``Runnable`` (``runner | tool``), wrapped in a
``RunnableLambda``, or registered as a tool callback -- in any of the standard
LangChain extension points.

Zero-dependency core, optional framework glue
---------------------------------------------

ROTN's core is pure stdlib.  LangChain is an *optional* dependency:

  * :class:`GuardRunner` (the tool-callback / ``Runnable`` wrapper) and its
    :meth:`GuardRunner.invoke` method are **pure stdlib** and import LangChain
    **never** -- so the adapter is importable, runnable, and fully testable in
    an environment without LangChain (this repo's CI).
  * The LangChain-specific glue -- :func:`langchain_runnable`,
    :func:`langchain_tool_callback`, :func:`guarded_tool` -- *lazy-imports*
    LangChain and raises a clear :class:`LangChainNotInstalled` error only if
    called without it installed.  With LangChain present they produce the
    framework-native object.

The decision itself (and the refusal shape) is identical everywhere: the
adapter only *routes* a tool call through :class:`RuntimeGuard`; it adds no
logic of its own.

Pure stdlib (Python 3.6 compatible) for the core; LangChain is an optional,
lazy dependency for the glue.
"""

from __future__ import print_function

import json

from .core import RuntimeGuard, Rule, ALLOWED, BLOCKED

__all__ = [
    "LangChainNotInstalled",
    "GuardRunner",
    "langchain_runnable",
    "langchain_tool_callback",
    "guarded_tool",
    "tool_name",
    "tool_args",
]


class LangChainNotInstalled(ImportError):
    """Raised when a LangChain-specific helper is used without LangChain.

    The core :class:`GuardRunner` (and its :meth:`~GuardRunner.invoke`) works
    without LangChain; only the framework-native glue (``langchain_runnable``,
    ``langchain_tool_callback``, ``guarded_tool``) requires it.
    """


# ---------------------------------------------------------------------------
# tool-call normalization (framework-agnostic)
# ---------------------------------------------------------------------------

def tool_name(tool_call):
    """The tool name from a tool call (a dict, a dataclass, or a LangChain
    ``ToolCall`` / ``ToolMessage``).

    Accepts the common shapes: a LangChain ``ToolCall`` (``.name``), an
    ``AIMessage.tool_calls`` entry (``{"name", "args"}``), a ``ToolMessage``
    (``.name``), or a plain dict with ``name`` / ``tool`` / ``tool_name`` /
    ``action``.  Returns ``None`` if no name is found.
    """
    name = getattr(tool_call, "name", None)
    if isinstance(name, str) and name:
        return name
    if isinstance(tool_call, dict):
        for key in ("name", "tool", "tool_name", "action", "function"):
            v = tool_call.get(key)
            if isinstance(v, str) and v:
                return v
            if isinstance(v, dict) and isinstance(v.get("name"), str):
                return v["name"]
    return None


def tool_args(tool_call):
    """The tool args from a tool call (a dict, a dataclass, or a LangChain
    ``ToolCall``).  Always returns a dict (possibly empty)."""
    args = getattr(tool_call, "args", None)
    if isinstance(args, dict):
        return dict(args)
    if isinstance(tool_call, dict):
        a = tool_call.get("args") or tool_call.get("input") \
            or tool_call.get("arguments") or {}
        if isinstance(a, dict):
            return dict(a)
        if isinstance(a, str):
            try:
                d = json.loads(a)
                if isinstance(d, dict):
                    return d
            except ValueError:
                return {"raw": a}
    return {}


def tool_state(tool_call):
    """A state dict carried by a tool call, if any (else ``None``).

    Lets a caller pre-compute the guard's state (e.g. ``{"completed": 0,
    "inflight": 3}`` for the spend-cap rule) and attach it to the call.
    """
    if isinstance(tool_call, dict):
        s = tool_call.get("state")
        if isinstance(s, dict):
            return dict(s)
    s = getattr(tool_call, "state", None)
    if isinstance(s, dict):
        return dict(s)
    return None



class GuardRunner(object):
    """The LangChain adapter (B3): a tool-callback / ``Runnable`` wrapper.

    Routes every tool call through the deterministic core::

        tool call  ->  RuntimeGuard.decide  ->  allow/deny + refusal JSON

    It implements the **``Runnable`` protocol** (the :meth:`invoke` method),
    so it is usable as a LangChain ``Runnable`` (``runner | tool``), inside a
    ``RunnableLambda``, or as a tool callback -- and, because ``invoke`` is
    pure stdlib, it is importable and testable **without** LangChain installed.

    Two construction modes (mutually exclusive):

      * ``GuardRunner(guard=RuntimeGuard(...))`` -- one guard applied to every
        tool (the common single-rule case, e.g. the spend-cap rule); or
      * ``GuardRunner(rules={"transfer": spendcap_rule(), "send": exfil_rule()})``
        -- one guard per tool name (each :class:`Rule` gets its own
        :class:`RuntimeGuard`).  A tool not in ``rules`` falls back to
        ``default_rule`` (if given); otherwise a call for an unknown tool
        raises :class:`KeyError` (fail-closed: an unruled tool is not allowed).

    The optional ``ledger`` (a :class:`~rot.runtime.ledger.DecisionLedger`)
    records every decision, so the runtime plane feeds the same append-only,
    auditable record the coach aggregates (B5).

    Parameters
    ----------
    guard : rot.runtime.core.RuntimeGuard, optional
        A single guard applied to every tool.
    rules : dict of str -> Rule, optional
        A per-tool guard mapping (tool name -> :class:`Rule`).
    default_rule : Rule, optional
        The guard for tools not named in ``rules`` (fail-open fallback).  When
        neither ``default_rule`` nor a matching entry is present, a tool call
        raises ``KeyError`` -- never silently allowed.
    ledger : rot.runtime.ledger.DecisionLedger, optional
        Records each decision (append-only, hash-chained).
    """

    def __init__(self, guard=None, rules=None, default_rule=None,
                 ledger=None):
        if guard is not None and (rules or default_rule is not None):
            raise ValueError(
                "pass either guard= (a single guard) or rules=/default_rule= "
                "(per-tool rules), not both")
        self._guards = {}
        if guard is not None:
            if not isinstance(guard, RuntimeGuard):
                raise TypeError("guard must be a RuntimeGuard (got %r)"
                                % type(guard).__name__)
            self._default_guard = guard
        else:
            self._default_guard = None
            if rules is not None:
                for name, rule in rules.items():
                    self._guards[str(name)] = self._make_guard(rule)
            if default_rule is not None:
                self._default_guard = self._make_guard(default_rule)
        self.ledger = ledger

    # -- guard resolution ----------------------------------------------------
    @staticmethod
    def _make_guard(rule):
        if not isinstance(rule, Rule):
            raise TypeError("rules must map to Rule (got %r)"
                            % type(rule).__name__)
        return RuntimeGuard(rule)

    def _guard_for(self, name):
        """The guard for ``name`` (per-tool, else the default; KeyError if none)."""
        if name is not None and name in self._guards:
            return self._guards[name]
        if self._default_guard is not None:
            return self._default_guard
        raise KeyError(
            "no rule for tool %r -- an unruled tool is not allowed "
            "(fail-closed)" % (name,))

    # -- the Runnable protocol ----------------------------------------------
    def invoke(self, tool_call, config=None):
        """Decide one tool call (the ``Runnable`` entry point).

        Parameters
        ----------
        tool_call : dict | LangChain ToolCall/ToolMessage | object
            The proposed tool call.  Normalized via :func:`tool_name` /
            :func:`tool_args` / :func:`tool_state`.
        config : dict, optional
            A LangChain run config (accepted for ``Runnable`` compatibility;
            unused by the decision -- the guard is deterministic).

        Returns
        -------
        dict
            The decision envelope (the refusal JSON, always present)::

                {"allowed", "blocked", "tool", "args", "refusal"}

            ``refusal`` is the exact five-field refusal
            (``{blocked, rule, why, to_proceed, allowed_now}``) plus its hash.
            A blocked envelope carries the refusal's ``why`` / ``to_proceed``;
            an allowed envelope carries the same shape with ``blocked=False``.
        """
        name = tool_name(tool_call)
        args = tool_args(tool_call)
        state = tool_state(tool_call)
        guard = self._guard_for(name)
        request = {"tool": name, "args": args}
        if state is not None:
            request["state"] = state
        decision = guard.decide(request=request)
        if self.ledger is not None:
            self.ledger.record(name, args, state, decision)
        return self._envelope(name, args, decision)

    def _envelope(self, name, args, decision):
        """The decision envelope (allow/deny + the refusal JSON)."""
        refusal = decision.to_dict()
        return {
            "allowed": decision.allowed,
            "blocked": decision.blocked,
            "tool": name,
            "args": dict(args),
            "refusal": refusal,
        }

    # -- convenience ---------------------------------------------------------
    def check(self, tool_call, config=None):
        """Alias for :meth:`invoke` (reads as "check this tool call")."""
        return self.invoke(tool_call, config=config)

    def __repr__(self):
        if self._default_guard is not None and not self._guards:
            return "GuardRunner(rule=%r)" % (self._default_guard.rule.rule_id,)
        return "GuardRunner(rules=%r)" % (sorted(self._guards),)


# ---------------------------------------------------------------------------
# LangChain-specific glue (lazy: import LangChain only when these are called)
# ---------------------------------------------------------------------------

def _langchain_core():
    """Lazy-import ``langchain_core`` (raise :class:`LangChainNotInstalled`).

    The core :class:`GuardRunner` works without LangChain; only the glue in
    this section (``langchain_runnable``, ``langchain_tool_callback``,
    ``guarded_tool``) needs it, and it is imported here -- at call time -- so
    the module stays importable in a LangChain-free environment.
    """
    try:
        import langchain_core  # noqa: F401
    except ImportError as exc:
        raise LangChainNotInstalled(
            "the LangChain glue requires LangChain "
            "(pip install langchain-core); the core GuardRunner works "
            "without it") from exc


def langchain_runnable(runner):
    """Wrap a :class:`GuardRunner` as a LangChain ``Runnable``.

    The returned ``RunnableLambda``'s ``invoke`` is exactly
    :meth:`GuardRunner.invoke`, so in a chain (``runner | tool``) or a
    ``RunnableLambda`` the tool call is *decided* before it runs: a blocked
    call yields the refusal envelope and never reaches the tool.

    Raises
    ------
    LangChainNotInstalled
        If LangChain is not installed.
    """
    _langchain_core()
    from langchain_core.runnables import RunnableLambda

    if not isinstance(runner, GuardRunner):
        raise TypeError("langchain_runnable expects a GuardRunner (got %r)"
                        % type(runner).__name__)
    return RunnableLambda(runner.invoke)


def langchain_tool_callback(runner):
    """A check-before-run tool callback for ``runner``.

    Returns ``callback(tool_call)``:

      * **blocked** -> the exact refusal JSON string (the call's refusal;
        the tool must not run);
      * **allowed** -> ``None`` (the call may proceed to the tool).

    The decision (and the refusal) is identical to :meth:`GuardRunner.invoke`
    -- the callback only routes; it adds no logic of its own.

    Raises
    ------
    LangChainNotInstalled
        If LangChain is not installed.
    """
    _langchain_core()
    if not isinstance(runner, GuardRunner):
        raise TypeError(
            "langchain_tool_callback expects a GuardRunner (got %r)"
            % type(runner).__name__)

    def callback(tool_call):
        envelope = runner.invoke(tool_call)
        if envelope.get("blocked"):
            return json.dumps(envelope["refusal"], sort_keys=True, indent=2)
        return None

    callback.__name__ = "guarded_tool_call"
    callback.runner = runner
    return callback


def guarded_tool(runner, func, name=None, description=None):
    """A tool function guarded by ``runner`` (check before run).

    ``func`` is the tool's implementation (``**kwargs -> result``).  The
    returned wrapper decides the call first (tool name: ``name`` or
    ``func.__name__``); if **blocked** it returns the exact refusal JSON
    string and *never* calls ``func``; if **allowed** it returns
    ``func(**kwargs)`` unchanged.  With LangChain present the wrapper is
    returned as-is (a plain callable is a valid LangChain tool body); the
    guard adds no framework logic.

    Raises
    ------
    LangChainNotInstalled
        If LangChain is not installed.
    """
    _langchain_core()
    if not isinstance(runner, GuardRunner):
        raise TypeError("guarded_tool expects a GuardRunner (got %r)"
                        % type(runner).__name__)
    if not callable(func):
        raise TypeError("guarded_tool expects a callable tool (got %r)"
                        % type(func).__name__)
    tool_name_ = name or getattr(func, "__name__", None) or "tool"

    def wrapper(**kwargs):
        state = kwargs.pop("_state", None)
        envelope = runner.invoke({"name": tool_name_,
                                  "args": dict(kwargs),
                                  "state": state})
        if envelope.get("blocked"):
            return json.dumps(envelope["refusal"], sort_keys=True, indent=2)
        return func(**kwargs)

    wrapper.__name__ = getattr(func, "__name__", None) or "guarded_tool"
    wrapper.__doc__ = description or getattr(func, "__doc__", None)
    wrapper.runner = runner
    wrapper.tool_name = tool_name_
    return wrapper

