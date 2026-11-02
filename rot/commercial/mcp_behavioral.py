# -*- coding: utf-8 -*-
"""mcp_behavioral.py -- G8: the *behavioral* audit of an MCP Manifest v1.

The Phase B, B2 manifest audit (:func:`rot.mcp_adapter.manifest_findings`) is a
*declaration* check: two pure set checks over the fields a tool *declares*
(``field_write_permission`` + ``tenant_read_isolation``).  The gap analysis
(G8) flags exactly this: Product 4's claim --

    "no user's agent can read another user's data through this connector"

-- is a *declaration* check, not a *behavioral* proof.  There is no temporal /
concurrency verification of tool use, and no adversarial agent calling the
MCP tools in sequence.

This module closes that gap by turning the manifest into an instance of the
general **adversarial agent + policy harness** model
(:mod:`rot.agent_harness`, the G1 generalization) and *model-checking* the
safety property over the reachable state space of tool-call sequences:

  * the **agent** is a nondeterministic actor that may attempt **any** tool in
    the manifest's catalog, in **any order**, **repeatedly** (the thesis's
    "a fully compromised model");
  * the **harness** (the thing under test) is the manifest's declared
    configuration -- the exposed tools and their declared data access;
  * the **property** is the guarantee we prove holds in *every* reachable
    state.

The state tracks the *cumulative* effect of the tool calls the agent has made
(the data it has touched), so the model is genuinely *temporal*: a violation is
a reachable state that is only produced by a *sequence* of tool calls.  The
single property the declaration check cannot see is the **exfiltration**
(``NoExfiltration``, thesis rule #1 / the "lethal trifecta"): the agent reads
the tenant's own private data (an *in-scope*, structurally-clean read) and then
sends it out through an outbound (``openWorldHint``) channel.  Each tool is
individually in-scope (the structural check PASSES), but the *sequence*
read-then-exfiltrate is a violation (the behavioral proof FAILS).  That is the
"declaration check -> behavioral proof" upgrade made concrete.

Verdicts are bounded and fail-closed, exactly like the rest of the engine:

  * ``proven``   -- the whole reachable state space was explored and the
                    property holds in every state (a proof over the bounded
                    model);
  * ``violated`` -- a reachable state violates the property; the witness is
                    that state *and* the tool-call path (the attack path) that
                    reaches it;
  * ``unknown``  -- the state budget was exhausted before the space drained;
                    this is an honest ``OUT_OF_SCOPE``, never read as proven.

The audit is a **pure function** of the manifest + budget, so it is
deterministic, JSON-serialisable, and hashable, like the rest of the report.

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir
import rot.agent_harness as ah
from rot.linearization import linearize
from rot.mcp_adapter import _field_tenant, _is_cross_tenant

__all__ = [
    "PROP_NO_CROSS_TENANT_READ",
    "PROP_NO_UNAPPROVED_WRITE",
    "PROP_TRIFECTA",
    "PROPERTIES",
    "BehavioralVerdict",
    "manifest_state_vars",
    "no_violation_property",
    "manifest_tools",
    "build_manifest_ir",
    "behavioral_audit",
    "violated_properties",
    "has_trifecta",
    "STRUCTURAL_EQUIVALENT",
]

# ---------------------------------------------------------------------------
# The behavioral property names (the ROTN properties the manifest audit proves)
# ---------------------------------------------------------------------------
#: The agent never reads a field namespaced under *another* tenant.
PROP_NO_CROSS_TENANT_READ = "no_cross_tenant_read"
#: The agent never writes a field outside the tenant's allowed write set.
PROP_NO_UNAPPROVED_WRITE = "no_unapproved_write"
#: The "lethal trifecta" *risk configuration* (a warning, not a hard
#: violation): the agent can hold the tenant's private data *and* reach an
#: outbound (open-world) channel.  The thesis says to *flag* this combination;
#: the behavioral proof proves the hard guarantees and reports this as a risk.
PROP_TRIFECTA = "lethal_trifecta"

#: The behavioral properties, in a stable (documented) order.  The first two
#: are hard violations (gated); the third is a risk configuration (a warning).
PROPERTIES = (
    PROP_NO_CROSS_TENANT_READ,
    PROP_NO_UNAPPROVED_WRITE,
    PROP_TRIFECTA,
)

#: Which ROTN structural finding (Phase B, B2) already covers each behavioral
#: property.  ``None`` means the behavioral property has *no* structural
#: equivalent -- it is the new, temporal property the declaration check cannot
#: see (the lethal-trifecta risk: private data + outbound channel reachable in
#: a tool-call *sequence*, which a per-tool declaration check cannot express).
STRUCTURAL_EQUIVALENT = {
    PROP_NO_CROSS_TENANT_READ: "tenant_read_isolation",
    PROP_NO_UNAPPROVED_WRITE: "field_write_permission",
    PROP_TRIFECTA: None,  # the new temporal property (no structural twin)
}

#: The state variables the behavioral model tracks (the data the agent touched).
_STATE_VARS = (
    "read_foreign",      # read a field of another tenant (cross-tenant read)
    "wrote_unapproved",  # wrote a field outside the allowed write set
    "holding_private",   # holds the tenant's own private data (read a same-tenant field)
    "used_outbound",     # used an outbound (open-world) channel
)


def _is_own_private(field, scope):
    """True if ``field`` is namespaced under ``scope`` (the tool's *own* tenant).

    Such a field is the tenant's own data -- *private by default*: it is
    in-scope to *read* (so the structural check passes) but must not *leave*
    the connector.  A ``None`` scope means the tool is not bound to any
    tenant, so no field is "its own" (fail-closed).
    """
    if scope is None:
        return False
    return _field_tenant(field) is not None and _field_tenant(field) == scope


def manifest_state_vars():
    """The behavioral model's state variables (all precise booleans).

    Each is a *latch*: it is set when the agent performs the corresponding
    touch and is never reset, so the state records the *cumulative* data the
    agent has accessed over its (adversarial) tool-call sequence.  That
    cumulative, sequence-dependent state is what makes the model temporal.
    """
    return [
        ir.StateVar("read_foreign", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the agent read a field namespaced under another tenant"),
        ir.StateVar("wrote_unapproved", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the agent wrote a field outside the allowed write set"),
        ir.StateVar("holding_private", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the agent holds the tenant's own private data"),
        ir.StateVar("used_outbound", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the agent used an outbound (open-world) channel"),
    ]


def no_violation_property():
    """The safety property: no cross-tenant read, no unauthorized write.

    ``NOT read_foreign AND NOT wrote_unapproved`` -- the behavioral form of the
    manifest's two hard guarantees (tenant read isolation + field write
    permission), checked over the *adversarial agent's tool-call sequences*
    (the thing the per-tool declaration check cannot do).  This is the rule the
    model checker must prove holds in *every* reachable state.  The lethal
    trifecta (``holding_private AND used_outbound``) is a separate *risk* that
    is reported, not part of this hard property.
    """
    return ir.And(
        ir.Not(ir.V("read_foreign")),
        ir.Not(ir.V("wrote_unapproved")),
    )


def _tool_effect(manifest, tool):
    """The state effect of firing ``tool`` (a list of ``(var, expr)`` pairs).

    Derived *purely* from the manifest's declaration of the tool (its
    ``read_fields`` / ``write_fields`` / ``annotations``) and the manifest's
    scoping (``tenant_scope`` / ``allowed_write_fields``).  An effect is added
    only when the tool's declared access triggers the corresponding latch, so
    firing an in-scope tool leaves the latches unchanged (the state is
    monotone -- touches accumulate and are never undone).
    """
    scope = manifest.effective_tenant_scope(tool)
    allowed_write = set(manifest.allowed_write_fields)
    annotations = tool.annotations or {}
    open_world = bool(annotations.get("openWorldHint", False))

    reads_foreign = any(_is_cross_tenant(f, scope) for f in tool.read_fields)
    writes_unapproved = any(f not in allowed_write for f in tool.write_fields)
    reads_private = any(_is_own_private(f, scope) for f in tool.read_fields)

    effect = []
    if reads_foreign:
        effect.append(("read_foreign", ir.C(True)))
    if writes_unapproved:
        effect.append(("wrote_unapproved", ir.C(True)))
    if reads_private:
        effect.append(("holding_private", ir.C(True)))
    # An open-world tool is an *outbound channel*: once the agent has used one
    # while holding private data, the lethal-trifecta risk is present (reported
    # separately as a warning, not a hard violation).
    if open_world:
        effect.append(("used_outbound", ir.C(True)))
    return effect


def manifest_tools(manifest):
    """The agent's tool catalog: one :class:`rot.agent_harness.Tool` per tool.

    The agent is *adversarial*: it may attempt any of these, in any order,
    repeatedly.  Each tool's effect is its declared data access (see
    :func:`_tool_effect`).  The order is the manifest's tool order (stable),
    which keeps the model and its witness deterministic.
    """
    return [
        ah.Tool(tool.name, _tool_effect(manifest, tool),
                desc="MCP tool %r (reads %s, writes %s)"
                     % (tool.name, sorted(tool.read_fields),
                        sorted(tool.write_fields)))
        for tool in manifest.tools
    ]


def build_manifest_ir(manifest, name=None):
    """Build the adversarial-agent :class:`rot.ir.ProtocolIR` for a manifest.

    The harness admits every declared tool (the manifest *exposes* them -- that
    declared configuration is the thing under test), and the pinned property is
    :func:`no_violation_property`.  The result is a real transition system over
    the agent's tool-call sequences, ready for
    :func:`rot.linearization.linearize` + a bounded model check.
    """
    tools = manifest_tools(manifest)
    # The harness admits every declared tool: the manifest's declared catalog
    # is the connector's configuration (the thing under test).  Whether that
    # configuration satisfies the safety property is what we prove.
    policy = ah.HarnessPolicy(
        {t.name: ir.T() for t in tools},
        name="mcp-manifest-harness",
    )
    init = {v: False for v in _STATE_VARS}
    return ah.build_ir(
        tools=tools,
        policy=policy,
        state_vars=manifest_state_vars(),
        property=no_violation_property(),
        init=init,
        name=name or ("mcp-manifest-%s" % (manifest.server or "tools")),
        metadata={
            "protocol": "MCP_MANIFEST",
            "family": "AGENT_HARNESS",
            "adversarial_agent": True,
            "server": manifest.server,
            "tenant_scope": manifest.tenant_scope,
            "allowed_write_fields": sorted(manifest.allowed_write_fields),
            "property_name": "no_violation",
            "properties": list(PROPERTIES),
        },
    )


def _violates(property_expr, state):
    """True iff ``state`` *definitely* violates ``property_expr``.

    A violation is only a *definite* ``False`` -- an ``UNDEF`` evaluation
    (a value over an unmodelled atom) is never read as a violation, matching
    the engine's conservative three-valued semantics.
    """
    r = property_expr.eval(state)
    return r is not ir.Expr.UNDEF and not r


def _successors(model, state):
    """The enabled successors of ``state`` as ``(next_state, action_name)``.

    Mirrors :func:`rot.symbolic._step` (the IR's own three-valued evaluation)
    but also yields the *action name* that produced each successor, so the
    audit can record the tool-call path (the attack path) of a violation.
    """
    out = []
    for a in model.actions:
        try:
            if a.guard.eval(state) is not True:
                continue
        except Exception:
            continue
        ns = dict(state)
        blocked = False
        for e in a.effects:
            v = e.expr.eval(state)
            if v is ir.Expr.UNDEF:
                blocked = True
                break
            ns[e.var] = v
        if blocked or ns == state:
            continue
        out.append((ns, a.name))
    return out


def _tool_from_action(action_name):
    """The manifest tool name behind an ``agent_take_<tool>`` action name."""
    prefix = "agent_take_"
    if action_name.startswith(prefix):
        return action_name[len(prefix):]
    return action_name


def violated_properties(state):
    """The *hard* behavioral properties violated by ``state`` (stable order).

    Read straight from the witness state: which hard-violation latches the
    agent set.  An empty list means the state satisfies the hard property (not
    a hard-violation witness).  The lethal trifecta is a *risk*, not a hard
    violation, so it is reported separately (see :func:`has_trifecta`).
    """
    props = []
    if state.get("read_foreign"):
        props.append(PROP_NO_CROSS_TENANT_READ)
    if state.get("wrote_unapproved"):
        props.append(PROP_NO_UNAPPROVED_WRITE)
    return props


def has_trifecta(state):
    """True iff ``state`` presents the *lethal-trifecta* risk configuration.

    The agent holds the tenant's private data *and* has used an outbound
    (open-world) channel -- the combination the thesis says to *flag*.  This is
    a *risk* (a configuration that enables exfiltration), not a hard violation,
    so it is reported as a warning, never as a gate-affecting finding.
    """
    return bool(state.get("holding_private")) and bool(state.get("used_outbound"))


class BehavioralVerdict(object):
    """The outcome of the behavioral (temporal) audit of a manifest.

    Attributes
    ----------
    status : str
        ``"proven"`` / ``"violated"`` / ``"unknown"``.
    witness : dict or None
        The violating state (the latches the agent set) -- ``violated`` only.
    path : list[str] or None
        The tool-call sequence (the attack path) that reaches the witness --
        ``violated`` only.
    properties : list[str]
        The *hard* behavioral properties violated by the witness
        (``violated`` only).
    trifecta : bool
        True iff *any* reachable state presents the lethal-trifecta risk
        (private data + outbound channel) -- reported as a *warning*, never
        as a gate-affecting finding.
    n_states : int
        The number of reachable states explored.
    complete : bool
        True iff the reachable state space was fully explored (a ``proven`` /
        ``violated`` verdict is sound); False iff the search was truncated by
        the budget (``unknown``).
    """

    def __init__(self, status, witness=None, path=None, properties=None,
                 trifecta=False, n_states=0, complete=False, note=""):
        self.status = status
        self.witness = witness
        self.path = path
        self.properties = list(properties or [])
        self.trifecta = bool(trifecta)
        self.n_states = int(n_states)
        self.complete = bool(complete)
        self.note = note

    def is_proven(self):
        return self.status == "proven"

    def is_violated(self):
        return self.status == "violated"

    def is_unknown(self):
        return self.status == "unknown"

    def to_dict(self):
        return {
            "status": self.status,
            "engine": "SymbolicEngine",
            "method": "behavioral_audit",
            "witness": self.witness,
            "path": self.path,
            "properties": self.properties,
            "trifecta_risk": self.trifecta,
            "n_states": self.n_states,
            "complete": self.complete,
            "note": self.note,
        }

    def __repr__(self):
        return "BehavioralVerdict(%s, n_states=%d)" % (
            self.status, self.n_states)


def behavioral_audit(manifest, max_states=200000):
    """Model-check the manifest's safety property over adversarial tool calls.

    Builds the adversarial-agent transition system for ``manifest`` (see
    :func:`build_manifest_ir`), linearizes it, and runs a bounded, exhaustive
    breadth-first search over the reachable states of tool-call sequences.  The
    search stops at the first state that violates
    :func:`no_violation_property` (a counterexample -- the attack path), or
    drains the whole space (a proof), or exhausts the state budget (an honest
    ``unknown``).

    Parameters
    ----------
    manifest : rot.mcp_manifest.McpManifest
        A validated manifest.
    max_states : int
        The state budget (fail-closed floor; a truncated search is ``unknown``).

    Returns
    -------
    BehavioralVerdict
        ``proven`` / ``violated`` (with witness + attack path) / ``unknown``.
    """
    budget = int(max_states)
    if budget < 1:
        raise ValueError("state budget must be >= 1, got %r" % (max_states,))

    ir_model = build_manifest_ir(manifest)
    model = linearize(ir_model)
    property_expr = no_violation_property()

    init = dict(model.init_state)
    trifecta_seen = has_trifecta(init)
    if _violates(property_expr, init):
        # Degenerate (a manifest whose initial state already violates) -- report
        # it soundly rather than crash.
        return BehavioralVerdict(
            "violated", witness=dict(init), path=[],
            properties=violated_properties(init),
            trifecta=trifecta_seen, n_states=1, complete=True,
            note="the initial state already violates the property")

    init_key = frozenset(init.items())
    seen = {init_key}
    parent = {init_key: None}          # key -> (parent_key, tool) | None
    queue = [(init, [])]               # (state, path-of-tools)
    i = 0
    n_states = 1
    truncated = False
    while i < len(queue):
        state, _path = queue[i]
        i += 1
        for ns, action_name in _successors(model, state):
            k = frozenset(ns.items())
            if k in seen:
                continue
            if len(seen) >= budget:
                truncated = True
                break
            seen.add(k)
            n_states += 1
            if has_trifecta(ns):
                trifecta_seen = True
            tool = _tool_from_action(action_name)
            parent[k] = (frozenset(state.items()), tool)
            if _violates(property_expr, ns):
                attack_path = _recover_path(parent, k)
                return BehavioralVerdict(
                    "violated",
                    witness=dict(ns),
                    path=attack_path,
                    properties=violated_properties(ns),
                    trifecta=trifecta_seen,
                    n_states=n_states,
                    complete=True,
                    note="a reachable tool-call sequence violates the property; "
                         "the attack path is attached")
            queue.append((ns, None))
        if truncated:
            break

    if truncated:
        return BehavioralVerdict(
            "unknown", trifecta=trifecta_seen, n_states=n_states, complete=False,
            note="the state budget (%d) was exhausted before the reachable "
                 "space drained; the property is undecidable at this bound -- "
                 "this is NOT a proof" % budget)
    return BehavioralVerdict(
        "proven", trifecta=trifecta_seen, n_states=n_states, complete=True,
        note="the property holds in all %d reachable states of the "
             "adversarial agent's tool-call sequences" % n_states)


def _recover_path(parent, key):
    """Reconstruct the tool-call path (list of tools) from ``init`` to ``key``.

    ``parent`` maps each state key to ``(parent_key, tool)`` (the tool fired
    to reach that state from its parent); the root maps to ``None``.  Walking
    back to the root and reversing yields the ordered tool-call sequence (the
    attack path).  Deterministic.
    """
    path = []
    cur = key
    seen = set()
    while cur is not None and cur not in seen:
        seen.add(cur)
        entry = parent.get(cur)
        if entry is None:
            break
        parent_key, tool = entry
        path.append(tool)
        cur = parent_key
    path.reverse()
    return path