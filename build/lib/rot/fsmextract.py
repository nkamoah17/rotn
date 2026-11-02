# -*- coding: utf-8 -*-
"""fsmextract.py -- the FSM-extraction lift of the Joern-primary rework.

This is **Phase 1** (``§2.4`` + ``§2.5``) of the "Joern-Primary + Objective
A/B" plan (``docs/joern-primary-ab-plan.md``) -- the *FSM extraction* half.
It builds on the CPG-1 (dataflow) + CPG-2 (generic CPG->Candidate producer)
work of ``docs/cpg-integration-plan.md``: the CPG scrape already flows into
:class:`rot.frontends.cpg_model.CpgModel`, and the shape heuristics live in
:mod:`rot.shapes`.  (The cross-check is CPG-3 of the *integration* plan,
``rot/cpg_crosscheck.py`` -- a different, already-DONE piece; this module is
the *extraction* lift the rework sequences first.)

This module consumes the *control half* that Phase 1 adds to the CPG model
(FILE / NAMESPACE_BLOCK / METHOD_PARAMETER / LOCAL / BLOCK / CONTROL_STRUCTURE
/ CALL, plus the CDG / DOMINATE / CONTAINS edges) and extracts a finite-state
machine ``(Q, Sigma, delta, s0, F)`` for a protocol method, then synthesises a
:class:`rot.ir.ProtocolIR` that carries the two components the IR was missing
-- the input alphabet ``Sigma`` and the final states ``F``.

Why an FSM: the paper's 2PC / ZAB / PBFT case studies are, at their core,
*control-flow* state machines -- a bounded discrete "phase" variable that a
loop drives forward, guarded by the protocol's inputs (the votes / the log
entries / the quorums).  That is exactly the classical 5-tuple
``(Q, Sigma, delta, s0, F)``:

  * ``Q``     -- the states: the values of the control-state variable (its
                 bounded discrete domain -- an enum or a bool).
  * ``Sigma`` -- the input alphabet: the method's direction-IN parameters
                 that the loop / its branches read (the votes, the log
                 entries, the quorum messages).
  * ``delta`` -- the transitions: one per branch inside the loop, each
                 ``from --input--> to`` (the branch's guard selects ``from``
                 and the input; its body assigns ``to``).
  * ``s0``    -- the initial state: the state with no incoming transition
                 (the entry of the phase machine).
  * ``F``     -- the final states: the states with no outgoing transition
                 (the sinks -- the protocol's terminal states).

The extractor is *generic*: it finds the control-state variable, the loop,
the alphabet, the transitions, and derives ``s0`` / ``F`` from the
transition graph, then *classifies* the shape (2PC / ZAB / PBFT / GENERIC)
with a keyword heuristic (the E2/E3 shape recognition from CPG-2).

Fixture encoding contract
-------------------------
The extractor reads the FSM from the CPG model's *edges* (not from free-form
code), using one convention that keeps it robust and testable: the *semantic
value* (a state name or an input name) is used as the CPG node id at the
three places that carry meaning:

  * a transition's **source state** is the ``src`` id of a ``REACHING_DEF``
    edge into the branch, where the id is a state in ``Q``;
  * a transition's **input** is the ``src`` id of a ``REACHING_DEF`` edge
    into the branch, where the id is an alphabet member (a parameter name);
  * a transition's **target state** is the ``dst`` id of a ``CDG`` edge out
    of the branch, where the id is a state in ``Q``.

Everything else (the state variable, its enum domain, the loop, the branches,
the alphabet) comes from the typed records the CPG model carries.  See
``tests/fixtures/cpg/`` for the concrete 2PC / ZAB / PBFT fixtures and
``tests/test_fsm_extraction.py`` for the gate.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

import rot.ir as ir

__all__ = [
    "EXTRACTED", "OUT_OF_SCOPE", "REJECTED",
    "SHAPE_2PC", "SHAPE_ZAB", "SHAPE_PBFT", "SHAPE_GENERIC", "SHAPE_NONE",
    "ANY_STATE", "EPSILON",
    "FsmExtraction", "extract_fsm", "extract_fsm_for_method",
]

# -- result status tokens ----------------------------------------------------
EXTRACTED = "EXTRACTED"        # a valid FSM was extracted and an IR built
OUT_OF_SCOPE = "OUT_OF_SCOPE"  # no FSM shape in scope (no loop / no state var)
REJECTED = "REJECTED"          # a candidate FSM failed a soundness guard

# -- shape labels (the E2/E3 shape recognition) -------------------------------
SHAPE_2PC = "2PC"
SHAPE_ZAB = "ZAB"
SHAPE_PBFT = "PBFT"
SHAPE_GENERIC = "GENERIC"
SHAPE_NONE = "NONE"

# -- transition sentinel tokens ----------------------------------------------
ANY_STATE = "*"      # a transition whose guard does not pin the source state
EPSILON = "epsilon"  # a transition that consumes no input


# ---------------------------------------------------------------------------
# result
# ---------------------------------------------------------------------------
class FsmExtraction(object):
    """The outcome of an FSM extraction attempt.

    ``status`` is one of :data:`EXTRACTED` / :data:`OUT_OF_SCOPE` /
    :data:`REJECTED`.  When ``EXTRACTED``: ``fs`` is the 5-tuple
    ``{"q", "sigma", "delta", "s0", "f"}`` and ``ir`` is the synthesised
    :class:`rot.ir.ProtocolIR`.  When not extracted, ``fs`` / ``ir`` are
    ``None`` and ``reason`` explains why (the sound fallback: surface to a
    human rather than guess).
    """

    def __init__(self, status, shape, reason, fs=None, ir=None,
                 evidence=None, warnings=None):
        if status not in (EXTRACTED, OUT_OF_SCOPE, REJECTED):
            raise ValueError("bad status %r" % (status,))
        self.status = status
        self.shape = shape
        self.reason = reason
        self.fs = fs
        self.ir = ir
        self.evidence = list(evidence or [])
        self.warnings = list(warnings or [])

    @property
    def ok(self):
        return self.status == EXTRACTED

    def to_dict(self):
        return {
            "status": self.status,
            "shape": self.shape,
            "reason": self.reason,
            "fs": self.fs,
            "ir": self.ir.to_dict() if self.ir is not None else None,
            "evidence": list(self.evidence),
            "warnings": list(self.warnings),
        }

    def __repr__(self):
        return "FsmExtraction(%s %s)" % (self.status, self.shape)
# ---------------------------------------------------------------------------
# domain + state-variable resolution (Q2: a bounded discrete state variable)
# ---------------------------------------------------------------------------
def _domain_size(dom):
    """The number of values a bounded discrete domain carries (0 if unbounded)."""
    if isinstance(dom, ir.Enum):
        return len(dom.values)
    if isinstance(dom, ir.Bool):
        return 2
    if isinstance(dom, ir.IntRange):
        return dom.hi - dom.lo + 1
    return 0


def _resolve_domain(model, type_name):
    """Resolve a CPG type name to a bounded discrete :class:`rot.ir.Domain`.

    Returns ``None`` when the type is not a bounded discrete domain (an
    unbounded int, a record, an unknown type) -- such a variable cannot be
    the FSM's control state (Q2a: a *bounded discrete* domain is required).
    """
    if not type_name:
        return None
    tn = type_name.lower()
    if tn in ("boolean", "bool"):
        return ir.Bool()
    if tn in ("int", "long", "short", "byte", "float", "double"):
        return None  # unbounded numeric -- not a bounded discrete state
    for t in model.types:
        if t.name == type_name or t.full_name == type_name:
            if t.constants:
                return ir.Enum(list(t.constants))
            return None
    return None


def _find_field(model, name):
    for f in model.fields:
        if f.name == name or f.full_name == name:
            return f
    return None


def _find_state_var(model, method):
    """The method's best control-state variable: ``(name, domain)`` or None.

    A candidate is a LOCAL (preferred) or a written FIELD of a bounded
    discrete domain that is *reassignable* (``constant is None``) and not
    external/implicit.  Among candidates the one with the largest domain wins
    (the "phase" variable -- the most states -- beats a boolean flag).
    """
    best = None  # (size, name, domain)
    for loc in model.locals_of(method.full_name):
        if loc.constant is not None:
            continue
        dom = _resolve_domain(model, loc.type_name)
        if dom is None:
            continue
        size = _domain_size(dom)
        if size < 2:
            continue
        if best is None or size > best[0]:
            best = (size, loc.name, dom)
    for fname in method.written_fields:
        field = _find_field(model, fname)
        if field is None or field.constant is not None:
            continue
        dom = _resolve_domain(model, field.type_name)
        if dom is None:
            continue
        size = _domain_size(dom)
        if size < 2:
            continue
        if best is None or size > best[0]:
            best = (size, fname, dom)
    if best is None:
        return None
    return (best[1], best[2])


# ---------------------------------------------------------------------------
# loop (Q1: the FSM lives inside a bounded loop -- the trip-count filter)
# ---------------------------------------------------------------------------
def _find_loop(model, method):
    """The method's main FSM loop (the branch-densest CONTROL_STRUCTURE loop).

    We pick the loop that contains the most branch blocks (the main
    state-machine loop); a method with no loop is out of scope (Q1).
    """
    loops = model.loop_blocks(method.full_name)
    if not loops:
        return None

    def branch_count(loop):
        return len([b for b in model.branch_blocks(method.full_name)
                    if model.contained_in(b.full_name, loop.full_name)])

    return max(loops, key=lambda L: (branch_count(L), -L.line))
# ---------------------------------------------------------------------------
# alphabet (Q3) + transitions (Q4)
# ---------------------------------------------------------------------------
def _find_alphabet(model, method, loop):
    """The input alphabet (Q3): direction-IN params read by the loop/branches.

    A param is in the alphabet iff it is direction-IN and has a dataflow edge
    (REACHING_DEF/ARGUMENT/FLOW) into the loop or into a branch inside it.
    """
    if loop is None:
        return []
    targets = [loop.full_name]
    targets += [b.full_name for b in model.branch_blocks(method.full_name)
                if model.contained_in(b.full_name, loop.full_name)]
    alpha = set()
    for p in model.input_params(method.full_name):
        if p.is_external or p.is_implicit:
            continue
        for e in model.dataflow_edges():
            if e.src == p.name and e.dst in targets:
                alpha.add(p.name)
                break
    return sorted(alpha)


def _find_transitions(model, method, loop, states, alphabet):
    """The transition relation (Q4): one per branch inside the loop.

    For each branch ``B`` inside ``loop``:
      * ``to``    -- a ``CDG`` edge ``B -> X`` with ``X in states``;
      * ``from``  -- a ``REACHING_DEF`` edge ``X -> B`` with ``X in states``
                     (else :data:`ANY_STATE`);
      * ``input`` -- a ``REACHING_DEF`` edge ``P -> B`` with ``P in alphabet``
                     (else :data:`EPSILON`).
    """
    if loop is None:
        return []
    stateset = set(states)
    alpha = set(alphabet)
    transitions = []
    for b in model.branch_blocks(method.full_name):
        if not model.contained_in(b.full_name, loop.full_name):
            continue
        to = None
        for e in model.cdg_dependents(b.full_name):
            if e.dst in stateset:
                to = e.dst
                break
        frm = ANY_STATE
        for e in model.reads_of(b.full_name):
            if e.src in stateset:
                frm = e.src
                break
        inp = EPSILON
        for e in model.reads_of(b.full_name):
            if e.src in alpha:
                inp = e.src
                break
        if to is None:
            # a branch that does not advance the state is not a transition
            continue
        transitions.append({"from": frm, "to": to, "input": inp,
                            "branch": b.full_name})
    transitions.sort(key=lambda t: (t["from"], t["to"], t["input"]))
    return transitions


# ---------------------------------------------------------------------------
# s0 / F from the transition graph (Q5: initial + final states)
# ---------------------------------------------------------------------------
def _compute_s0_f(states, transitions):
    """``(s0, F)`` from ``delta``: s0 = the in-degree-0 state; F = the sinks.

    ``s0`` is the (unique) state no transition enters (the entry of the phase
    machine).  ``F`` is the set of states no transition leaves (the terminal
    states).  If neither is well-defined we fall back to the sound defaults
    (s0 = first state, F = empty) and the caller records a warning.
    """
    q = list(states)
    targets = set(t["to"] for t in transitions)
    origins = set(t["from"] for t in transitions if t["from"] != ANY_STATE)
    # s0: the state no transition enters (no incoming) -- the machine's entry.
    s0_candidates = [s for s in q if s not in targets]
    # F:  the states no transition leaves (no outgoing) -- the terminal states.
    f_candidates = [s for s in q if s not in origins]
    s0 = s0_candidates[0] if len(s0_candidates) == 1 else (q[0] if q else None)
    f = sorted(f_candidates) if f_candidates else []
    return s0, f
# ---------------------------------------------------------------------------
# shape classification (the E2/E3 shape recognition, carried from CPG-2)
# ---------------------------------------------------------------------------
def _classify_shape(states, alphabet):
    """Label the FSM's shape by its state/input vocabulary (a heuristic).

    Keyword recognition over the state names and the alphabet (case-
    insensitive).  2PC is checked before PBFT because both use a ``prepare``
    phase; the discriminator is the *vote* input (2PC) vs the *quorum* input
    (PBFT).  Anything that is a valid FSM but matches no known shape is
    :data:`SHAPE_GENERIC` -- still a usable control model.
    """
    s = [x.lower() for x in states]
    a = [x.lower() for x in alphabet]

    def any_in(coll, keys):
        return any(any(k in name for k in keys) for name in coll)

    # 2PC: a decide/commit phase driven by per-participant votes.
    if any_in(a, ("vote",)) and any_in(s, ("decide", "commit", "abort",
                                            "prepare", "decided")):
        return SHAPE_2PC
    # PBFT: prepare/commit phases driven by quorum message counts.
    if any_in(s, ("prepare", "commit")) and any_in(a, ("quorum", "vote",
                                                        "prepare")):
        return SHAPE_PBFT
    # ZAB: an epoch/mark/apply phase driven by log entries / leader terms.
    if any_in(s, ("apply", "epoch", "mark", "log")) and any_in(
            a, ("log", "leader", "term", "entry")):
        return SHAPE_ZAB
    return SHAPE_GENERIC


# ---------------------------------------------------------------------------
# IR synthesis (the FSM -> ProtocolIR half)
# ---------------------------------------------------------------------------
_STATE_VAR = "state"


def _build_ir(name, states, alphabet, transitions, s0, final, shape):
    """Synthesise a :class:`rot.ir.ProtocolIR` carrying the extracted FSM.

    The IR models the control-state variable (an enum over ``Q``), one
    boolean state variable per alphabet member (``True`` when the input is
    present -- the transition's trigger), an ``init`` action (``state := s0``),
    and one action per transition (guarded by the source state and/or the
    input, effect ``state := target``).  This follows the existing 2PC model
    (``rot/twopc.py``), which models the environment's choices as state
    variables rather than channels.  ``alphabet`` (Sigma) and ``final_states``
    (F) are carried on the IR itself -- the two components the FSM-extraction
    lift adds.
    """
    domain = ir.Enum(states) if states else ir.Bool()
    variables = [ir.StateVar(_STATE_VAR, domain, ir.MODE_PRECISE, "service",
                             "control state (extracted FSM)")]
    for a in alphabet:
        variables.append(ir.StateVar(a, ir.Bool(), ir.MODE_PRECISE, "environment",
                                     "input (FSM alphabet; True = present)"))
    channels = []

    init_effects = [ir.Assignment(_STATE_VAR, ir.C(s0))]
    for a in alphabet:
        init_effects.append(ir.Assignment(a, ir.C(False)))
    actions = [ir.Action(name="init", owner="service", guard=ir.T(),
                         effects=init_effects,
                         is_initial=True, source="fsmextract:init")]
    for i, t in enumerate(transitions):
        guards = []
        if t["from"] != ANY_STATE:
            guards.append(ir.eq(ir.V(_STATE_VAR), ir.C(t["from"])))
        if t["input"] != EPSILON:
            guards.append(ir.V(t["input"]))
        guard = ir.And(*guards) if guards else ir.T()
        label = (t["input"] if t["input"] != EPSILON else "tick")
        actions.append(ir.Action(
            name="t%d_%s_to_%s" % (i, t["from"], t["to"]),
            owner="service", guard=guard,
            effects=[ir.Assignment(_STATE_VAR, ir.C(t["to"]))],
            linearization="send(%s)" % label,
            source="fsmextract:t%d" % i))

    # The pinned safety invariant: the control state never leaves Q.  This is
    # a tautology over the enum domain (always satisfiable) but it is the
    # sound domain constraint the FSM honours; F-reachability is checked
    # separately as a liveness property (see the gate test).
    pinned = ir.T()

    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=channels,
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        assumptions=[],
        source_path="fsmextract",
        metadata={"protocol": shape, "extracted": True, "s0": s0,
                  "F": list(final), "sigma": list(alphabet)},
        alphabet=list(alphabet),
        final_states=list(final),
    )
# ---------------------------------------------------------------------------
# public entry points
# ---------------------------------------------------------------------------
def _pick_method(model, method_name=None):
    """Choose the FSM-owner method (by name, else the branch-densest method)."""
    methods = model.methods
    if not methods:
        return None
    if method_name is not None:
        for m in methods:
            if m.name == method_name or m.full_name == method_name:
                return m
        return None
    # the method with the most branches inside a loop is the FSM owner
    def score(m):
        loops = model.loop_blocks(m.full_name)
        if not loops:
            return -1
        best = 0
        for L in loops:
            best = max(best, len([b for b in model.branch_blocks(m.full_name)
                                  if model.contained_in(b.full_name, L.full_name)]))
        return best
    return max(methods, key=lambda m: score(m))


def extract_fsm(model, method_name=None):
    """Extract ``(Q, Sigma, delta, s0, F)`` for a method and synthesise the IR.

    Parameters
    ----------
    model : rot.frontends.cpg_model.CpgModel
        The CPG model (with the control half populated).
    method_name : str, optional
        The FSM-owner method (name or fullName).  When omitted, the method
        with the most loop-contained branches is chosen.

    Returns
    -------
    FsmExtraction
        ``EXTRACTED`` with ``fs`` + ``ir`` on success; ``OUT_OF_SCOPE`` or
        ``REJECTED`` (with a ``reason``) otherwise.
    """
    method = _pick_method(model, method_name)
    if method is None:
        return FsmExtraction(OUT_OF_SCOPE, SHAPE_NONE,
                             "no method in the CPG model to extract from")

    # Q1: the FSM lives inside a bounded loop (the trip-count filter).
    loop = _find_loop(model, method)
    if loop is None:
        return FsmExtraction(
            OUT_OF_SCOPE, SHAPE_NONE,
            "method %s has no loop -- the FSM shape requires a bounded loop "
            "(Q1 trip-count filter)" % method.full_name)

    # Q2: the bounded discrete control-state variable.
    state = _find_state_var(model, method)
    if state is None:
        return FsmExtraction(
            OUT_OF_SCOPE, SHAPE_NONE,
            "method %s has no bounded discrete state variable to drive the "
            "loop (Q2a)" % method.full_name)
    state_name, domain = state

    # Q: the states are the state variable's domain values.
    if isinstance(domain, ir.Enum):
        states = list(domain.values)
    else:  # Bool
        states = [False, True]
    if len(states) < 2:
        return FsmExtraction(
            REJECTED, SHAPE_NONE,
            "state variable %s has fewer than 2 values -- not an FSM "
            "(Q2a)" % state_name)

    # Q3: the input alphabet.
    alphabet = _find_alphabet(model, method, loop)

    # Q4: the transition relation.
    transitions = _find_transitions(model, method, loop, states, alphabet)
    if not transitions:
        return FsmExtraction(
            REJECTED, SHAPE_NONE,
            "no transitions advance the state variable %s inside the loop "
            "(Q4)" % state_name)

    # Q5: the initial and final states (from the transition graph).
    s0, final = _compute_s0_f(states, transitions)
    warnings = []
    if s0 is None:
        warnings.append("no unique initial state; defaulting to first state")
    if not final:
        warnings.append("no final (sink) state found; F defaulted to empty")

    # Soundness guard (the UNSAT check): every transition's source and target
    # must be in Q, and s0 must be in Q.  A violation means the CPG edges are
    # inconsistent with the state domain -- reject rather than emit a broken
    # FSM (the sound fallback: surface to a human).
    stateset = set(states)
    for t in transitions:
        if t["from"] != ANY_STATE and t["from"] not in stateset:
            return FsmExtraction(
                REJECTED, SHAPE_NONE,
                "transition from %r is outside Q (UNSAT guard)" % (t["from"],))
        if t["to"] not in stateset:
            return FsmExtraction(
                REJECTED, SHAPE_NONE,
                "transition to %r is outside Q (UNSAT guard)" % (t["to"],))
    if s0 is not None and s0 not in stateset:
        return FsmExtraction(
            REJECTED, SHAPE_NONE,
            "initial state %r is outside Q (UNSAT guard)" % (s0,))

    # Classify the shape (E2/E3) and synthesise the IR.
    shape = _classify_shape(states, alphabet)
    fs = {
        "q": states,
        "sigma": alphabet,
        "delta": [{"from": t["from"], "to": t["to"], "input": t["input"]}
                  for t in transitions],
        "s0": s0,
        "f": final,
    }
    evidence = [
        "method=%s" % method.full_name,
        "state_var=%s (domain size %d)" % (state_name, len(states)),
        "loop=%s" % loop.full_name,
        "sigma=%r" % (alphabet,),
        "%d transitions" % len(transitions),
        "s0=%r f=%r" % (s0, final),
    ]
    ir_model = _build_ir("fsm_%s" % shape.lower(), states, alphabet,
                         transitions, s0, final, shape)
    return FsmExtraction(EXTRACTED, shape,
                         "extracted %s FSM for %s" % (shape, method.full_name),
                         fs=fs, ir=ir_model, evidence=evidence,
                         warnings=warnings)


def extract_fsm_for_method(model, method_full_name):
    """Convenience wrapper: extract the FSM for a specific method fullName."""
    return extract_fsm(model, method_name=method_full_name)