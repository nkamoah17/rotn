# -*- coding: utf-8 -*-
"""invariants.py -- named safety invariants for the product plane.

The pipeline pins ONE invariant at a time (the soundness core is
property-directed: abstraction keeps only the property's free-variable closure).
This module is the registry of *named* invariants we can pin, so the CLI and the
report can refer to them by a stable name rather than an ad-hoc expression.

The product plane carries the policy-plane and agent-harness invariants
(spend-cap, exfiltration, over-privilege, and the structural soundness core).
The protocol-plane and governance-plane invariants (2PC, ZAB, PBFT, payment
composition, approval/delegation, orchestration liveness) live in the research
plane -- the ``rotn_research`` package (the ``rotn-research`` repository),
which builds on this module and extends the registry
(see ``rotn_research.invariants``).

Each :class:`Invariant` carries:

  * a stable ``name``, a human ``description``, and the ``Expr`` predicate
    that must hold in every reachable state;
  * an assurance **label** that records *how* the invariant was justified:

      - ``inductive_at_bound`` -- proven inductively by a verifier (Apalache)
        at bound B.  Strongest; may block an MR when pinned.
      - ``bounded_depth``      -- holds under bounded model checking to
        depth D (the symbolic engine's exhaustive BFS, or TLC to depth D).
        May block an MR when pinned.
      - ``likely_on_traces``   -- "likely: holds on N traces."  Weakest;
        informational only, never blocks.

  * a **pinned** flag: a human has explicitly approved this property as a
    blocking gate.

Only invariants whose label is ``inductive_at_bound``, ``bounded_depth`` or
``bounded_eventually`` **and** whose ``pinned`` flag is True may produce a
BLOCK verdict at the merge-request gate.  This is the Phase 3
blocking-permission rule:

    blocking_permission  ==  label in {inductive_at_bound, bounded_depth,
                                       bounded_eventually}
                             AND
                             pinned == True

Most invariants are *safety*: the predicate must hold in **every** reachable
state.  The ``bounded_eventually`` invariant is the first *liveness*
invariant (``kind="liveness"``): its ``expression`` is a **goal** predicate
that must be *reachable* within a bounded horizon, and the CEGAR loop
(``rot.cegar``) dispatches it to ``SymbolicEngine.reach_within`` instead of
a universal safety check.

The expressions are built with the same ``rot.ir`` helpers the target IRs use
(rot.spendcap, rot.agent_step, rot.agent_harness), so they evaluate with the
IR's own three-valued ``Expr.eval``.

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir
import rot.spendcap as spendcap
import rot.agent_step as agent_step
import rot.agent_harness as agent_harness


# ---------------------------------------------------------------------------
# Label constants
# ---------------------------------------------------------------------------
LABEL_INDUCTIVE    = "inductive_at_bound"
LABEL_BOUNDED      = "bounded_depth"
LABEL_LIKELY       = "likely_on_traces"
LABEL_EVENTUALLY   = "bounded_eventually"

#: Invariant kinds.  Safety predicates must hold in **every** reachable state
#: (``SymbolicEngine.check``); liveness predicates must be **reachable**
#: within a bounded horizon (``SymbolicEngine.reach_within``).  A *constraint*
#: is a state constraint (a ``TypeInvariant``-style well-formedness predicate):
#: it is not a property to be checked -- it *restricts* the state space, so a
#: state that violates it is **dropped** from the reachable set (never a
#: ``VIOLATED`` counterexample).  In the TLA+ spec it is emitted as a state
#: constraint (``INVARIANT`` in the ``.cfg``), never as a ``PROPERTY``.
KIND_SAFETY   = "safety"
KIND_LIVENESS = "liveness"
KIND_CONSTRAINT = "constraint"

#: The three well-formed property kinds.  ``KIND_CONSTRAINT`` is the
#: state-constraint kind (well-formedness); the other two are temporal
#: properties (safety / liveness).
KINDS = (KIND_SAFETY, KIND_LIVENESS, KIND_CONSTRAINT)

#: The set of labels that are strong enough to block an MR (when also pinned).
BLOCKING_LABELS = frozenset((LABEL_INDUCTIVE, LABEL_BOUNDED, LABEL_EVENTUALLY))


# ---------------------------------------------------------------------------
# Assurance ladder: severity rungs and gate permissions
# ---------------------------------------------------------------------------
# These constants live in :mod:`rot.ir` -- the IR is the narrow waist that owns
# the rung/permission model of ``Action.rung`` (see :data:`rot.ir.RUNG_CEILING`).
# They are re-exported here so that the historical import path
# (``from rot.invariants import RUNG_CEILING``) keeps working and so that
# :class:`Invariant` and the registered invariants below can reference the
# rungs without any dependency change.
from rot.ir import (  # noqa: F401  (re-export for backward compatibility)
    PERM_ALERT, PERM_WARN, PERM_BLOCK,
    RUNG_STRUCTURAL, RUNG_LOCAL, RUNG_PROTOCOL, RUNG_E2E,
    RUNG_ENV, ALL_RUNGS, RUNG_CEILING, PERMISSION_NAMES,
)


class Invariant(object):
    """A named, pinnable safety invariant with an assurance label.

    Parameters
    ----------
    name, description, expression, kind :
        Stable name, human text, IR predicate, and the invariant kind:
        ``"safety"`` (default -- the predicate must hold in every reachable
        state) or ``"liveness"`` (the predicate is a *goal* that must be
        reachable within a bounded horizon; the CEGAR loop dispatches it to
        ``SymbolicEngine.reach_within``).
    label : str or None
        One of :data:`LABEL_INDUCTIVE`, :data:`LABEL_BOUNDED`,
        :data:`LABEL_LIKELY`, or ``None`` if the invariant has not yet been
        justified (no label assigned).
    pinned : bool
        True when a human has approved this invariant as a blocking gate.
    bound : int or None
        The numeric bound that the label refers to:
        the induction bound B for ``inductive_at_bound``, or the BMC depth D
        for ``bounded_depth``.  ``None`` if not yet recorded.
    n_traces : int or None
        The number of traces the invariant held on, for the
        ``likely_on_traces`` label.  ``None`` for the other labels.
    rung : int
        The severity rung of the assurance ladder
        (:data:`RUNG_STRUCTURAL` .. :data:`RUNG_E2E`).  The rung imposes a
        *ceiling* on the gate permission a violation of this invariant may
        have (see :data:`RUNG_CEILING`).  Defaults to
        :data:`RUNG_PROTOCOL`, which preserves the pre-ladder behaviour of
        every existing invariant.
    policy_clause : str or None
        A short, human-readable statement of the specific policy clause this
        invariant encodes (e.g. "the sum over all requests (settled +
        in-flight) must not exceed the cap").  Recorded on counterexample
        trace steps (``Verdict.trace``) so a reported violation can be tied
        back to the clause it breaks.  ``None`` when not set.
    violation_code : str or None
        The :data:`rot.verdicts` violation code this invariant's violation
        carries (e.g. ``DEADLOCK`` for ``no_deadlock``).  When set, the CEGAR
        layer stamps VIOLATED verdicts with this code instead of the default
        (``POLICY_DENIAL`` for safety / ``LIVENESS_BOUND_EXCEEDED`` for
        liveness).  ``None`` when not set (the default applies).
    """

    def __init__(self, name, description, expression, kind="safety",
                 label=None, pinned=False, bound=None, n_traces=None,
                 rung=RUNG_PROTOCOL, policy_clause=None,
                 violation_code=None):
        if label is not None and label not in (LABEL_INDUCTIVE,
                                               LABEL_BOUNDED,
                                               LABEL_LIKELY,
                                               LABEL_EVENTUALLY):
            raise ValueError("unknown invariant label %r "
                             "(expected one of %r)"
                             % (label, (LABEL_INDUCTIVE, LABEL_BOUNDED,
                                       LABEL_LIKELY, LABEL_EVENTUALLY)))
        if rung not in RUNG_CEILING:
            raise ValueError("unknown invariant rung %r "
                             "(expected one of %r)" % (rung, ALL_RUNGS))
        self.name = name
        self.description = description
        self.expression = expression
        self.kind = kind
        self.label = label
        self.pinned = bool(pinned)
        self.bound = int(bound) if bound is not None else None
        self.n_traces = int(n_traces) if n_traces is not None else None
        self.rung = int(rung)
        self.policy_clause = policy_clause
        self.violation_code = violation_code

    # -- blocking permission -------------------------------------------------
    def declared_permission(self):
        """The gate permission the invariant's label and pinning ask for.

        A blocking-eligible (label in ``BLOCKING_LABELS``) AND pinned
        invariant declares :data:`PERM_BLOCK`; any other invariant declares
        :data:`PERM_WARN` (a violation is at least worth flagging).
        """
        if (self.label in BLOCKING_LABELS) and self.pinned:
            return PERM_BLOCK
        return PERM_WARN

    def effective_permission(self):
        """The gate permission this invariant's violations may actually reach.

        The rung imposes a *ceiling* on the declared permission (see
        :data:`RUNG_CEILING`): a rung can only lower the permission an
        invariant declares, never raise it.
        """
        return min(self.declared_permission(), RUNG_CEILING[self.rung])

    def blocking_permission(self):
        """True iff this invariant may produce a BLOCK at the MR gate.

        The rule (Phase 3 spec + assurance ladder):
          * the label must be ``inductive_at_bound`` or ``bounded_depth``
            (``likely_on_traces`` never blocks); AND
          * a human must have pinned the property (``pinned == True``); AND
          * the invariant's rung must allow :data:`PERM_BLOCK` (the
            :data:`RUNG_PROTOCOL` and :data:`RUNG_E2E` rungs do;
            :data:`RUNG_STRUCTURAL` and :data:`RUNG_LOCAL` can never
            reach a BLOCK, no matter how they are pinned).
        """
        return self.effective_permission() >= PERM_BLOCK

    # -- serialization -------------------------------------------------------
    def to_dict(self):
        d = {
            "name": self.name,
            "description": self.description,
            "kind": self.kind,
            "label": self.label,
            "pinned": self.pinned,
            "bound": self.bound,
            "n_traces": self.n_traces,
            "rung": self.rung,
            "policy_clause": self.policy_clause,
            "permission": PERMISSION_NAMES.get(self.effective_permission()),
            "blocking_permission": self.blocking_permission(),
        }
        if self.expression is not None:
            d["expression"] = self.expression.to_dict()
        return d

    def __repr__(self):
        return "<Invariant %s (label=%r, pinned=%r)>" % (
            self.name, self.label, self.pinned)


# ---------------------------------------------------------------------------
# G0: well-formedness (TypeInvariant) -- a state constraint, not a property
# ---------------------------------------------------------------------------
def _wf_clause(v):
    """The well-formedness clause for one state variable, from its domain.

    Returns an :class:`rot.ir.Expr` (or ``None`` for an unhandled domain).

    * ``IntRange`` [lo, hi]  -> ``lo <= v <= hi`` (covers *domains* and the
      *budget bounds* of a budget/spend variable declared ``[0, cap]``);
    * ``Bool``               -> ``v \\in {TRUE, FALSE}`` (a *domain* check);
    * ``Enum`` {v1, ...}     -> ``v \\in {v1, ...}`` (*label membership* when the
      enum is a label set, *history shape* when its values are the well-formed
      shapes of a history variable).
    """
    d = v.domain
    if isinstance(d, ir.IntRange):
        return ir.And(ir.BinOp(">=", ir.V(v.name), ir.C(d.lo)),
                      ir.BinOp("<=", ir.V(v.name), ir.C(d.hi)))
    if isinstance(d, ir.Bool):
        return ir.BinOp("in", ir.V(v.name), ir.C([True, False]))
    if isinstance(d, ir.Enum):
        return ir.BinOp("in", ir.V(v.name), ir.C(list(d.values)))
    return None


def type_invariant(model):
    """``TypeInvariant`` -- the model's well-formedness *state constraint*.

    This is a **state constraint** (``kind == KIND_CONSTRAINT``), *not* a
    temporal property: it *restricts* the reachable state space to well-formed
    states rather than being a claim checked over behaviours. A state that
    violates it is **dropped** from the reachable set (never a ``VIOLATED``
    counterexample), and in the TLA+ spec it is emitted as a *constraint*
    (baked into ``Init``/``Next`` and listed as ``INVARIANT``), never as a
    ``PROPERTY`` (see ``rot.emitter.emit_spec``).

    The predicate is the conjunction, over every declared state variable, of
    the well-formedness clause for its domain, covering the four
    well-formedness categories:

    * **domains**         -- an ``IntRange`` variable ``v`` satisfies
                            ``lo <= v <= hi``; a ``Bool`` variable is a boolean;
    * **budget bounds**   -- a budget/spend variable declared ``IntRange``
                            ``[0, cap]`` is non-negative and within the cap;
    * **label membership** -- an ``Enum`` label variable is a declared member
                            of its label set (``v \\in {labels}``);
    * **history shape**   -- a history variable (an ``Enum`` whose values are
                            the well-formed shapes) holds one of them
                            (``v \\in {shapes}``).

    Parameters
    ----------
    model : rot.ir.ProtocolIR
        The protocol model whose declared state-variable domains define the
        well-formedness predicate.
    """
    conjs = []
    for v in model.variables:
        clause = _wf_clause(v)
        if clause is not None:
            conjs.append(clause)
    expr = ir.And(*conjs) if conjs else ir.T()
    return Invariant(
        name="type_invariant",
        description="TypeInvariant: every state variable is well-formed in its "
                    "declared domain (domains, budget bounds, label membership, "
                    "history shape) -- a state constraint, not a property",
        expression=expr,
        kind=KIND_CONSTRAINT,
        # A state *constraint* is not a blocking claim: it restricts the state
        # space (ill-formed states are dropped), so it is neither pinned nor
        # labelled as an MR-gate permission (a constraint violation is never a
        # VIOLATED counterexample).
        label=None,
        pinned=False,
        rung=RUNG_STRUCTURAL,
        policy_clause="well-formedness: every state variable holds a well-formed "
                      "value in its declared domain",
    )


def agreement(n=3):
    """2PC agreement: decisions, once made, agree across participants.

    For every pair of participants that have both made a real (non-none)
    decision, those decisions must be identical. Tolerates the transient
    'some decided, some not yet' states while the coordinator's decision is
    being applied.
    """
    conjs = []
    for i in range(1, n + 1):
        for j in range(i + 1, n + 1):
            none_i = ir.eq(ir.V("applied_%d" % i), ir.C("none"))
            none_j = ir.eq(ir.V("applied_%d" % j), ir.C("none"))
            equal = ir.eq(ir.V("applied_%d" % i), ir.V("applied_%d" % j))
            conjs.append(ir.Or(none_i, none_j, equal))
    return Invariant(
        name="agreement",
        description="2PC agreement: participants that have both decided apply "
                    "the same decision",
        expression=ir.And(*conjs) if conjs else ir.T(),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=True,
        bound=None,  # depth D recorded at verification time (engine max_states)
    )


def validity(n=3):
    """2PC validity: the coordinator commits only if every participant voted yes.

    If ``decision = commit`` then every ``vote_i = yes``. (The converse is not
    required: aborting on all-yes is allowed, committing on any no is not.)
    """
    conjs = [
        ir.If(ir.eq(ir.V("decision"), ir.C("commit")),
              ir.eq(ir.V("vote_%d" % i), ir.C("yes")),
              ir.T())
        for i in range(1, n + 1)
    ]
    return Invariant(
        name="validity",
        description="2PC validity: a commit decision implies all-yes votes",
        expression=ir.And(*conjs),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=True,
    )


def no_spurious_abort(n=3):
    """2PC 'never abort on unanimous yes' (a liveness-flavoured safety proxy).

    If every participant voted yes, the coordinator must not decide abort.
    Useful to show the registry drives different abstractions (different
    free-variable closures) than agreement.
    """
    all_yes = ir.And(*[ir.eq(ir.V("vote_%d" % i), ir.C("yes"))
                      for i in range(1, n + 1)])
    not_abort = ir.neq(ir.V("decision"), ir.C("abort"))
    return Invariant(
        name="no_spurious_abort",
        description="unanimous-yes never leads to an abort decision",
        expression=ir.If(all_yes, not_abort, ir.T()),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=False,  # liveness proxy; informational, not a blocking gate
    )


def spendcap_within_cap(n=1):
    """Spendcap: settled + in-flight amount never exceeds the cap.

    ``completed + inflight * AMOUNT <= CAP`` in every reachable state.  This
    is the parallel-fire guarantee of the AWS Dogwood spend-cap policy:
    admitted-but-unsettled (in-flight) requests count against the cap
    *before* their responses settle.  It discriminates the two variants --
    the buggy ``spend_ok`` guard (settled-only accounting) lets a burst of
    parallel fires grow the in-flight amount past the cap, while the correct
    guard (in-flight accounting) keeps it within the cap.

    Single-service property, but the decision-plane guarantee the MR gate
    exists to enforce (like ``policy_conformance``): pinned,
    :data:`LABEL_BOUNDED`, on the :data:`RUNG_PROTOCOL` rung -- a blocking
    gate, not merely a warning.
    """
    return Invariant(
        name="spendcap_within_cap",
        description="spendcap: settled + in-flight amount never exceeds the cap "
                    "(completed + inflight * AMOUNT <= CAP)",
        expression=spendcap.within_cap_property(),
        kind=KIND_SAFETY,
        label=LABEL_BOUNDED,
        pinned=True,
        rung=RUNG_PROTOCOL,  # decision-plane property: blocking-eligible
        policy_clause="spendcap: the sum over all requests (settled + in-flight) "
                      "must not exceed the cap",
    )


def no_exfiltration(n=1):
    """AgentHarness: private data never reaches an unapproved channel.

    ``NOT exfiltrated`` in every reachable state of the exfiltration
    agent-harness IR.  The agent is a *nondeterministic actor* that may attempt
    any tool in its catalog; only the harness's policy decision (the guard on
    ``send_unapproved``) can stop an exfiltration.  This is the structural,
    provable half of the thesis's ``NoExfiltration`` rule -- a correct policy
    makes it unreachable (PROVEN), a buggy one leaves it reachable (VIOLATED,
    witness = the exfiltration path).

    ``n`` is accepted for registry compatibility (the slice is single-actor).
    Single-actor (the agent) property on the :data:`RUNG_PROTOCOL` rung (the
    agent's decision plane): pinned, :data:`LABEL_BOUNDED`, a blocking gate.
    """
    return Invariant(
        name="no_exfiltration",
        description="agent-harness: private data never reaches an unapproved "
                    "channel (NOT exfiltrated in every reachable state)",
        expression=agent_harness.no_exfiltration_property(),
        kind=KIND_SAFETY,
        label=LABEL_BOUNDED,
        pinned=True,
        rung=RUNG_PROTOCOL,  # the agent's decision plane: a blocking gate
        policy_clause="exfiltration: sending while holding private data must "
                      "be denied by the harness policy",
    )


def policy_conformance(n=1, policy=None):
    """AgentStep: the agent never takes an action denied by its policy.

    Single-actor (the agent) property over the ``agent-step`` IR:
    ``decision notin policy.denied`` in every reachable state.  This is the
    discriminator between the *conforming* and *adversarial* agent variants
    and the core guarantee of the adversarial-agent security pivot.  Because
    it is the property we want to gate on, it carries a blocking label and is
    pinned, on the :data:`RUNG_PROTOCOL` rung (the agent's decision plane) --
    so a reachable policy violation may produce a BLOCK verdict.
    """
    return Invariant(
        name="policy_conformance",
        description="agent-step: the agent never takes an action denied by "
                    "its adversarial policy (decision notin policy.denied)",
        expression=agent_step.policy_conformance_property(policy),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=True,
        rung=RUNG_PROTOCOL,  # the agent's decision plane: a blocking gate
    )


def bounded_eventually(n=1, name="bounded_eventually", description=None,
                       goal=None):
    """Bounded liveness: the agent's decision step terminates (AGENT_STEP).

    Within a bounded horizon the agent commits to a concrete action -- the
    linear model reaches a state where ``decision != "idle"``.  This is the
    first *liveness* invariant (``kind="liveness"``): its ``expression`` is
    a **goal** predicate, not a universal safety predicate, so it is
    evaluated differently by the CEGAR loop (``rot.cegar``), which dispatches
    it to ``SymbolicEngine.reach_within`` over the linear model:

        REACHED     -> the goal is reachable within the horizon: PROVEN
        NOT_REACHED -> the goal is not reachable within the horizon: VIOLATED
        UNKNOWN     -> inconclusive within the horizon (truncated search)

    ``n`` is accepted for registry compatibility (the AgentStep slice is
    single-actor); ``goal`` may override the default reachability target.
    """
    if goal is None:
        goal = ir.neq(ir.V("decision"), ir.C("idle"))
    if description is None:
        description = (
            "bounded liveness: within the bounded horizon the agent commits "
            "to a concrete action (decision != idle) -- evaluated by "
            "SymbolicEngine.reach_within, not a universal safety check")
    return Invariant(
        name=name,
        description=description,
        expression=goal,
        kind=KIND_LIVENESS,
        label=LABEL_EVENTUALLY,
        pinned=True,
    )

# ---------------------------------------------------------------------------
# G6: over-privileged tool bind (rot.agent_harness)
# ---------------------------------------------------------------------------
def no_over_privileged_tool(n=1):
    """No over-privileged tool (G6 bind, model-checked over-grant).

    The agent never takes a tool the harness *permits* but the task does not
    *require* (``NOT took_unneeded`` in every reachable state).  The correct
    policy denies the unneeded tool (the property holds); the buggy policy
    over-grants it, so the model checker refutes the property with a witness
    (the state where the over-privileged tool was taken).

    :data:`RUNG_E2E` rung: pinned, :data:`LABEL_BOUNDED`, a blocking gate.
    """
    return Invariant(
        name="no_over_privileged_tool",
        description="over-privilege: the agent never takes a tool the harness "
                    "permits but the task does not require (no over-grant)",
        expression=agent_harness.no_over_privileged_tool_property(),
        kind=KIND_SAFETY,
        label=LABEL_BOUNDED,
        pinned=True,
        rung=RUNG_E2E,
        policy_clause="over-privilege: the harness must not permit a tool "
                      "whose effect is reachable but never needed by any "
                      "task-completing path",
    )


_REGISTRY = {
    "agreement": agreement,
    "policy_conformance": policy_conformance,
    "bounded_eventually": bounded_eventually,
    "validity": validity,
    "no_spurious_abort": no_spurious_abort,
    "spendcap_within_cap": spendcap_within_cap,
    "no_exfiltration": no_exfiltration,
    # G6: over-privileged tool bind
    "no_over_privileged_tool": no_over_privileged_tool,
}


def names():
    """Stable names of all registered invariants (ordered).

    Dynamic: includes any research kinds added via :func:`register`
    (e.g. ZAB/PBFT/payment/approval from ``rotn_research``).
    """
    return sorted(_REGISTRY)


def get(name, n=3):
    """Look up a registered invariant by name (default n=3 participants)."""
    if name not in _REGISTRY:
        raise KeyError("no invariant %r; have %r" % (name, names()))
    return _REGISTRY[name](n)


def register(name, factory):
    """Register an invariant kind under ``name`` (extension point).

    Research packages (``rotn_research``) use this to add their invariant
    kinds (e.g. ZAB/PBFT/payment/approval) to the shared registry without
    the product importing any research module.  The product never needs to
    know these names; they resolve only once the research package has been
    imported (which re-registers them here).
    """
    _REGISTRY[name] = factory
    return factory


def default(n=3):
    """The invariant the 2PC vertical slice pins by default: agreement."""
    return agreement(n)


__all__ = ["Invariant",
           "LABEL_INDUCTIVE", "LABEL_BOUNDED", "LABEL_LIKELY", "LABEL_EVENTUALLY",
           "KIND_SAFETY", "KIND_LIVENESS", "KIND_CONSTRAINT", "KINDS",
           "BLOCKING_LABELS",
           "PERM_ALERT", "PERM_WARN", "PERM_BLOCK",
           "RUNG_STRUCTURAL", "RUNG_LOCAL", "RUNG_PROTOCOL", "RUNG_E2E",
           "RUNG_ENV",
           "ALL_RUNGS", "RUNG_CEILING", "PERMISSION_NAMES",
           "type_invariant", "agreement", "policy_conformance",
           "bounded_eventually", "validity", "no_spurious_abort",
           "spendcap_within_cap", "no_exfiltration",
           "no_over_privileged_tool",
           "names", "get", "register", "default"]
