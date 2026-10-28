# -*- coding: utf-8 -*-
"""coach.py -- the CoachingArtifact: coach the agent back in bounds, *with a proof*.

This module closes the motto gap -- "coach agents back in bounds when they
try" -- by making the coaching a **formal, auditable artifact** rather than a
verbal suggestion. It is the third leg of the ROTN triad:

  * **Rule**  -- the policy (the Dogwood ``.dw`` source);
  * **Proof** -- the RTF trace (:mod:`rot.trace`; the deterministic, hashable
                 reasoning that the policy is or isn't safe);
  * **Coach** -- the :class:`CoachingArtifact` (this module): the corrected
                 policy + the plain-English rationale + the *re-verification
                 proof* that the corrected behaviour is safe.

The 5-step loop
---------------

  1. **Detect**  -- verify the buggy policy; on ``VIOLATED`` capture the
                    witness (the concrete counterexample).
  2. **Explain** -- derive a plain-English rationale *from the witness*
                    (the reason the guard let the violation through).
  3. **Correct** -- produce the corrected policy: the same policy, but the
                    temporal sum is over ``request`` events, so in-flight
                    (issued, unsettled) requests are charged against the cap.
  4. **Re-check** -- verify the corrected policy; on ``PROVEN`` the coaching
                    is discharged (the corrected behaviour is *proven* safe).
  5. **Close**    -- package the artifact (deterministic, SHA-256, fail-closed).

Why "coach + proof" is the contribution
--------------------------------------

Reflexion (arXiv:2303.11366) and Self-Refine (arXiv:2303.17651) coach an LLM
with *verbal* feedback -- a natural-language critique that the model may or
may not act on. Neither produces a **guarantee**: the corrected behaviour is
asserted, not proved. Dogwood (the AWS Cedar temporal extension) is a
*runtime monitor / evaluator*: it decides one request against the settled
trace, and its own specification (guide §7) is a set of *operational*
meta-properties (fail-closed evaluation, total lowering, deterministic
identity) -- none of them a soundness-of-intent guarantee over concurrent,
in-flight activity.

ROTN's coaching is different: the correction is **discharged by a proof**.
The re-check step runs the same bounded-exhaustive engine that produced the
original violation, and the artifact is only ``closed`` when the corrected
policy is ``PROVEN`` within the recorded bound. If the correction does not
re-prove, the artifact is ``open`` -- never "coached."

Soundness contract (inherited from the engine)
-----------------------------------------------

* The re-check is **proven** only on a *definite* engine result (``proven``);
  an ``unknown`` / budget-truncated search is never read as proven.
* The coaching is **fail-closed**: a correction that cannot be re-proven is
  surfaced as ``open`` (status :data:`OPEN`), never silently assumed safe.

Determinism contract
--------------------

The artifact is a **pure function** of the buggy policy + the model knobs
(``max_inflight``, ``amount``, ``cap``, ``window``): no timestamps, no random
IDs, stable ordering -- the same input always produces the same bytes. It is
**hashable** (a top-level ``hash``, the SHA-256 of its canonical body) so it
can be referenced, compared, and re-verified byte-for-byte, exactly like the
RTF trace.

Pure stdlib, Python 3.6 compatible.
"""

import rot
from rot import trace as _trace  # reuse canonical_json + trace_hash (one source)

__all__ = [
    "SCHEMA",
    "CLOSED", "OPEN",
    "CoachingArtifact",
    "coach",
    "coach_hash",
    "canonical_json",
]

#: The coaching artifact schema tag (stable; bump on breaking changes).
SCHEMA = "caravel.coach/v1"

#: Coaching statuses (stable). The loop is fail-closed: only a re-check that
#: re-proves the corrected policy closes the coaching.
CLOSED = "closed"  # re-check PROVEN: the coaching is discharged.
OPEN = "open"      # re-check failed: the coaching is NOT discharged.


def canonical_json(obj, indent=None):
    """Deterministic JSON (sorted keys, stable separators).

    Delegates to :func:`rot.trace.canonical_json` so the coaching artifact and
    the RTF trace share one canonicaliser (byte-stable for the same input).
    """
    return _trace.canonical_json(obj, indent=indent)


def coach_hash(body):
    """SHA-256 hex digest of the coaching body's canonical JSON.

    This is the *hashable* part of the artifact: it pins the exact coaching
    (every field in the body) to a single stable identifier.
    """
    return _trace.trace_hash(body)


class CoachingArtifact(object):
    """A deterministic, hashable coaching artifact (coach + proof).

    The body is the 5-step loop record (``detect`` / ``explain`` / ``correct``
    / ``recheck`` / ``close``). The hash pins the exact coaching to a single
    stable identifier, so the artifact can be referenced, compared, and
    re-verified byte-for-byte -- the same contract as the RTF trace.
    """

    def __init__(self, body):
        self.body = body
        self.hash = coach_hash(body)

    def status(self):
        """The coaching status (:data:`CLOSED` / :data:`OPEN`)."""
        return self.body["status"]

    def to_dict(self):
        """The artifact body plus the top-level ``hash``."""
        d = dict(self.body)
        d["hash"] = self.hash
        return d

    def to_json(self, indent=2):
        """Deterministic, JSON-serialisable form (stable separators)."""
        return canonical_json(self.to_dict(), indent=indent)

    def __repr__(self):
        return "CoachingArtifact(status=%r, hash=%s...)" % (
            self.body.get("status"), self.hash[:12])


# ---------------------------------------------------------------------------
# 5-step loop helpers
# ---------------------------------------------------------------------------

def _verify(ir, max_states=100000):
    """Check the IR's pinned property with the bounded-exhaustive engine.

    Returns ``(status, witness, n_states)`` where status is one of
    ``"proven" | "violated" | "unknown"`` and witness is the violating state
    dict (``None`` for a proven / unknown verdict). Deterministic over the
    bounded state space.
    """
    from rot.linearization import linearize
    from rot.symbolic import SymbolicEngine
    model = linearize(ir)
    res = SymbolicEngine(model, max_states=max_states).check(ir.pinned_property)
    return res.status, res.witness, res.n_states


def _remap_event_kind(node, kind):
    """Create a copy of a ``.dw`` ``when`` expression with the event reference's
    ``kind`` remapped to ``kind`` (the corrected event kind).

    Duck-typed traversal of the :mod:`rot.dw` AST (the same discipline
    :mod:`rot.lower` uses), so the corrected policy is a faithful AST -- not a
    hand-written model. Leaves any node that is not part of the known ``.dw``
    shape untouched.
    """
    if node is None:
        return None
    from rot import dw as _dw
    if isinstance(node, _dw.EventRef):
        return _dw.EventRef(node.namespace, node.action, kind, node.fields)
    if isinstance(node, _dw.Sum):
        return _dw.Sum(node.summand, node.bindings,
                       _remap_event_kind(node.where, kind))
    if isinstance(node, _dw.Count):
        return _dw.Count(node.bindings, _remap_event_kind(node.where, kind))
    if isinstance(node, _dw.Exists):
        return _dw.Exists(node.binding, _remap_event_kind(node.body, kind))
    if isinstance(node, _dw.FormerlyWithin):
        return _dw.FormerlyWithin(node.window, _remap_event_kind(node.body, kind))
    if isinstance(node, _dw.BinaryOp):
        return _dw.BinaryOp(node.op, _remap_event_kind(node.left, kind),
                            _remap_event_kind(node.right, kind))
    if isinstance(node, _dw.UnaryOp):
        return _dw.UnaryOp(node.op, _remap_event_kind(node.operand, kind))
    if isinstance(node, _dw.LetCall):
        return _dw.LetCall(node.name,
                           [_remap_event_kind(a, kind) for a in node.args])
    return node


def _corrected_policy(policy):
    """The corrected policy: the same policy, but the temporal sum is over
    ``request`` events so in-flight (issued, unsettled) requests are charged
    against the cap.

    The correction is a faithful AST rewrite (the event reference's ``kind`` is
    remapped from ``response`` to ``request``), not a hand-written model -- so
    the corrected policy is derived from the buggy one, with no drift.
    """
    from rot import dw as _dw
    corrected_when = _remap_event_kind(policy.when, "request")
    return _dw.DwPolicy(
        policy_id=policy.policy_id,
        action=policy.action,
        event_kind="request",
        cap=policy.cap,
        window=policy.window,
        source=policy.source,
        when=corrected_when,
    )


def _guard_str(ir, action_name="spend_ok"):
    """Render the ``spend_ok`` guard of ``ir`` as a stable string."""
    from rot.design_view import expr_to_str
    return expr_to_str(ir.action(action_name).guard)


def _explain(policy, witness, amount, cap):
    """Derive a plain-English rationale *from the witness* (deterministic).

    The rationale is a pure function of the policy's event kind, the witness
    state, and the model knobs -- so the same coaching always explains itself
    the same way.
    """
    inflight = int((witness or {}).get("inflight", 0))
    completed = int((witness or {}).get("completed", 0))
    exposure = completed + inflight * amount
    rationale = (
        "The policy sums over '%s' events, so it charges only settled requests. "
        "In the witness (completed=%d, inflight=%d) the %d in-flight requests "
        "are invisible to the decision: each of the %d parallel fires sees "
        "completed=0 and is admitted, pushing total exposure to %d -- past the "
        "cap of %d."
        % (policy.event_kind, completed, inflight, inflight, inflight,
           exposure, cap)
    )
    root_cause = (
        "the spend_ok guard sums over '%s' events only; in-flight (issued, "
        "unsettled) requests are not charged against the cap"
        % policy.event_kind
    )
    return {
        "rationale": rationale,
        "root_cause": root_cause,
        "witness": witness,
        "exposure": exposure,
        "cap": cap,
    }



def coach(policy, max_inflight=None, amount=None, cap=None, window=None,
          max_states=100000, corrected=None):
    """Run the 5-step coaching loop on a buggy spend-cap policy.

    Parameters
    ----------
    policy : rot.dw.DwPolicy
        The buggy policy to coach (the ``response``-sum variant).
    max_inflight : int, optional
        The bounded in-flight pool ``K`` (defaults to ``spendcap.MAX_INFLIGHT``).
    amount : int, optional
        The per-request amount (defaults to ``spendcap.AMOUNT``).
    cap : int, optional
        The spend cap (defaults to the policy's own cap).
    window : int, optional
        The temporal window ``W`` (defaults to ``spendcap.MAX_WINDOW``).
    max_states : int, optional
        The state budget for the engine (default 100000).
    corrected : rot.dw.DwPolicy, optional
        The corrected policy to re-check (defaults to the ``request``-sum
        variant derived from ``policy``). Pass a policy that does *not*
        re-prove to exercise the fail-closed path (status :data:`OPEN`).

    Returns
    -------
    CoachingArtifact
        The deterministic, hashable coaching artifact (fail-closed).
    """
    import rot.spendcap as _sp

    # Resolve the knobs (deterministic defaults).
    k = _sp.MAX_INFLIGHT if max_inflight is None else int(max_inflight)
    amt = _sp.AMOUNT if amount is None else int(amount)
    cp = int(cap if cap is not None else policy.cap)
    w = _sp.MAX_WINDOW if window is None else int(window)

    # 1. Detect: verify the buggy policy; capture the witness.
    ir_buggy = policy.to_ir(max_inflight=k, amount=amt, cap=cp, window=w)
    buggy_status, witness, buggy_n_states = _verify(ir_buggy, max_states)

    # 2. Explain: derive the rationale from the witness.
    explain = _explain(policy, witness, amt, cp)

    # 3. Correct: produce the corrected policy (the request-sum variant).
    if corrected is None:
        corrected = _corrected_policy(policy)
    ir_corrected = corrected.to_ir(max_inflight=k, amount=amt, cap=cp, window=w)
    correct_guard = _guard_str(ir_corrected)
    buggy_guard = _guard_str(ir_buggy)

    # 4. Re-check: verify the corrected policy.
    corrected_status, corrected_witness, corrected_n_states = _verify(
        ir_corrected, max_states)

    # 5. Close: package the artifact (fail-closed).
    closed = (corrected_status == "proven")
    status = CLOSED if closed else OPEN
    discharge = (
        "the corrected policy is proven safe within the bound (K=%d, W=%d): "
        "the coaching is discharged" % (k, w)
        if closed else
        "the corrected policy did not re-prove (status=%s); the coaching is "
        "NOT discharged (fail-closed)" % corrected_status
    )

    body = {
        "schema": SCHEMA,
        "rot_version": rot.__version__,
        "status": status,
        "policy": {
            "policy_id": policy.policy_id,
            "action": policy.action,
            "event_kind": policy.event_kind,
            "cap": cp,
            "window": w,
            "amount": amt,
            "max_inflight": k,
        },
        "detect": {
            "status": buggy_status,
            "witness": witness,
            "n_states": buggy_n_states,
            "engine": "symbolic",
        },
        "explain": explain,
        "correct": {
            "event_kind": corrected.event_kind,
            "guard": correct_guard,
            "buggy_guard": buggy_guard,
            "delta": "%s -> %s (charge in-flight against the cap)"
                     % (policy.event_kind, corrected.event_kind),
            "policy": corrected.summary(),
        },
        "recheck": {
            "status": corrected_status,
            "witness": corrected_witness,
            "n_states": corrected_n_states,
            "engine": "symbolic",
        },
        "close": {
            "status": status,
            "discharge": discharge,
        },
    }
    return CoachingArtifact(body)

