# -*- coding: utf-8 -*-
"""classify.py -- Phase 3: claim classification on the robustness ladder.

Given the per-rung verdicts for one claim, this module:

  * classifies the claim (safety / liveness) from its kind;
  * reports the **highest** rung at which the claim was discharged (F1);
  * verifies the monotone-safety law (F1): the rungs where a claim is
    discharged must form a *prefix* of the ladder -- a definite ``violated`` at
    a lower rung with a discharge at a higher rung is impossible under the
    monotone reachable-state space and is a modelling bug the ladder
    must flag;
  * names the non-claims (F3): the compromised-harness rung is out of scope.

This is a thin, pure-stdlib layer over :class:`rot.verdicts.Verdict`; it does
not itself run any verification (that is :mod:`rot.ladder` + the pipeline).

Python 3.6 compatible (no f-strings).
"""

__all__ = [
    "NON_CLAIM_INTEGRITY",
    "NON_CLAIMS",
    "classify_claim",
    "discharged_at",
    "highest_discharged_rung",
    "verify_monotonicity",
    "non_claims",
]

# F3 -- the integrity rung is out of scope. A compromised *harness* (tampered
# gateway, injected transitions) is NOT a rung of the robustness ladder. It is
# a named non-claim on every claim packet (spec T2 / F3).
NON_CLAIM_INTEGRITY = (
    "compromised-harness (tampered gateway, injected transitions): OUT OF "
    "SCOPE -- not a rung of the robustness ladder (F3). The ladder weakens "
    "the *environment* (agent posture, benign harness faults); a tampered "
    "harness is a different threat model and is never claimed.")

#: The dual-soundness non-claim: liveness on a bare over-approximation is never
#: claimed; it is discharged only under stated fairness or a complete bounded
#: horizon (spec R2).
NON_CLAIM_LIVENESS_OVERAPPROX = (
    "unbounded liveness on a bare over-approximation: NEVER claimed; liveness "
    "is discharged only under stated fairness or a complete bounded horizon "
    "(dual-soundness R2).")

#: The named non-claims carried on every ladder report (spec F3 / T2 / R2).
NON_CLAIMS = [
    NON_CLAIM_INTEGRITY,
    NON_CLAIM_LIVENESS_OVERAPPROX,
]


def classify_claim(prop):
    """Classify a claim as ``"safety"`` or ``"liveness"`` (from its kind).

    ``prop`` is a :class:`rot.invariants.Invariant` (or any object with a
    ``kind`` attribute). Raises ``ValueError`` for an unknown kind.
    """
    kind = getattr(prop, "kind", "safety")
    if kind in ("safety", "liveness"):
        return kind
    raise ValueError("unknown claim kind %r" % (kind,))


def discharged_at(verdict):
    """True iff ``verdict`` discharges the claim at its rung.

    A discharge is a definite ``proven`` (the claim holds at that rung). An
    ``unknown`` / ``unsound`` / ``error`` is **not** a discharge (fail-closed),
    and a ``violated`` is the opposite of a discharge.
    """
    return getattr(verdict, "status", None) == "proven"


def highest_discharged_rung(per_rung):
    """F1: the **highest** rung level at which the claim was discharged.

    ``per_rung`` maps rung level (int) -> :class:`rot.verdicts.Verdict`.
    Returns the highest level with a discharge, or ``None`` if the claim was
    not discharged at any rung.
    """
    discharged = [level for level, v in per_rung.items() if discharged_at(v)]
    return max(discharged) if discharged else None


def verify_monotonicity(per_rung):
    """F1: verify the monotone-safety law.

    The reachable state space is monotone (``Reach(R0)`` is a subset of
    ``Reach(R1)`` is a subset of ``Reach(R2)``), so the rungs where a claim is
    *discharged* must form a
    *prefix* of the ladder: a definite ``violated`` at a lower rung with a
    discharge at a higher rung is impossible and is a modelling bug. Returns a
    list of violation strings (empty when the law holds).
    """
    violations = []
    levels = sorted(per_rung.keys())
    for i, li in enumerate(levels):
        if getattr(per_rung[li], "status", None) != "violated":
            continue
        for lj in levels[i + 1:]:
            if discharged_at(per_rung[lj]):
                violations.append(
                    "monotonicity violation: %s at rung %d but discharged at "
                    "higher rung %d -- the reachable state space is monotone "
                    "(Reach(Ri) is a subset of Reach(Rj)), so this is "
                    "impossible (F1)" % (per_rung[li].status, li, lj))
    return violations


def non_claims():
    """The named non-claims carried on every ladder report (spec F3 / T2 / R2)."""
    return list(NON_CLAIMS)
