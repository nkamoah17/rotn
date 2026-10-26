# -*- coding: utf-8 -*-
"""mr_gate.py -- the top-level merge-request gate (Phase 3.6).

A *merge request* is a candidate change to a protocol: a before/after pair of
``rot.ir.ProtocolIR`` (or two registered target names).  The gate decides
whether the change may be merged, by running the change through the rest of the
Phase 2/3 pipeline and applying the blocking-permission rule:

    1. resolve before/after into ``ProtocolIR``s;
    2. compute the semantic spec diff          (3.4, rot.specdiff);
    3. deterministically check every invariant of interest on before and after
       (bounded witness search, rot.witness.find_witness_path over
       rot.linearization.linearize) -- this is the verdict core and the source
       of the *deterministic failing test*;
    4. apply the verdict rule (assurance ladder, see rot.invariants):
         BLOCK -- a violated invariant whose *effective* gate permission is
                  PERM_BLOCK: it is blocking-eligible (label in
                  {inductive_at_bound, bounded_depth}), pinned=True, and on a
                  rung that permits BLOCK (see RUNG_CEILING);
         WARN  -- a violated invariant whose effective permission is
                  PERM_WARN (a ``likely_on_traces`` invariant, or a
                  blocking-eligible one that is not pinned, or a
                  blocking-eligible pinned one on a rung that caps it at
                  WARN);
         PASS  -- no invariant is violated on the candidate, or only
                  PERM_ALERT (noted, non-gating) invariants are violated;
    5. compute the impact set on the gate contract (3.2, rot.gateimpact);
    6. generate the targeted test suite for the primary invariant (3.5,
       rot.targeted_test) and run each schedule through the existing W3/W4
       replay oracle (rot.targeted_test.replay_schedule);
    7. emit a verdict artifact (JSON) with the verdict, a justification, the
       affected invariants, the spec diff, the gate impact, the targeted
       schedules, the executed-test results, and the deterministic failing
       test (if any).

The verdict is a pure function of the invariants' *labels*, *pinned* flags and
*rungs* (see :class:`rot.invariants.Invariant.effective_permission`) plus
whether the invariant is violated on the candidate -- it does not depend on
engine timing or search order, and the deterministic failing test is the first
(counterexample) witness found by a breadth-first, action-order-stable search,
so repeated evaluations are reproducible.

Pure stdlib, Python 3.6 compatible.
"""

import os
import json

import rot.ir as ir
import rot.invariants as invariants
import rot.targets as targets
from rot import specdiff
from rot import gateimpact
from rot import targeted_test
from rot import witness
from rot.linearization import linearize


# ---------------------------------------------------------------------------
# Verdict constants
# ---------------------------------------------------------------------------
PASS = "PASS"
WARN = "WARN"
BLOCK = "BLOCK"


def _ensure_dir(out_dir):
    """Create ``out_dir`` (and parents) if it does not already exist."""
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------
class InvariantResult(object):
    """The gate's outcome for one named invariant against before/after."""

    def __init__(self, name, violated_before, violated_after,
                 witness_path=None, witness_state=None,
                 blocking=False, pinned=False, label=None, description="",
                 permission=None):
        self.name = name
        self.violated_before = bool(violated_before)
        self.violated_after = bool(violated_after)
        self.witness_path = list(witness_path or [])
        self.witness_state = (dict(witness_state) if witness_state else None)
        self.blocking = bool(blocking)
        self.pinned = bool(pinned)
        self.label = label
        self.description = description
        if permission is None:
            # Back-compat: results built before the assurance ladder had a
            # two-tier behaviour -- a blocking-eligible violation is a BLOCK,
            # any other violation is a WARN.
            permission = invariants.PERM_BLOCK if blocking \
                else invariants.PERM_WARN
        self.permission = int(permission)
        # A *regression* is one the change introduced: held before, breaks after.
        self.regression = (not self.violated_before) and self.violated_after

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "label": self.label,
            "pinned": self.pinned,
            "blocking": self.blocking,
            "permission": invariants.PERMISSION_NAMES.get(self.permission),
            "violated_before": self.violated_before,
            "violated_after": self.violated_after,
            "regression": self.regression,
            "witness_path": list(self.witness_path),
            "witness_state": (dict(self.witness_state)
                              if self.witness_state else None),
        }


class ExecutedTest(object):
    """The result of running one targeted (W3/W4) schedule on the candidate."""

    def __init__(self, schedule_id, property_name, expected, actual, failed):
        self.schedule_id = schedule_id
        self.property_name = property_name
        self.expected = expected
        self.actual = actual
        self.failed = bool(failed)

    def to_dict(self):
        return {
            "schedule_id": self.schedule_id,
            "property_name": self.property_name,
            "expected": self.expected,
            "actual": self.actual,
            "failed": self.failed,
        }


class DeterministicFailingTest(object):
    """A concrete, reproducible counterexample for a violated invariant."""

    def __init__(self, invariant_name, path, state, schedule_id=None):
        self.invariant_name = invariant_name
        self.path = list(path or [])
        self.state = (dict(state) if state else None)
        self.schedule_id = schedule_id

    def to_dict(self):
        return {
            "invariant_name": self.invariant_name,
            "path": list(self.path),
            "state": (dict(self.state) if self.state else None),
            "schedule_id": self.schedule_id,
        }


class MRVerdict(object):
    """The merge-request verdict artifact (serialisable to JSON)."""

    def __init__(self, verdict, justification, before_label, after_label,
                 invariants, spec_diff, gate_impact, schedules, executed,
                 deterministic, n, properties):
        self.verdict = verdict
        self.justification = justification
        self.before_label = before_label
        self.after_label = after_label
        self.invariants = list(invariants)
        self.spec_diff = spec_diff
        self.gate_impact = gate_impact
        self.schedules = list(schedules)
        self.executed = list(executed)
        self.deterministic = deterministic
        self.n = n
        self.properties = list(properties)

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "justification": self.justification,
            "before": self.before_label,
            "after": self.after_label,
            "n": self.n,
            "properties": list(self.properties),
            "invariants": [i.to_dict() for i in self.invariants],
            "spec_diff": self.spec_diff.to_dict(),
            "gate_impact": self.gate_impact.to_dict(),
            "schedules": [s.to_dict() for s in self.schedules],
            "executed_tests": [t.to_dict() for t in self.executed],
            "deterministic_failing_test": (
                self.deterministic.to_dict()
                if self.deterministic is not None else None),
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)

    def write(self, out_dir, base_name="mr-verdict"):
        """Serialise the verdict to ``<out_dir>/<base_name>.json``; return the path."""
        _ensure_dir(out_dir)
        path = os.path.join(out_dir, base_name + ".json")
        with open(path, "w") as f:
            f.write(self.to_json() + "\n")
        return path


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------
def _resolve_ir(x, n, what):
    """Resolve a target name or a ``ProtocolIR`` into a ``ProtocolIR``."""
    if isinstance(x, ir.ProtocolIR):
        return x
    if isinstance(x, str):
        if x not in targets.names():
            raise ValueError(
                "%s: %r is not a registered target and is not a ProtocolIR"
                % (what, x))
        return targets.build(x, n=n)
    raise TypeError(
        "%s: expected a registered target name (str) or a ProtocolIR, got %r"
        % (what, type(x)))


def _resolve_invariants(after, properties, n):
    """Resolve the invariants to check.

    ``properties`` is an optional list of invariant *names* (str) or
    :class:`rot.invariants.Invariant` objects.  When omitted, the target's full
    registered invariant set is used (requires ``after`` to be a registered
    name).
    """
    if properties is not None:
        out = []
        for p in properties:
            if isinstance(p, invariants.Invariant):
                out.append(p)
            elif isinstance(p, str):
                out.append(invariants.get(p, n))
            else:
                raise TypeError(
                    "each property must be an invariant name (str) or an "
                    "Invariant, got %r" % (type(p),))
        if not out:
            raise ValueError("properties must be a non-empty list")
        return out
    if isinstance(after, str) and after in targets.names():
        return [targets.get_property(after, p, n)
                for p in targets.list_properties(after)]
    raise ValueError(
        "no invariants to check: pass properties=[...] or use a registered "
        "target name")


def _check_model(model, invariant, max_states):
    """Deterministically check one invariant on a linearised model.

    Returns ``(violated, path, state)`` -- the first (counterexample) witness,
    or ``(False, None, None)`` if none is found within the search budget.
    """
    path, state = witness.find_witness_path(model, invariant.expression,
                                            max_states=max_states)
    if path is None:
        return (False, None, None)
    return (True, path, state)


# ---------------------------------------------------------------------------
# Verdict rule
# ---------------------------------------------------------------------------
def apply_verdict(invariant_results, candidate=None):
    """Apply the blocking-permission rule (assurance ladder).

    Returns ``(verdict, justification)`` for a list of
    :class:`InvariantResult`.  A violation *blocks* only when the invariant's
    effective gate permission is ``rot.invariants.PERM_BLOCK`` -- i.e. it is
    blocking-eligible (label ``inductive_at_bound`` / ``bounded_depth``),
    pinned, AND on a rung that permits BLOCK (see
    ``rot.invariants.RUNG_CEILING``).  A violation whose effective permission
    is ``PERM_WARN`` only *warns*; a violation whose effective permission is
    ``PERM_ALERT`` is merely noted (the MR still passes); no violation passes.

    ``candidate`` is an optional :class:`rot.ir.ProtocolIR`.  When given,
    each violated invariant's effective permission is additionally capped by
    the rung of the *last action* on its witness path: if that action carries
    a ``rung`` annotation (e.g. an environment action at ``RUNG_ENV``), the
    permission may not exceed ``RUNG_CEILING[action.rung]``.  This is how
    environment asynchrony (at-least-once queue, lossy channel, ...) can
    never drive a BLOCK.  Without ``candidate`` the rule is exactly the
    invariant's own rung ceiling (unchanged).
    """
    violated = [r for r in invariant_results if r.violated_after]
    if not violated:
        return (PASS,
                "no checked invariant is violated on the candidate "
                "(%d invariant(s) verified)" % len(invariant_results))

    def _effective(r):
        """Effective permission for ``r`` after the witness-action rung cap."""
        perm = r.permission
        if candidate is not None and r.witness_path:
            a = candidate.action(r.witness_path[-1])
            if a is not None and a.rung is not None:
                perm = min(perm, invariants.RUNG_CEILING.get(
                    a.rung, invariants.PERM_BLOCK))
        return perm

    pairs = [(r, _effective(r)) for r in violated]
    blocking = [r for r, p in pairs if p >= invariants.PERM_BLOCK]
    if blocking:
        names = ", ".join(sorted(r.name for r in blocking))
        return (BLOCK,
                "pinned blocking-eligible invariant(s) violated on the "
                "candidate: %s" % names)
    warned = [r for r, p in pairs if p >= invariants.PERM_WARN]
    noted = [r for r, p in pairs if p < invariants.PERM_WARN]
    names = ", ".join(sorted(r.name for r in warned))
    if warned:
        j = ("invariant(s) violated on the candidate but not blocking-eligible "
             "(not pinned, or a non-blocking label): %s" % names)
        if noted:
            j += " (noted, non-gating: %s)" % \
                 ", ".join(sorted(r.name for r in noted))
        demoted = [r for r, p in pairs if p < r.permission]
        if demoted:
            j += (" (rung-demoted by the witness action's rung: %s)"
                  % ", ".join(sorted(r.name for r in demoted)))
        return (WARN, j)
    names = ", ".join(sorted(r.name for r in noted))
    return (PASS,
            "only noted (non-gating) invariant(s) violated on the candidate "
            "(%d invariant(s) verified): %s" % (len(invariant_results), names))


def _pick_primary(invariant_results, invariants_list):
    """Pick the invariant that drives the 3.5 targeted suite.

    Preference: the first violated blocking invariant, then the first violated
    invariant, then the first invariant overall.
    """
    violated = [r for r in invariant_results if r.violated_after]
    for r in violated:
        if r.blocking:
            for inv in invariants_list:
                if inv.name == r.name:
                    return inv
    if violated:
        for inv in invariants_list:
            if inv.name == violated[0].name:
                return inv
    return invariants_list[0]


def _result_for(invariant_results, name):
    for r in invariant_results:
        if r.name == name:
            return r
    return invariant_results[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def evaluate_mr(before, after, properties=None, n=2, out_dir=None,
                max_states=200000):
    """Evaluate a merge request and return an :class:`MRVerdict`.

    Parameters
    ----------
    before, after :
        Each a registered target name (str) or a ``rot.ir.ProtocolIR``.
    properties :
        Optional list of invariant names or :class:`Invariant` objects to
        check.  When omitted, the target's full registered invariant set is
        used (so ``after`` must be a registered name).
    n : int
        Node/participant count used to build IRs from names and to resolve
        named invariants.
    out_dir : str or None
        When given, the verdict artifact is written to
        ``<out_dir>/mr-verdict.json``.
    max_states : int
        Search budget for the deterministic witness (counterexample) search.
    """
    before_ir = _resolve_ir(before, n, "before")
    after_ir = _resolve_ir(after, n, "after")
    invariants_list = _resolve_invariants(after, properties, n)

    before_label = before if isinstance(before, str) else before_ir.name
    after_label = after if isinstance(after, str) else after_ir.name

    # -- 3.4 semantic spec diff ----------------------------------------------
    sd = specdiff.compute_spec_diff(before_ir, after_ir)

    # -- deterministic per-invariant check (the verdict core) ----------------
    before_model = linearize(before_ir)
    after_model = linearize(after_ir)
    results = []
    for inv in invariants_list:
        vb, _pb, _sb = _check_model(before_model, inv, max_states)
        va, pa, sa = _check_model(after_model, inv, max_states)
        results.append(InvariantResult(
            name=inv.name,
            violated_before=vb,
            violated_after=va,
            witness_path=pa,
            witness_state=sa,
            blocking=inv.blocking_permission(),
            pinned=inv.pinned,
            label=inv.label,
            description=inv.description,
            permission=inv.effective_permission(),
        ))

    verdict, justification = apply_verdict(results, after_ir)

    # -- primary invariant for the 3.5 targeted suite ------------------------
    primary = _pick_primary(results, invariants_list)
    presult = _result_for(results, primary.name)
    primary_witness = presult.witness_path  # [] when the invariant holds

    # -- 3.2 impact set on the gate contract ---------------------------------
    gi = gateimpact.analyze_gate_impact(sd, primary_witness)

    # -- 3.5 targeted test generation ----------------------------------------
    schedules = targeted_test.generate_suite(
        before_ir, after_ir, primary.expression, sd, gi, primary_witness, n)

    # -- run the targeted schedules through the W3/W4 replay oracle ----------
    executed = []
    for s in schedules:
        actual = targeted_test.replay_schedule(after_ir, primary.expression,
                                               s.path)
        executed.append(ExecutedTest(
            schedule_id=s.schedule_id,
            property_name=primary.name,
            expected=s.expected_verdict,
            actual=actual["verdict"],
            failed=(actual["verdict"] == "violation"),
        ))

    # -- deterministic failing test (if the primary invariant was violated) --
    deterministic = None
    if presult.violated_after and presult.witness_path:
        deterministic = DeterministicFailingTest(
            invariant_name=primary.name,
            path=presult.witness_path,
            state=presult.witness_state,
            schedule_id=(executed[0].schedule_id if executed else None),
        )

    verdict_obj = MRVerdict(
        verdict=verdict,
        justification=justification,
        before_label=before_label,
        after_label=after_label,
        invariants=results,
        spec_diff=sd,
        gate_impact=gi,
        schedules=schedules,
        executed=executed,
        deterministic=deterministic,
        n=n,
        properties=[inv.name for inv in invariants_list],
    )
    if out_dir is not None:
        verdict_obj.write(out_dir)
    return verdict_obj


__all__ = [
    "PASS", "WARN", "BLOCK",
    "InvariantResult", "ExecutedTest", "DeterministicFailingTest", "MRVerdict",
    "apply_verdict", "evaluate_mr",
]
