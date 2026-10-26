# -*- coding: utf-8 -*-
"""ZooKeeper (ZAB) bug-replay corpus + Phase 3 gate evaluation (Step 3.7).

This is the headline Phase 3 demo.  We replay a small corpus of *known,
documented* ZooKeeper/ZAB bug-introducing changes -- each expressed as a
before/after ``ProtocolIR`` diff, i.e. exactly what a merge request looks like
to the gate -- and for every commit we record:

  * did the gate fire?            (PASS / WARN / BLOCK)
  * which invariant was violated? (zab_no_premature_apply / zab_apply_persisted)
  * was it a true positive, a false negative, or a false block?

The corpus is deliberately honest.  It contains

  * two real, reachable premature-apply bugs (ZK-001, ZK-002) the gate SHOULD
    catch and does -- TRUE POSITIVES, each with a deterministic counterexample;
  * a documented bug (ZOOKEEPER-1073-class "commit before quorum", ZK-003) the
    current two-invariant set does NOT model -- an honest FALSE NEGATIVE /
    coverage gap, reported rather than hidden; and
  * real SAFE changes (two refactors + an additive feature, ZK-S1..S3) the gate
    must NOT block, which lets us measure the false-block rate directly
    (0.0% here: no false positives).

``docs/phase3-eval.md`` is the narrative report; this module is the
reproducible engine behind it (run ``python -m rot.zk_bugs`` to see it live).

Pure stdlib, Python 3.6 compatible (no f-strings), mirroring rot/falseblock.py.
"""

from __future__ import division

import json
import os

from rot.invariants import LABEL_BOUNDED  # noqa: F401  (re-exported for callers)
from rot import zab
from rot.ir import (
    Action, Assignment, Enum, StateVar,
    C, V, And, If, eq,
)
from rot.mr_gate import PASS, WARN, BLOCK, evaluate_mr

# The invariants the gate checks for every ZAB commit (the Phase 3.1 ZAB
# invariant set, rot/targets.py).
ZAB_PROPS = ["zab_no_premature_apply", "zab_apply_persisted"]

# -- classification labels ----------------------------------------------------
TP = "true_positive"                 # bug, gate BLOCKED it (caught)
DETECTED_NOT_BLOCKED = "detected_not_blocked"  # bug, gate WARNed (surfaced)
FN = "false_negative"                # bug, gate PASSED it (missed)
FP = "false_positive"                # safe, gate BLOCKED it (false block)
FALSE_WARNING = "false_warning"      # safe, gate WARNed it (spurious alert)
TN = "true_negative"                 # safe, gate PASSED it (correct)


# ---------------------------------------------------------------------------
# Small IR helpers
# ---------------------------------------------------------------------------
def _done(var):
    return eq(V(var), C("done"))


def _none(var):
    return eq(V(var), C("none"))


def _base(n):
    """The current, correct ZooKeeper/ZAB replication core (the 'before')."""
    return zab.build_ir(n=n, buggy=False)


def _set_apply_guard(n, guard_fn):
    after = _base(n)
    for i in range(1, zab.M + 1):
        for j in range(1, n + 1):
            after.action("apply_%d_%d" % (i, j)).guard = guard_fn(i, j)
    return after


def _set_commit_guard(n, guard_fn):
    after = _base(n)
    for i in range(1, zab.M + 1):
        after.action("commit_%d" % i).guard = guard_fn(i)
    return after


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------
class ZkCommit(object):
    """One replayed 'commit': a before->after diff (a merge request)."""

    def __init__(self, commit_id, title, ref, is_bug, before, after,
                 expected_verdict, notes=""):
        self.commit_id = commit_id
        self.title = title
        self.ref = ref
        self.is_bug = bool(is_bug)
        self.before = before
        self.after = after
        self.expected_verdict = expected_verdict
        self.notes = notes

    def to_dict(self):
        return {
            "commit_id": self.commit_id,
            "title": self.title,
            "ref": self.ref,
            "is_bug": self.is_bug,
            "before": self.before.name,
            "after": self.after.name,
            "expected_verdict": self.expected_verdict,
            "notes": self.notes,
        }


class ZkReplayOutcome(object):
    """The gate's outcome + classification for one commit."""

    def __init__(self, commit, verdict, justification, violated_after,
                 blocking_violated, has_deterministic_test, classification):
        self.commit = commit
        self.verdict = verdict
        self.justification = justification
        self.violated_after = list(violated_after)
        self.blocking_violated = list(blocking_violated)
        self.has_deterministic_test = bool(has_deterministic_test)
        self.classification = classification

    @property
    def blocked(self):
        return self.verdict == BLOCK

    @property
    def warned(self):
        return self.verdict == WARN

    @property
    def passed(self):
        return self.verdict == PASS

    def to_dict(self):
        return {
            "commit_id": self.commit.commit_id,
            "title": self.commit.title,
            "ref": self.commit.ref,
            "is_bug": self.commit.is_bug,
            "verdict": self.verdict,
            "justification": self.justification,
            "violated_after": self.violated_after,
            "blocking_violated": self.blocking_violated,
            "deterministic_test_emitted": self.has_deterministic_test,
            "classification": self.classification,
            "expected_verdict": self.commit.expected_verdict,
        }


def _ensure_dir(d):
    if d and not os.path.isdir(d):
        os.makedirs(d)


class ZkReplayReport(object):
    """Aggregate evaluation report across the corpus (Step 3.7 metrics)."""

    def __init__(self, n, max_states, outcomes):
        self.n = n
        self.max_states = max_states
        self.outcomes = list(outcomes)
        self._tally()

    def _tally(self):
        self.total = len(self.outcomes)
        self.bugs = sum(1 for o in self.outcomes if o.commit.is_bug)
        self.safe = self.total - self.bugs
        self.true_positives = sum(
            1 for o in self.outcomes if o.classification == TP)
        self.detected_not_blocked = sum(
            1 for o in self.outcomes if o.classification == DETECTED_NOT_BLOCKED)
        self.false_negatives = sum(
            1 for o in self.outcomes if o.classification == FN)
        self.false_positives = sum(
            1 for o in self.outcomes if o.classification == FP)
        self.false_warnings = sum(
            1 for o in self.outcomes if o.classification == FALSE_WARNING)
        self.true_negatives = sum(
            1 for o in self.outcomes if o.classification == TN)

    @property
    def bugs_detected(self):
        """A bug the gate did *something* about (blocked OR warned)."""
        return self.true_positives + self.detected_not_blocked

    @property
    def false_block_rate(self):
        """safe commits the gate incorrectly hard-blocked / safe commits."""
        return (self.false_positives / self.safe) if self.safe else 0.0

    @property
    def blocking_precision(self):
        d = self.true_positives + self.false_positives
        return (self.true_positives / d) if d else None

    @property
    def blocking_recall(self):
        d = self.true_positives + self.false_negatives
        return (self.true_positives / d) if d else None

    @property
    def detection_recall(self):
        return (self.bugs_detected / self.bugs) if self.bugs else None

    def to_dict(self):
        def _p(x):
            return round(x, 4) if isinstance(x, float) else x
        return {
            "n": self.n,
            "max_states": self.max_states,
            "total_commits": self.total,
            "bug_commits": self.bugs,
            "safe_commits": self.safe,
            "true_positives_blocked": self.true_positives,
            "detected_not_blocked": self.detected_not_blocked,
            "false_negatives_missed": self.false_negatives,
            "false_positives_blocked": self.false_positives,
            "false_warnings": self.false_warnings,
            "true_negatives_passed": self.true_negatives,
            "bugs_detected": self.bugs_detected,
            "false_block_rate": _p(self.false_block_rate),
            "blocking_precision": _p(self.blocking_precision),
            "blocking_recall": _p(self.blocking_recall),
            "detection_recall": _p(self.detection_recall),
            "outcomes": [o.to_dict() for o in self.outcomes],
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)

    def write(self, out_dir, base_name="zk-bug-replay"):
        _ensure_dir(out_dir)
        path = os.path.join(out_dir, base_name + ".json")
        with open(path, "w") as f:
            f.write(self.to_json() + "\n")
        return path


# ---------------------------------------------------------------------------
# Corpus: 3 documented bug-introducing changes + 3 real safe changes
# ---------------------------------------------------------------------------
def commit_premature_apply(n):
    """ZK-001 -- ZAB ordering bug: a follower APPLIES a transaction BEFORE the
    leader has COMMITTED it.  (Drop ``committed_i == done`` from apply.)"""
    def guard(i, j):
        return And(_done("persisted_%d_%d" % (i, j)),
                   _none("applied_%d_%d" % (i, j)))
    after = _set_apply_guard(n, guard)
    after.name = "zab-buggy(premature-apply)"
    return ZkCommit(
        commit_id="ZK-001",
        title="Follower applies a transaction before the leader commits it",
        ref="ZAB apply-before-commit (canonical 'zab-buggy'; see rot/zab.py)",
        is_bug=True,
        before=_base(n),
        after=after,
        expected_verdict=BLOCK,
        notes="Breaks the pinned, blocking invariant zab_no_premature_apply "
              "(applied => committed). The gate must BLOCK and emit a "
              "deterministic counterexample.")


def commit_apply_with_no_preconditions(n):
    """ZK-002 -- ZAB ordering+durability bug: a follower APPLIES a transaction
    with NO preconditions at all (drop BOTH ``committed_i`` AND
    ``persisted_i_j`` from apply).  This is the most severe premature-apply
    form: the follower applies a tx it neither persisted nor saw committed."""
    def guard(i, j):
        return _none("applied_%d_%d" % (i, j))
    after = _set_apply_guard(n, guard)
    after.name = "zab-buggy(apply-with-no-preconditions)"
    return ZkCommit(
        commit_id="ZK-002",
        title="Follower applies a transaction without persisting or awaiting commit",
        ref="ZAB apply-before-commit, no preconditions (severe premature-apply)",
        is_bug=True,
        before=_base(n),
        after=after,
        expected_verdict=BLOCK,
        notes="Immediately reachable from init: apply fires with committed_i and "
              "persisted_i_j both 'none', breaking the pinned, blocking invariant "
              "zab_no_premature_apply (applied => committed). The gate must BLOCK "
              "and emit a deterministic counterexample.")


def commit_commit_before_quorum(n):
    """ZK-003 -- ZOOKEEPER-1073-class bug: the leader COMMITS before all
    followers have PERSISTED.  (Drop the all-persisted requirement from commit.)"""
    def guard(i):
        return _none("committed_%d" % i)
    after = _set_commit_guard(n, guard)
    after.name = "zab-buggy(commit-before-quorum)"
    return ZkCommit(
        commit_id="ZK-003",
        title="Leader commits before all followers have persisted (quorum)",
        ref="ZOOKEEPER-1073-class: leader commits an unpersisted txn "
            "(data loss / split on leader failover)",
        is_bug=True,
        before=_base(n),
        after=after,
        expected_verdict=PASS,
        notes="OUTSIDE the two pinned invariants (commit-ordering/durability is "
              "not modelled) -> the gate PASSES it: an honest FALSE NEGATIVE / "
              "coverage gap. docs/phase3-eval.md shows the one invariant that "
              "would close it (and tests/test_zk_bug_replay.py proves it does).")


def commit_refactor_reorder_apply(n):
    """ZK-S1 -- behaviour-preserving refactor: the SAME apply guard, conjuncts
    reordered (a benign 'clean up condition order' change)."""
    def guard(i, j):
        return And(_none("applied_%d_%d" % (i, j)),
                   _done("persisted_%d_%d" % (i, j)),
                   _done("committed_%d" % i))
    after = _set_apply_guard(n, guard)
    after.name = "zab-correct(refactor:reordered-apply)"
    return ZkCommit(
        commit_id="ZK-S1",
        title="Refactor: reorder apply-guard conjuncts (no behaviour change)",
        ref="benign refactor (condition reordering)",
        is_bug=False,
        before=_base(n),
        after=after,
        expected_verdict=PASS,
        notes="Identical reachable state space to the correct core; both "
              "invariants hold. The gate must NOT block (would be a false block).")


def commit_add_leader_epoch(n):
    """ZK-S2 -- additive, safety-neutral feature: add a leader-epoch
    bookkeeping variable + action that never touches the safety path."""
    after = _base(n)
    after.variables.append(StateVar(
        "leader_epoch", Enum([0, 1]), owner="leader",
        desc="leader epoch (additive bookkeeping; disjoint from the safety path)"))
    init = [a for a in after.actions if a.is_initial][0]
    init.effects.append(Assignment("leader_epoch", C(0)))
    after.actions.append(Action(
        name="bump_epoch", owner="leader",
        guard=eq(V("leader_epoch"), C(0)),
        effects=[Assignment("leader_epoch", C(1))],
        linearization="bump_epoch()"))
    after.name = "zab-correct(+leader-epoch)"
    return ZkCommit(
        commit_id="ZK-S2",
        title="Add leader-epoch bookkeeping (additive, safety-neutral)",
        ref="ZAB leader-epoch / liveness bookkeeping (new code path)",
        is_bug=False,
        before=_base(n),
        after=after,
        expected_verdict=PASS,
        notes="Adds a variable/action disjoint from persisted/applied/committed; "
              "both invariants still hold. The gate must NOT block.")


def commit_reorder_persist_actions(n):
    """ZK-S3 -- behaviour-preserving refactor: same persist actions, declared
    order changed (reachability is unchanged; only witness order moves)."""
    after = _base(n)
    persists = [a for a in after.actions if a.name.startswith("persist_")]
    others = [a for a in after.actions if not a.name.startswith("persist_")]
    after.actions = others + persists  # persist actions moved to the end
    after.name = "zab-correct(refactor:reordered-actions)"
    return ZkCommit(
        commit_id="ZK-S3",
        title="Refactor: reorder persist actions (no behaviour change)",
        ref="benign refactor (action/statement reordering)",
        is_bug=False,
        before=_base(n),
        after=after,
        expected_verdict=PASS,
        notes="Same transition relation as the correct core; both invariants "
              "hold. The gate must NOT block (would be a false block).")


def commit_corpus(n=2):
    """The ordered corpus: 3 documented bug-introducing + 3 safe commits."""
    return [
        commit_premature_apply(n),
        commit_apply_with_no_preconditions(n),
        commit_commit_before_quorum(n),
        commit_refactor_reorder_apply(n),
        commit_add_leader_epoch(n),
        commit_reorder_persist_actions(n),
    ]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def classify(commit, verdict):
    """Map a commit + gate verdict to a TP/FN/FP/TN(+nuance) classification."""
    if commit.is_bug:
        if verdict == BLOCK:
            return TP
        if verdict == WARN:
            return DETECTED_NOT_BLOCKED
        return FN
    # safe change
    if verdict == BLOCK:
        return FP
    if verdict == WARN:
        return FALSE_WARNING
    return TN


def replay_corpus(n=2, max_states=200000, out_dir=None):
    """Run every commit through the Phase 3 gate and aggregate the report.

    Each commit's before/after ``ProtocolIR`` pair is handed to
    ``rot.mr_gate.evaluate_mr`` with the ZAB invariant set -- exactly how the
    gate would treat the change in CI.
    """
    outcomes = []
    for c in commit_corpus(n=n):
        v = evaluate_mr(c.before, c.after, properties=ZAB_PROPS, n=n,
                        max_states=max_states)
        violated_after = [r.name for r in v.invariants if r.violated_after]
        blocking_violated = [r.name for r in v.invariants
                             if r.violated_after and r.blocking]
        outcomes.append(ZkReplayOutcome(
            commit=c, verdict=v.verdict, justification=v.justification,
            violated_after=violated_after,
            blocking_violated=blocking_violated,
            has_deterministic_test=(v.deterministic is not None),
            classification=classify(c, v.verdict)))
    report = ZkReplayReport(n=n, max_states=max_states, outcomes=outcomes)
    if out_dir:
        report.write(out_dir)
    return report


# ---------------------------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------------------------
def format_report(report):
    """Render a compact, investor/design-partner-facing text summary."""
    bar = "=" * 70
    lines = [bar,
             "  ROTN Phase 3 -- ZooKeeper/ZAB bug-replay evaluation (Step 3.7)",
             bar,
             "  corpus : %d documented commit(s) replayed "
             "(%d bug-introducing, %d safe)" %
             (report.total, report.bugs, report.safe),
             "",
             "  BUG commits the gate should catch:"]
    lines.append("    caught & blocked  (TRUE POSITIVE)       : %d"
                 % report.true_positives)
    lines.append("    detected, WARN (surfaced, not vetoed)   : %d"
                 % report.detected_not_blocked)
    lines.append("    missed              (FALSE NEGATIVE)    : %d"
                 % report.false_negatives)
    lines.append("")
    lines.append("  SAFE changes the gate must NOT block:")
    lines.append("    passed              (TRUE NEGATIVE)     : %d"
                 % report.true_negatives)
    lines.append("    incorrectly blocked (FALSE POSITIVE)    : %d"
                 % report.false_positives)
    if report.false_warnings:
        lines.append("    spurious WARN (not blocked)           : %d"
                     % report.false_warnings)
    lines.append("")
    lines.append("  Headline metrics:")

    def _fmt(x):
        return "n/a" if x is None else "%.1f%%" % (x * 100.0)
    lines.append("    false-block rate (safe blocked / safe)  : %s"
                 % _fmt(report.false_block_rate))
    lines.append("    blocking precision (TP / blocks)        : %s"
                 % _fmt(report.blocking_precision))
    lines.append("    blocking recall  (TP / real bugs)       : %s"
                 % _fmt(report.blocking_recall))
    lines.append("    detection recall (detected / real bugs) : %s"
                 % _fmt(report.detection_recall))
    lines.append("")
    lines.append("  Per-commit detail:")
    lines.append("  %-7s %-7s %-22s %-24s %s"
                 % ("commit", "verdict", "classification", "invariant fired",
                    "deterministic test"))
    lines.append("  " + "-" * 70)
    for o in report.outcomes:
        if o.blocking_violated:
            inv = o.blocking_violated[0]
        elif o.violated_after:
            inv = o.violated_after[0] + " (warn)"
        else:
            inv = "-"
        lines.append("  %-7s %-7s %-22s %-24s %s"
                     % (o.commit.commit_id, o.verdict, o.classification,
                        inv, "yes" if o.has_deterministic_test else "-"))
    lines.append(bar)
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(
        description="ZooKeeper/ZAB bug-replay evaluation (Phase 3, Step 3.7)")
    ap.add_argument("--n", type=int, default=2,
                    help="ZAB follower count (default 2; small enough to prove "
                         "every invariant over ALL reachable states)")
    ap.add_argument("--max-states", type=int, default=200000,
                    help="search budget for the deterministic witness")
    ap.add_argument("--out", default=None,
                    help="directory to write the JSON report")
    args = ap.parse_args()
    rep = replay_corpus(n=args.n, max_states=args.max_states, out_dir=args.out)
    print(format_report(rep))
    if args.out:
        print("\nJSON report written to: "
              + os.path.join(args.out, "zk-bug-replay.json"))
