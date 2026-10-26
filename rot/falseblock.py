# -*- coding: utf-8 -*-
"""falseblock.py -- measure the false-block rate of the MR gate (Phase 3.6).

The MR gate (:mod:`rot.mr_gate`) blocks merge requests that violate a pinned
blocking-eligible invariant.  A *false block* is the cost of that conservatism
applied to a change that was actually safe: the gate says BLOCK for a diff that
should have passed.

This module measures that cost over a *corpus of safe diffs*.  Each corpus
entry is a ``(before, after)`` pair (two registered target names, or two
``rot.ir.ProtocolIR``s) representing a change that is *known to be safe*.  We
run the gate on every entry and count:

    * ``blocked`` -- the gate returned BLOCK (a false block, since the diff is safe);
    * ``passed``  -- the gate returned PASS (correctly accepted);
    * ``warned``  -- the gate returned WARN (accepted with a warning).

and compute

    false_block_rate = blocked / total        (0.0 for an empty corpus).

If the rate exceeds a ``threshold``, the report recommends restricting the gate
to fewer pinned properties (i.e. unpinning non-critical invariants) so the gate
blocks less often -- trading some safety coverage for fewer false blocks.

Pure stdlib, Python 3.6 compatible.
"""

import os
import json

from rot import mr_gate


class DiffOutcome(object):
    """The gate's outcome on a single (safe) diff in the corpus."""

    def __init__(self, before, after, verdict, blocked, passed,
                 justification, blocked_invariants):
        self.before = before
        self.after = after
        self.verdict = verdict
        self.blocked = bool(blocked)
        self.passed = bool(passed)
        self.justification = justification
        self.blocked_invariants = list(blocked_invariants or [])

    def to_dict(self):
        return {
            "before": self.before,
            "after": self.after,
            "verdict": self.verdict,
            "blocked": self.blocked,
            "passed": self.passed,
            "justification": self.justification,
            "blocked_invariants": list(self.blocked_invariants),
        }


class FalseBlockReport(object):
    """Aggregate false-block measurement over a safe-diff corpus."""

    def __init__(self, corpus_size, blocked, passed, warned,
                 false_block_rate, threshold, exceeded, recommendation, outcomes):
        self.corpus_size = corpus_size
        self.blocked = blocked
        self.passed = passed
        self.warned = warned
        self.false_block_rate = false_block_rate
        self.threshold = threshold
        self.exceeded = bool(exceeded)
        self.recommendation = recommendation
        self.outcomes = list(outcomes or [])

    def to_dict(self):
        return {
            "corpus_size": self.corpus_size,
            "blocked": self.blocked,
            "passed": self.passed,
            "warned": self.warned,
            "false_block_rate": self.false_block_rate,
            "threshold": self.threshold,
            "exceeded": self.exceeded,
            "recommendation": self.recommendation,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)

    def write(self, out_dir, base_name="falseblock-report"):
        """Serialise the report to ``<out_dir>/<base_name>.json``; return the path."""
        path = os.path.join(out_dir, base_name + ".json")
        with open(path, "w") as f:
            f.write(self.to_json() + "\n")
        return path


def measure_false_blocks(corpus, threshold=0.10, n=2, max_states=200000):
    """Measure the false-block rate of the MR gate over a corpus of safe diffs.

    Parameters
    ----------
    corpus :
        An iterable of safe diffs.  Each entry is a ``(before, after)`` pair,
        where each side is a registered target name (str) or a
        ``rot.ir.ProtocolIR``.  A safe diff is one that should be accepted by
        the gate (it preserves the pinned blocking-eligible invariants).
    threshold : float
        A ``false_block_rate`` strictly greater than this triggers the
        "restrict the gate to fewer pinned properties" recommendation.
    n : int
        Node/participant count for building IRs from names.
    max_states : int
        Search budget passed to the gate's invariant checks.

    Returns
    -------
    FalseBlockReport
        With ``blocked`` / ``passed`` / ``warned`` counts, the
        ``false_block_rate = blocked / total`` (0.0 for an empty corpus), and a
        recommendation if the rate exceeds ``threshold``.
    """
    outcomes = []
    blocked = passed = warned = 0
    for entry in corpus:
        before, after = entry
        v = mr_gate.evaluate_mr(before, after, n=n, max_states=max_states)
        blocked_invariants = sorted(
            r.name for r in v.invariants
            if r.violated_after and r.blocking)
        o = DiffOutcome(
            before=(before if isinstance(before, str) else before.name),
            after=(after if isinstance(after, str) else after.name),
            verdict=v.verdict,
            blocked=(v.verdict == mr_gate.BLOCK),
            passed=(v.verdict == mr_gate.PASS),
            justification=v.justification,
            blocked_invariants=blocked_invariants,
        )
        outcomes.append(o)
        if o.blocked:
            blocked += 1
        elif o.passed:
            passed += 1
        else:
            warned += 1

    total = len(outcomes)
    rate = (float(blocked) / float(total)) if total > 0 else 0.0
    exceeded = (rate > threshold)
    if exceeded:
        recommendation = (
            "false_block_rate %.3f exceeds threshold %.3f: restrict the gate "
            "to fewer pinned properties (unpin non-critical invariants) to "
            "reduce false blocks" % (rate, threshold))
    else:
        recommendation = (
            "false_block_rate %.3f is within threshold %.3f: the gate's "
            "pinned-property set is acceptable" % (rate, threshold))

    return FalseBlockReport(
        corpus_size=total,
        blocked=blocked,
        passed=passed,
        warned=warned,
        false_block_rate=rate,
        threshold=threshold,
        exceeded=exceeded,
        recommendation=recommendation,
        outcomes=outcomes,
    )


__all__ = ["DiffOutcome", "FalseBlockReport", "measure_false_blocks"]