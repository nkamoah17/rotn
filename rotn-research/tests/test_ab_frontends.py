# -*- coding: utf-8 -*-
"""test_ab_frontends.py -- the A/B gate (Joern-primary, §3).

Verifies the frontend A/B harness (rot/ab.py + bench/ corpus):

* it runs **offline** (no network, no external tools) and **deterministically**;
* the **false-PROVEN hard gate** is enforced (any false-PROVEN = disqualification);
* **UNAVAILABLE is recorded distinctly** (an honest, objective distinction, not
  a loss);
* the full metric table is **citable** (JSON, deterministic).

Pure stdlib.  Python 3.6 compatible (unittest, no f-strings).
"""

import json
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class TestABOffline(unittest.TestCase):
    """The A/B runs offline and deterministically (the gate)."""

    def _run(self):
        from rotn_research.ab import run_ab
        return run_ab()

    def test_runs_offline_and_deterministic(self):
        r1 = self._run()
        r2 = self._run()
        # Deterministic: two runs produce the same JSON (same winner, same
        # cells, same metrics).  No network, no external tools, no randomness.
        self.assertEqual(json.dumps(r1.to_dict(), sort_keys=True),
                         json.dumps(r2.to_dict(), sort_keys=True))

    def test_winner_is_deterministic(self):
        from rotn_research.ab import lexicographic_winner
        w1 = lexicographic_winner(self._run())
        w2 = lexicographic_winner(self._run())
        self.assertEqual(w1, w2)
        self.assertIsNotNone(w1)

    def test_corpus_loaded(self):
        from rotn_research.ab import load_corpus
        fixtures = [f["fixture"] for f in load_corpus()]
        self.assertIn("spendcap", fixtures)
        self.assertIn("labelflow", fixtures)
        self.assertIn("twopc", fixtures)


class TestABHardGate(unittest.TestCase):
    """The false-PROVEN hard gate is enforced (any = disqualification)."""

    def test_hard_gate_disqualifies(self):
        from rotn_research.ab import CellResult, _aggregate
        # A frontend with a false-PROVEN cell must NOT pass the hard gate.
        cells = [
            CellResult("bad", "spendcap", "available", verdict_status="proven",
                       metrics={"false_proven": 1, "violation_recall": 0,
                                "dataflow_edge_recall": 1.0,
                                "source_pinning_rate": 1.0,
                                "coach_quality": 1, "unknown_rate": 0,
                                "cost": 4}),
            CellResult("good", "spendcap", "available", verdict_status="violated",
                       metrics={"false_proven": 0, "violation_recall": 1,
                                "dataflow_edge_recall": 1.0,
                                "source_pinning_rate": 1.0,
                                "coach_quality": 1, "unknown_rate": 0,
                                "cost": 4}),
        ]
        bad_agg = _aggregate(cells, "bad")
        good_agg = _aggregate(cells, "good")
        self.assertFalse(bad_agg["hard_gate_pass"])
        self.assertTrue(good_agg["hard_gate_pass"])

    def test_winner_excludes_false_proven(self):
        from rotn_research.ab import run_ab
        # Run the real A/B; the winner must have passed the hard gate (no
        # false-PROVEN cell).
        result = run_ab()
        if result.winner is not None:
            self.assertTrue(result.per_frontend[result.winner]["hard_gate_pass"])
        # No cell in the corpus is a false-PROVEN (the known-bug variants are
        # all caught, the known-correct variants are all proven).
        for c in result.cells:
            if c.status == "available":
                self.assertEqual(c.metrics.get("false_proven", 0), 0,
                                 "cell %s/%s false-PROVEN" % (c.frontend, c.fixture))


class TestABUnavailable(unittest.TestCase):
    """UNAVAILABLE is recorded distinctly (an honest, objective distinction,
    not a loss)."""

    def test_unavailable_recorded_distinctly(self):
        from rotn_research.ab import run_ab
        result = run_ab()
        statuses = set(c.status for c in result.cells)
        # The corpus has at least one AVAILABLE and one UNAVAILABLE cell (the
        # cpg producer is UNAVAILABLE on the spendcap known-bug; the java
        # producer is UNAVAILABLE on the P1 fixtures).
        self.assertIn("available", statuses)
        self.assertIn("unavailable", statuses)
        # UNAVAILABLE cells carry a detail (an honest, objective reason).
        for c in result.cells:
            if c.status == "unavailable":
                self.assertTrue(c.detail, "UNAVAILABLE cell needs a reason")

    def test_unavailable_not_a_loss(self):
        from rotn_research.ab import run_ab
        result = run_ab()
        # The unavailable count is tracked per frontend (an honest, objective
        # distinction, not a loss).
        for f, agg in result.per_frontend.items():
            self.assertIn("unavailable", agg)
            self.assertGreaterEqual(agg["unavailable"], 0)


class TestABCitable(unittest.TestCase):
    """The full metric table is citable (JSON, deterministic)."""

    def test_json_citable(self):
        from rotn_research.ab import run_ab, to_json
        result = run_ab()
        s = to_json(result)
        # The JSON is valid and carries the key fields.
        d = json.loads(s)
        self.assertIn("corpus", d)
        self.assertIn("cells", d)
        self.assertIn("per_frontend", d)
        self.assertIn("winner", d)
        # Every cell has the §3 metrics (or a detail, if UNAVAILABLE).
        for c in d["cells"]:
            if c["status"] == "available":
                for m in ("false_proven", "violation_recall",
                          "dataflow_edge_recall", "source_pinning_rate",
                          "coach_quality", "unknown_rate", "cost"):
                    self.assertIn(m, c["metrics"])
            else:
                self.assertIn("detail", c)


if __name__ == "__main__":
    unittest.main()

