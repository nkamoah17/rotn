# -*- coding: utf-8 -*-
"""Unit tests for ``rot.cegar.cegar_liveness``: ReachResult -> Verdict mapping.

Liveness invariants (``kind="liveness"``, e.g. ``bounded_eventually``) are the
mirror image of the safety path: the engine searches for the GOAL within a
bounded horizon (``SymbolicEngine.reach_within``) and the mapping is

  * REACHED     -> Verdict.proven   (goal reachable within the bound: holds)
  * NOT_REACHED -> Verdict.violated (goal unreachable within the bound: fails)
  * UNKNOWN     -> Verdict.unknown  (the state budget cut the search short)

The verdict stays relative to its bound (``cfg.liveness_horizon``) and never
claims unconditional liveness.

Pure stdlib, Python 3.6 compatible (no f-strings, no capture_output).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot import cegar
from rot.config import Config
from rot.invariants import get as get_inv, KIND_LIVENESS
from rot.symbolic import (ReachResult, REACHED, NOT_REACHED, UNKNOWN)

HORIZON = 12


def _cfg(max_states=1000):
    return Config(liveness_horizon=HORIZON, max_states=max_states)


def _prop():
    return get_inv("bounded_eventually", 1)


class LivenessMappingTests(unittest.TestCase):
    """Direct ReachResult -> Verdict mapping (no engine, pure function)."""

    def test_prop_is_liveness(self):
        prop = _prop()
        self.assertEqual(prop.kind, KIND_LIVENESS)
        self.assertEqual(prop.label, "bounded_eventually")

    def test_reached_maps_to_verdict_proven(self):
        path = [{"decision": "idle"}, {"decision": "read_log"}]
        res = ReachResult(REACHED, HORIZON, depth=1, path=path,
                          witness={"decision": "read_log"}, n_states=10,
                          budget_complete=True, horizon_complete=True)
        v = cegar.cegar_liveness(res, _prop(), _cfg(), "symbolic")
        self.assertEqual(v.status, "proven")
        self.assertTrue(v.is_proven())
        self.assertEqual(v.engine, "symbolic")
        self.assertEqual(v.n_states, 10)
        # the concrete reachability witness is preserved as evidence
        self.assertEqual(v.evidence["path"], path)
        self.assertEqual(v.evidence["horizon"], HORIZON)

    def test_not_reached_maps_to_verdict_violated(self):
        res = ReachResult(NOT_REACHED, HORIZON, n_states=10,
                          budget_complete=True, horizon_complete=True)
        v = cegar.cegar_liveness(res, _prop(), _cfg(), "symbolic")
        self.assertEqual(v.status, "violated")
        self.assertTrue(v.is_violated())
        # NOT_REACHED is only sound when the whole horizon was explored
        self.assertTrue(res.horizon_complete)

    def test_unknown_maps_to_verdict_unknown(self):
        res = ReachResult(UNKNOWN, HORIZON, n_states=10,
                          budget_complete=False, horizon_complete=False)
        v = cegar.cegar_liveness(res, _prop(), _cfg(), "symbolic")
        self.assertEqual(v.status, "unknown")
        # an undecidable bounded search is explicitly NOT a proof of
        # non-reachability -- the note must say so.
        self.assertIn("NOT a proof", v.note)
        self.assertIn("budget", v.note.lower())


class LivenessEngineIntegrationTests(unittest.TestCase):
    """cegar_liveness consumes a real SymbolicEngine.reach_within result."""

    def _linear_model(self):
        from rot import targets
        from rot.linearization import linearize
        prop = _prop()
        # The agent-step model is already minimal (single `decision` variable),
        # so property-directed abstraction is a no-op; linearize the IR directly.
        return linearize(targets.build("agent-step")), prop

    def test_correct_agent_step_reaches_goal(self):
        from rot.symbolic import SymbolicEngine
        model, prop = self._linear_model()
        cfg = _cfg()
        res = (SymbolicEngine(model, max_states=cfg.max_states)
               .reach_within(prop.expression, cfg.liveness_horizon,
                             max_states=cfg.max_states))
        # The conforming agent reaches decision != idle at step 1
        # (e.g. read_log), so the bounded liveness property holds.
        self.assertEqual(res.status, REACHED)
        self.assertTrue(res.path)
        v = cegar.cegar_liveness(res, prop, cfg, "symbolic")
        self.assertEqual(v.status, "proven")

    def test_engine_result_maps_consistently(self):
        from rot.symbolic import SymbolicEngine
        model, prop = self._linear_model()
        cfg = _cfg()
        res = (SymbolicEngine(model, max_states=cfg.max_states)
               .reach_within(prop.expression, cfg.liveness_horizon,
                             max_states=cfg.max_states))
        expected = {REACHED: "proven", NOT_REACHED: "violated", UNKNOWN: "unknown"}
        v = cegar.cegar_liveness(res, prop, cfg, "symbolic")
        self.assertEqual(v.status, expected[res.status])


if __name__ == "__main__":
    unittest.main(verbosity=2)
