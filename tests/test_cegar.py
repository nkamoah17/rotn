# -*- coding: utf-8 -*-
"""Unit tests for ``rot.cegar``: EngineResult -> Verdict mapping.

Covers the four engine outcomes plus the refinement (recheck) hook:
  * proven  -> Verdict.proven
  * violated + concrete witness -> Verdict.violated
  * violated + infeasible witness -> Verdict.unsound (spurious)
  * unknown / timeout -> Verdict.unknown
  * unknown + recheck that converges -> refined verdict (bounded by cegar_max_iter)
  * error -> Verdict.error

Pure stdlib, Python 3.6 compatible (no f-strings, no capture_output).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot import cegar
from rot.config import Config
from rot.invariants import get as get_inv
from rot.symbolic import EngineResult


def _cfg(max_iter=3):
    return Config(cegar_max_iter=max_iter, max_states=1000)


class CegarMappingTests(unittest.TestCase):
    """Direct EngineResult -> Verdict mapping (no refinement hook)."""

    def test_proven_maps_to_verdict_proven(self):
        prop = get_inv("agreement", 3)
        res = EngineResult(status="proven", n_states=99, note="holds everywhere")
        v = cegar.cegar(res, prop, _cfg(), "symbolic")
        self.assertEqual(v.status, "proven")
        self.assertEqual(v.engine, "symbolic")
        self.assertTrue(v.is_proven())

    def test_violated_feasible_witness_maps_to_violated(self):
        prop = get_inv("agreement", 3)
        # applied_1=commit, applied_3=abort: both decided, different -> clause
        # (1,3) is False, so agreement is False here: a genuine counterexample.
        witness = {"phase": "decided", "decision": "abort",
                   "applied_1": "commit", "applied_2": "none", "applied_3": "abort"}
        res = EngineResult(status="violated", witness=witness, n_states=40)
        v = cegar.cegar(res, prop, _cfg(), "symbolic")
        self.assertEqual(v.status, "violated")
        self.assertTrue(v.is_violated())
        self.assertEqual(v.counterexample, witness)

    def test_violated_infeasible_witness_maps_to_unsound(self):
        prop = get_inv("agreement", 3)
        # All applied = none -> agreement is TRUE here, so a "violated" result
        # pointing at this state is a spurious over-approximation artefact.
        witness = {"applied_1": "none", "applied_2": "none", "applied_3": "none"}
        res = EngineResult(status="violated", witness=witness, n_states=10)
        v = cegar.cegar(res, prop, _cfg(), "symbolic")
        self.assertEqual(v.status, "unsound")

    def test_violated_without_witness_still_violated(self):
        prop = get_inv("agreement", 3)
        res = EngineResult(status="violated", witness=None, n_states=5)
        v = cegar.cegar(res, prop, _cfg(), "tlc")
        self.assertEqual(v.status, "violated")
        self.assertFalse(v.counterexample)

    def test_unknown_without_recheck_maps_to_unknown(self):
        prop = get_inv("agreement", 3)
        res = EngineResult(status="unknown", note="state space exhausted")
        v = cegar.cegar(res, prop, _cfg(), "symbolic")
        self.assertEqual(v.status, "unknown")
        self.assertEqual(v.cegar_iterations, 0)

    def test_timeout_maps_to_unknown(self):
        prop = get_inv("agreement", 3)
        res = EngineResult(status="timeout", note="timed out")
        v = cegar.cegar(res, prop, _cfg(), "tlc")
        self.assertEqual(v.status, "unknown")

    def test_error_maps_to_verdict_error(self):
        prop = get_inv("agreement", 3)
        res = EngineResult(status="error", note="java not found")
        v = cegar.cegar(res, prop, _cfg(), "tlc")
        self.assertEqual(v.status, "error")
        self.assertIn("java not found", v.note)


class CegarRefinementTests(unittest.TestCase):
    """The recheck hook: bounded refinement on unknown, respecting cegar_max_iter."""

    def _prop(self):
        return get_inv("agreement", 3)

    def test_unknown_with_recheck_converging_to_proven(self):
        prop = self._prop()
        first = EngineResult(status="unknown", note="first pass undecidable")

        def recheck(model, p, max_states):
            return EngineResult(status="proven", n_states=50)

        v = cegar.cegar(first, prop, _cfg(max_iter=3), "symbolic",
                        model=object(), recheck=recheck)
        self.assertEqual(v.status, "proven")
        self.assertEqual(v.cegar_iterations, 1)

    def test_unknown_with_recheck_converging_to_violated(self):
        prop = self._prop()
        first = EngineResult(status="unknown", note="first pass undecidable")
        witness = {"applied_1": "commit", "applied_2": "none", "applied_3": "abort"}

        def recheck(model, p, max_states):
            return EngineResult(status="violated", witness=witness)

        v = cegar.cegar(first, prop, _cfg(max_iter=3), "symbolic",
                        model=object(), recheck=recheck)
        self.assertEqual(v.status, "violated")
        self.assertEqual(v.counterexample, witness)

    def test_unknown_with_recheck_bounded_by_max_iter(self):
        prop = self._prop()
        first = EngineResult(status="unknown", note="stuck")
        calls = {"n": 0}

        def recheck(model, p, max_states):
            calls["n"] += 1
            return EngineResult(status="unknown", note="still stuck")

        v = cegar.cegar(first, prop, _cfg(max_iter=3), "symbolic",
                        model=object(), recheck=recheck)
        self.assertEqual(v.status, "unknown")
        self.assertEqual(calls["n"], 3)  # bounded by cegar_max_iter
        self.assertEqual(v.cegar_iterations, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)