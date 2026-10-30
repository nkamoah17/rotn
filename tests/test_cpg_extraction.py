# -*- coding: utf-8 -*-
"""CPG-2 gate: the two code-grounded producers agree on the same control.

This is the A/B gate for the **generic CPG -> Candidate producer**
(``rot.frontends.cpg``): for the *same* P1 control, the CPG producer
(reading a ``CpgModel`` scrape -- structure, not source text) and the
Python-source producer (``rot.frontends.code`` -- name heuristics) must
lower to a ``to_dict()``-identical ``ProtocolIR`` (provenance excluded --
it is necessarily language-specific).  Both then flow through the same
Verify gate: PROVEN / VIOLATED + exact witness / OUT_OF_SCOPE -- never a
silent UNKNOWN.

The CPG side is exercised on:
  * the committed fixture ``tests/fixtures/cpg/connector.cpg.json`` --
    budget ENFORCED (canSpend charges settled + inflight + amount against
    the cap) and label_flow BYPASSABLE (report() sends the private
    parameter to the egress sink unguarded);
  * hand-built in-memory models covering the other two quadrants --
    budget BYPASSABLE (a settled-only sum) and label_flow ENFORCED (a
    mutable boolean gate), under names the fixture does not use, so the
    gate proves recognition is structural, not fixture-memorized.

Run: python -m pytest tests/test_cpg_extraction.py -v
"""

import glob
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_ROOT, _TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from rot.config import Config
from rot.cegar import verify_candidate
from rot.frontends.code import (extract_file, PATTERN_BUDGET,
                                PATTERN_LABEL_FLOW)
from rot.frontends.cpg import extract_cpg
from rot.frontends.cpg_model import (CpgEdge, CpgField, CpgMethod, CpgModel,
                                     CpgTaintNode, CpgType, EDGE_ARGUMENT,
                                     EDGE_CALL, EDGE_REACHING_DEF)
from rot.lower import lower_candidate
from rot.verdicts import Verdict
from test_narrow_waist import scan_source

FIX_CPG = os.path.join(_ROOT, "tests", "fixtures", "cpg",
                       "connector.cpg.json")
FIX_PY = os.path.join(_ROOT, "tests", "fixtures", "code")
CFG = Config(max_states=100000)


def _cpg_model():
    """The committed CPG fixture (a Joern/Java scrape of connector.java)."""
    return CpgModel.from_file(FIX_CPG)


def _py(name):
    return os.path.join(FIX_PY, name + ".py")


def _bypassable_budget_model():
    """A settled-only spend decision under different names (``used`` /
    ``total``) -- recognition must be structural, not fixture-memorized."""
    O = "b.Service"
    m = CpgModel(
        meta={"source": "b/Service.java"},
        types=[CpgType("Service", O, owner="b")],
        fields=[CpgField("used", O + ".used", type_name="int", owner=O),
                CpgField("cap", O + ".cap", type_name="int", owner=O)],
        methods=[CpgMethod("can_spend", O + ".can_spend", owner=O,
                           line=5, end_line=7, calls=[],
                           read_fields=["used", "cap"], written_fields=[],
                           defs=["amount", "total"], args=["amount"],
                           ret_type="boolean")],
        edges=[CpgEdge(EDGE_REACHING_DEF, O + ".used", O + ".can_spend#total",
                       line=6),
               CpgEdge(EDGE_REACHING_DEF, O + ".can_spend#amount",
                       O + ".can_spend#total", line=6)],
        taint_sources=[CpgTaintNode(O + ".can_spend#amount", "parameter",
                                    "amount", O + ".can_spend", "parameter",
                                    5)],
        taint_sinks=[],
    )
    assert not m.validate()
    return m



def _guarded_label_flow_model():
    """An egress guarded by a mutable boolean gate (written by another
    method) -- the ENFORCED label/flow quadrant, under new names."""
    O = "g.Guarded"
    OUT = "g.Out"
    m = CpgModel(
        meta={"source": "g/Guarded.java"},
        types=[CpgType("Guarded", O, owner="g"),
               CpgType("Out", OUT, owner="g")],
        fields=[CpgField("holdingPrivate", O + ".holdingPrivate",
                         type_name="boolean", owner=O),
                CpgField("channel", O + ".channel", type_name=OUT, owner=O)],
        methods=[
            CpgMethod("mark", O + ".mark", owner=O, line=3, end_line=4,
                      calls=[], read_fields=[],
                      written_fields=["holdingPrivate"],
                      defs=["holdingPrivate"], args=[], ret_type="void"),
            CpgMethod("report", O + ".report", owner=O, line=7, end_line=9,
                      calls=["send"], read_fields=["holdingPrivate", "channel"],
                      written_fields=[], defs=["data", "payload"],
                      args=["data"], ret_type="void"),
            CpgMethod("send", OUT + ".send", owner=OUT, line=12, end_line=12,
                      calls=[], read_fields=[], written_fields=[],
                      defs=["payload"], args=["payload"], ret_type="void"),
        ],
        edges=[CpgEdge(EDGE_REACHING_DEF, O + ".report#data",
                       O + ".report#payload", line=8),
               CpgEdge(EDGE_ARGUMENT, O + ".report#payload",
                       OUT + ".send#payload", line=9),
               CpgEdge(EDGE_CALL, O + ".report", OUT + ".send", line=9)],
        taint_sources=[CpgTaintNode(O + ".report#data", "parameter", "data",
                                    O + ".report", "private-name:data", 7)],
        taint_sinks=[CpgTaintNode(OUT + ".send", "call", "send", O + ".report",
                                  "egress-name:send", 9)],
    )
    assert not m.validate()
    return m


def _no_control_model():
    """A plain logging helper: no P1 control (E2 -> OUT_OF_SCOPE)."""
    O = "n.Logger"
    m = CpgModel(
        meta={"source": "n/Logger.java"},
        types=[CpgType("Logger", O, owner="n")],
        fields=[CpgField("sink", O + ".sink",
                         type_name="java.io.PrintStream", owner=O)],
        methods=[CpgMethod("log", O + ".log", owner=O, line=3, end_line=4,
                           calls=[], read_fields=["sink"], written_fields=[],
                           defs=["msg"], args=["msg"], ret_type="void")],
        edges=[], taint_sources=[], taint_sinks=[],
    )
    assert not m.validate()
    return m


def _lowered(candidate):
    """``lower_candidate`` with the per-instance provenance stripped -- the
    A/B comparison is over the *control* (state / actions / guards /
    params), not the provenance, which is necessarily language-specific
    (Java method fullNames vs. a Python filename)."""
    ir_model = lower_candidate(candidate)
    ir_model.metadata.pop("provenance", None)
    return ir_model


class CpgExtractionTest(unittest.TestCase):
    """extract_cpg recognizes the P1 shapes from CPG structure (E1) and
    reports out-of-pattern input as OUT_OF_SCOPE (E2), never UNKNOWN."""

    def test_budget_enforced_from_structure(self):
        c = extract_cpg(_cpg_model(), shape=PATTERN_BUDGET)
        self.assertFalse(c.out_of_scope)
        self.assertEqual(c.pattern, PATTERN_BUDGET)
        self.assertTrue(c.enforced, "in-flight in the sum => enforced")
        self.assertEqual(c.params, {"amount": 100, "cap": 200})
        self.assertTrue(c.candidate, "E1: a candidate, not intent")
        self.assertEqual(c.provenance["function"], "canSpend")
        self.assertEqual(c.provenance["cap"], "cap")
        self.assertEqual(c.provenance["sum_over"], ["inflight", "settled"])
        self.assertIsNotNone(c.pinned_property)
        self.assertIn("cone", c.provenance, "E4: the property-directed slice")

    def test_label_flow_bypassable_from_structure(self):
        c = extract_cpg(_cpg_model(), shape=PATTERN_LABEL_FLOW)
        self.assertFalse(c.out_of_scope)
        self.assertEqual(c.pattern, PATTERN_LABEL_FLOW)
        self.assertFalse(c.enforced, "unguarded egress => bypassable")
        self.assertEqual(c.params, {"label": "holding_private"})
        self.assertEqual(c.provenance["function"], "report")
        self.assertIsNone(c.provenance["guard"])
        self.assertTrue(c.provenance["taint_path"],
                        "the private -> sink path is in the provenance")
        self.assertIsNotNone(c.pinned_property)

    def test_budget_bypassable_from_structure(self):
        c = extract_cpg(_bypassable_budget_model(), shape=PATTERN_BUDGET)
        self.assertFalse(c.out_of_scope)
        self.assertEqual(c.pattern, PATTERN_BUDGET)
        self.assertFalse(c.enforced, "settled-only sum => bypassable")
        self.assertEqual(c.params, {"amount": 100, "cap": 200})
        self.assertEqual(c.provenance["sum_over"], ["used"])

    def test_label_flow_enforced_from_structure(self):
        c = extract_cpg(_guarded_label_flow_model(), shape=PATTERN_LABEL_FLOW)
        self.assertFalse(c.out_of_scope)
        self.assertEqual(c.pattern, PATTERN_LABEL_FLOW)
        self.assertTrue(c.enforced, "a mutable boolean gate => enforced")
        self.assertEqual(c.params, {"label": "holding_private"})
        self.assertEqual(c.provenance["guard"], "holdingPrivate")

    def test_out_of_scope_never_unknown(self):
        c = extract_cpg(_no_control_model())
        self.assertTrue(c.out_of_scope, "E2: OUT_OF_SCOPE")
        self.assertFalse(c.candidate)
        self.assertIn("no P1 control", c.reason)
        with self.assertRaises(ValueError):
            lower_candidate(c)


class AbGateTest(unittest.TestCase):
    """The A/B gate (CPG-2): for the same control, the CPG producer and the
    code producer classify identically and lower to a ``to_dict()``-
    identical ProtocolIR (provenance excluded)."""

    def _ab(self, cpg_candidate, py_name):
        c_py = extract_file(_py(py_name))
        self.assertEqual(cpg_candidate.pattern, c_py.pattern,
                         "A/B: both producers must name the same P1 shape")
        self.assertEqual(cpg_candidate.enforced, c_py.enforced,
                         "A/B: both must read the same enforced/bypassable "
                         "split from the control")
        ir_a = _lowered(cpg_candidate).to_dict()
        ir_b = _lowered(c_py).to_dict()
        self.assertEqual(ir_a, ir_b,
                         "A/B: the lowered ProtocolIRs must be identical")
        return ir_a

    def test_budget_enforced_ab(self):
        self._ab(extract_cpg(_cpg_model(), shape=PATTERN_BUDGET),
                 "budget_enforced")

    def test_budget_bypassable_ab(self):
        self._ab(extract_cpg(_bypassable_budget_model(),
                             shape=PATTERN_BUDGET),
                 "budget_bypassable")

    def test_label_flow_bypassable_ab(self):
        self._ab(extract_cpg(_cpg_model(), shape=PATTERN_LABEL_FLOW),
                 "label_flow_bypassable")

    def test_label_flow_enforced_ab(self):
        self._ab(extract_cpg(_guarded_label_flow_model(),
                             shape=PATTERN_LABEL_FLOW),
                 "label_flow_enforced")


class CpgGateTest(unittest.TestCase):
    """The CPG candidate flows through the SAME Verify gate as the code
    candidate (E3): PROVEN / VIOLATED + exact witness / OUT_OF_SCOPE."""

    def _verdict(self, candidate):
        if candidate.out_of_scope:
            return Verdict.out_of_scope("cpg", "symbolic",
                                        reason=candidate.reason)
        return verify_candidate(lower_candidate(candidate), CFG)

    def test_budget_enforced_is_proven(self):
        v = self._verdict(extract_cpg(_cpg_model(), shape=PATTERN_BUDGET))
        self.assertTrue(v.is_proven(), "an enforced budget must be PROVEN")
        self.assertIsNone(v.counterexample)

    def test_budget_bypassable_violated_with_exact_witness(self):
        v = self._verdict(extract_cpg(_bypassable_budget_model(),
                                      shape=PATTERN_BUDGET))
        self.assertTrue(v.is_violated(), "a bypassable budget must be VIOLATED")
        self.assertEqual(v.counterexample, {"completed": 0, "inflight": 3})

    def test_label_flow_bypassable_violated_with_exact_witness(self):
        v = self._verdict(extract_cpg(_cpg_model(), shape=PATTERN_LABEL_FLOW))
        self.assertTrue(v.is_violated())
        self.assertEqual(v.counterexample,
                         {"holding_private": True, "exfiltrated": True})

    def test_label_flow_enforced_is_proven(self):
        v = self._verdict(extract_cpg(_guarded_label_flow_model(),
                                      shape=PATTERN_LABEL_FLOW))
        self.assertTrue(v.is_proven())

    def test_out_of_scope_verdict(self):
        v = self._verdict(extract_cpg(_no_control_model()))
        self.assertTrue(v.is_out_of_scope(), "E2: OUT_OF_SCOPE, not UNKNOWN")


class NarrowWaistTest(unittest.TestCase):
    """The new CPG front-end subpackage respects the narrow waist (the
    existing test_narrow_waist scans only rot/frontends/*.py -- top level --
    so the subpackage is checked here)."""

    def test_cpg_subpackage_imports_only_ir_and_stdlib(self):
        files = sorted(glob.glob(os.path.join(_ROOT, "rot", "frontends",
                                              "cpg", "*.py")))
        self.assertTrue(files, "no CPG frontend modules found")
        violations = []
        for path in files:
            with open(path, "r") as fh:
                for (line, target) in scan_source(fh.read()):
                    violations.append("%s:%d imports %r"
                                     % (os.path.basename(path), line, target))
        self.assertEqual(violations, [],
                         "CPG frontend crossed the narrow waist: %s"
                         % ", ".join(violations))


if __name__ == "__main__":
    unittest.main(verbosity=2)

