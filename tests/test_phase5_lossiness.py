# -*- coding: utf-8 -*-
"""Phase 5 gate: reduce the CPG -> IR lossiness (joern-primary-ab-plan §2.2).

The CPG is the ground truth ``G``; the lowered ``ProtocolIR`` is the
abstraction ``A(G)``.  The lossiness that bites is the dataflow edges the
lowering drops: a deliberately-dropped edge is a *potential* threat.  Phase 5
turns that from a silent false-negative risk into an explicit, auditable
discipline (``rot.retention``):

  * **property-directed retention** -- the kept set is the property-relevant
    dataflow (the source -> sink path); every dropped edge is classified
    *irrelevant* / *unknown* / *taint-critical*;
  * **the hard rule** -- a ``PROVEN`` verdict with a dropped edge of unknown
    relevance fails closed to ``UNKNOWN`` + ``unsound_abstraction`` (the edge
    is named); a ``PROVEN`` with only proven-irrelevant drops stands;
  * **CEGAR on the front-end** -- a static <-> formal disagreement (the CPG
    carries a dropped threat edge yet the IR proved the property) is resolved
    by refining the IR to model the threat and re-checking (taint-critical ->
    the refutation; or proven irrelevant -> the PROVEN stands);
  * **the manifest is part of the claim packet** -- a deliberately-dropped
    dataflow edge is always *named* in the artifact.

The pure functions (``retention_manifest``, ``apply_retention_rule``,
``refine_on_disagreement``, ``apply_phase5``) are unit-tested offline on the
committed CPG fixture + a hand-built disagreement model, and the wiring is
tested end-to-end through ``verify_candidate(cpg=...)`` and the CPG-4 claim
packet.

Run: python -m pytest tests/test_phase5_lossiness.py -v
"""

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
from rot.frontends.code import PATTERN_BUDGET, PATTERN_LABEL_FLOW
from rot.frontends.cpg import extract_cpg
from rot.frontends.cpg_model import (CpgEdge, CpgMethod, CpgModel,
                                     CpgTaintNode, CpgType, EDGE_REACHING_DEF)
from rot.lower import lower_candidate
from rot.retention import (RELEVANCE_IRRELEVANT, RELEVANCE_TAINT_CRITICAL,
                           RELEVANCE_UNKNOWN, apply_phase5,
                           apply_retention_rule, retention_manifest)
from rot.verdicts import (PROVEN, VIOLATED, UNKNOWN, UNSOUND_ABSTRACTION,
                          Verdict)

CFG = Config(max_states=100000)
FIX_CPG = os.path.join(_ROOT, "tests", "fixtures", "cpg",
                       "connector.cpg.json")


def _connector():
    """The committed CPG fixture: budget ENFORCED + label_flow BYPASSABLE.

    Its label_flow taint path is ``report#ssn -> mask#ssn -> report#payload
    -> AuditLog.send#payload`` (a private parameter to the egress sink), while
    the budget accounting edges (``cap`` / ``inflight`` / ``settled`` /
    ``amount`` -> ``projected``) do not reach the egress sink -- so for the
    label_flow shape they are provably irrelevant, and for the budget shape the
    sum edges are kept.
    """
    return CpgModel.from_file(FIX_CPG)


def _disagreement_model():
    """A label_flow CPG with a *deliberately-dropped* threat edge of unknown
    relevance: a taint source (``report#ssn``) feeds the egress sink, AND a
    second, unclassified edge (``leak#junk``) also feeds the egress sink.  The
    second edge's target can reach the sink but its source is not a confirmed
    taint source -- exactly the "dropped edge of unknown relevance" the Phase
    5 gate must catch.
    """
    O = "p.Svc"
    S = "p.Out"
    return CpgModel(
        meta={"source": "p/Svc.java"},
        types=[CpgType("Svc", O, owner="p"), CpgType("Out", S, owner="p")],
        fields=[],
        methods=[
            CpgMethod("report", O + ".report", owner=O,
                      defs=["ssn", "payload"], args=["ssn"]),
            CpgMethod("leak", O + ".leak", owner=O, defs=["junk"]),
        ],
        edges=[
            CpgEdge(EDGE_REACHING_DEF, O + ".report#ssn",
                    O + ".report#payload"),
            CpgEdge(EDGE_REACHING_DEF, O + ".report#payload",
                    S + ".send#payload"),
            # the deliberately-dropped threat edge (unknown relevance).
            CpgEdge(EDGE_REACHING_DEF, O + ".leak#junk",
                    S + ".send#payload"),
        ],
        taint_sources=[CpgTaintNode(O + ".report#ssn", "parameter", "ssn",
                                    O, "private")],
        taint_sinks=[CpgTaintNode(S + ".send", "call", "send",
                                  O + ".report", "egress")])


def _proven(name="no_exfil"):
    return Verdict.proven(name, "symbolic")


def _violated(name="no_exfil"):
    return Verdict.violated(name, "symbolic", counterexample={"witness": True})


class RetentionManifestTest(unittest.TestCase):
    """Property-directed retention: the kept set is the taint path; the rest
    is classified (irrelevant / unknown / taint-critical) and *named*."""

    def test_connector_keeps_taint_path_drops_irrelevant(self):
        m = _connector()
        mf = retention_manifest(m, PATTERN_LABEL_FLOW)
        kept_pairs = set((e.src, e.dst) for e in mf.kept)
        self.assertIn(("com.acme.guard.Connector.report#ssn",
                       "com.acme.guard.Connector.mask#ssn"), kept_pairs)
        self.assertIn(("com.acme.guard.Connector.report#payload",
                       "com.acme.guard.AuditLog.send#payload"), kept_pairs)
        # the budget accounting edges do not reach the egress sink: dropped
        # and classified proven-irrelevant (named).
        self.assertTrue(mf.dropped)
        self.assertEqual(mf.unknown(), [])  # no unconfirmed sources here
        for e in mf.dropped:
            self.assertEqual(e.relevance, RELEVANCE_IRRELEVANT)
            self.assertTrue(e.evidence)
            self.assertIn(e.dst, e.evidence)  # the edge is named

    def test_budget_shape_keeps_sum_inputs(self):
        m = _connector()
        mf = retention_manifest(m, PATTERN_BUDGET)
        self.assertTrue(any(e.dst.endswith("canSpend#projected")
                            for e in mf.kept))
        # budget has no unknown category (its threat is the sum, which the
        # CPG-3 cross-check verifies) -- every dropped edge is irrelevant.
        self.assertEqual(mf.unknown(), [])
        for e in mf.dropped:
            self.assertEqual(e.relevance, RELEVANCE_IRRELEVANT)

    def test_disagreement_model_has_an_unknown_edge(self):
        m = _disagreement_model()
        mf = retention_manifest(m, PATTERN_LABEL_FLOW)
        self.assertEqual(mf.dropped_edge_names(RELEVANCE_UNKNOWN),
                         ["p.Svc.leak#junk -> p.Out.send#payload"])

    def test_manifest_is_deterministic_and_hashable(self):
        m = _connector()
        a = retention_manifest(m, PATTERN_LABEL_FLOW).to_dict()
        b = retention_manifest(m, PATTERN_LABEL_FLOW).to_dict()
        self.assertEqual(a, b)
        import hashlib
        import json
        h = hashlib.sha256(
            json.dumps(a, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertEqual(len(h), 64)


class HardRuleTest(unittest.TestCase):
    """The hard rule (over-approximate, don't omit): a ``PROVEN`` with a
    dropped edge of unknown relevance fails closed to ``UNKNOWN`` + the
    ``unsound_abstraction`` advisory, and the edge is *named*."""

    def test_proven_with_unknown_edge_is_downgraded(self):
        m = _disagreement_model()
        mf = retention_manifest(m, PATTERN_LABEL_FLOW)
        out = apply_retention_rule(_proven(), mf)
        self.assertEqual(out.status, UNKNOWN)
        self.assertIn(UNSOUND_ABSTRACTION, out.advisories)
        self.assertIsNone(out.counterexample)
        self.assertIsNone(out.trace)
        # the dropped edge is named on the verdict.
        self.assertIn("leak#junk", out.note)
        self.assertTrue(any("leak#junk" in s for s in out.soundness))

    def test_proven_with_only_irrelevant_drops_stands(self):
        m = _connector()  # label_flow: taint path kept, rest proven irrelevant
        mf = retention_manifest(m, PATTERN_LABEL_FLOW)
        out = apply_retention_rule(_proven(), mf)
        self.assertEqual(out.status, PROVEN, "irrelevant drops must not fire")
        self.assertNotIn(UNSOUND_ABSTRACTION, out.advisories)

    def test_non_proven_verdicts_are_untouched(self):
        m = _disagreement_model()
        mf = retention_manifest(m, PATTERN_LABEL_FLOW)
        v = _violated()
        self.assertIs(apply_retention_rule(v, mf), v)

    def test_rule_does_not_mutate_input(self):
        m = _disagreement_model()
        mf = retention_manifest(m, PATTERN_LABEL_FLOW)
        v = _proven()
        apply_retention_rule(v, mf)
        self.assertEqual(v.status, PROVEN, "the input verdict is untouched")


class CegarDisagreementTest(unittest.TestCase):
    """CEGAR on the front-end: a static <-> formal disagreement (the CPG
    carries a dropped threat edge yet the IR proved the property) is resolved
    by refining the IR to model the threat and re-checking."""

    def _ir(self, shape):
        """A lowered label_flow IR whose egress is *guarded* (the enforced
        shape) -- so refining it to model the dropped threat edge (unguarded
        egress) exposes the leak.  Built directly, independent of the CPG
        control-recognition heuristics."""
        class _C(object):
            out_of_scope = False
            is_control = True
            pattern = PATTERN_LABEL_FLOW
            enforced = True
            params = {"label": "ssn"}
            provenance = {"source": "phase5-test"}
            pinned_property = None
        return lower_candidate(_C())

    def test_disagreement_resolves_to_taint_critical(self):
        m = _disagreement_model()
        ir = self._ir(PATTERN_LABEL_FLOW)
        final, resolved, record = apply_phase5(
            m, PATTERN_LABEL_FLOW, ir, _proven(), CFG)
        # the dropped edge was taint-critical: modeling it refutes the
        # property, so the original PROVEN was a silent false negative.
        self.assertEqual(final.status, VIOLATED)
        self.assertEqual(
            [e.relevance for e in resolved.dropped],
            [RELEVANCE_TAINT_CRITICAL])
        self.assertIsNotNone(record)
        self.assertEqual(record["refined_status"], VIOLATED)

    def test_no_disagreement_when_not_proven(self):
        m = _disagreement_model()
        ir = self._ir(PATTERN_LABEL_FLOW)
        final, resolved, record = apply_phase5(
            m, PATTERN_LABEL_FLOW, ir, _violated(), CFG)
        self.assertEqual(final.status, VIOLATED)
        self.assertIsNone(record, "no refinement when there is no PROVEN")

    def test_no_disagreement_when_no_unknown_edge(self):
        m = _connector()  # no unknown-relevance edge
        cand = extract_cpg(m, shape=PATTERN_LABEL_FLOW)
        ir = lower_candidate(cand)
        final, resolved, record = apply_phase5(
            m, PATTERN_LABEL_FLOW, ir, _proven(), CFG)
        # PROVEN stands (only proven-irrelevant drops), no refinement.
        self.assertEqual(final.status, PROVEN)
        self.assertIsNone(record)


class PipelineWiringTest(unittest.TestCase):
    """The Phase 5 discipline is wired end-to-end: ``verify_candidate(cpg=...)``
    stamps the retention manifest on the verdict evidence, and the CPG-4 claim
    packet carries it as a first-class section (a deliberately-dropped dataflow
    edge is always named in the artifact)."""

    def _gate(self, model, shape):
        cand = extract_cpg(model, shape=shape)
        if cand.out_of_scope:
            return Verdict.out_of_scope("cpg", "symbolic", reason=cand.reason)
        ir = lower_candidate(cand)
        return verify_candidate(ir, CFG, cpg=model)

    def test_verify_candidate_stamps_retention(self):
        v = self._gate(_connector(), PATTERN_LABEL_FLOW)
        rt = v.evidence.get("retention")
        self.assertIsInstance(rt, dict)
        self.assertIn("kept", rt)
        self.assertIn("dropped", rt)
        self.assertIn("unknown", rt)
        self.assertIn("irrelevant", rt)
        # the taint path is kept, named.
        self.assertTrue(any(e["to"].endswith("AuditLog.send#payload")
                            for e in rt["kept"]))

    def test_claim_packet_carries_retention_section(self):
        import rot.cpg4 as cpg4
        m = _connector()
        packet = cpg4.claim_packet_for_cpg(m, CFG)
        self.assertIn("retention", packet)
        self.assertIn(PATTERN_LABEL_FLOW, packet["retention"])
        lf = packet["retention"][PATTERN_LABEL_FLOW]
        self.assertIn("kept", lf)
        # the manifest reproduces: same inputs -> same manifest_id.
        self.assertEqual(packet["manifest_id"], cpg4.manifest_id(
            {k: packet[k] for k in packet if k != "manifest_id"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)