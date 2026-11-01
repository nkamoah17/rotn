# -*- coding: utf-8 -*-
"""Phase 0 gate (docs/joern-primary-ab-plan.md): the unified IR contract.

Every frontend -- the ``code`` and ``cpg`` P1 producers, the hand-authored
``targets`` oracle, and the ``java`` 2PC frontend -- must land in the *same*
``ProtocolIR`` type, stamp the contract metadata (the derived ``protocol``
label + source-pinned ``provenance`` + a ``lossiness`` manifest), and the
narrow waist must be green: ``linearize -> emit -> check -> CEGAR -> replay``
runs **byte-for-byte** identically on every frontend's IR of the *same
control*.

Controls covered in the PRODUCT suite:

* **spendcap** (budget P1): ``code`` + ``cpg`` + ``targets`` (correct and
  bypassable variants).

The **2PC** byte-for-byte control (``targets`` oracle vs the ``java``
frontend) needs the protocol-plane oracle (``rot.twopc``), which lives in the
research plane -- it runs in the ``rotn-research`` suite, not here.  The
``java`` frontend's IR is still held to the metadata contract below (it is a
product frontend and imports no research module).

Run: python tests/test_phase0_ir_contract.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir
import rot.targets as targets
import rot.frontends.java as java_fe
from rot.config import Config
from rot.frontends.code import extract_file
from rot.frontends.cpg import extract_cpg
from rot.frontends.cpg_model import CpgModel
from rot.lower import lower_candidate
from rot.linearization import linearize
from rot.emitter import Emitter
from rot.symbolic import SymbolicEngine
from rot.cegar import cegar
from rot.invariants import Invariant
from rot.targeted_test import replay_schedule

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE_FIX = os.path.join(ROOT, "tests", "fixtures", "code")
CPG_FIX = os.path.join(ROOT, "tests", "fixtures", "cpg", "connector.cpg.json")
JAVA_DIR = os.path.join(ROOT, "examples", "twopc")
CFG = Config(max_states=100000)

# The four frontends' IRs of the same control (Phase 0: all four land in the
# same ProtocolIR type with the contract metadata stamped).
FRONTEND_IRS = [
    ("code", lower_candidate(
        extract_file(os.path.join(CODE_FIX, "budget_enforced.py")))),
    ("cpg", lower_candidate(
        extract_cpg(CpgModel.from_file(CPG_FIX), shape="budget"))),
    ("targets", targets.build("spendcap-correct", 1)),
    ("java", java_fe.build_ir(JAVA_DIR, n=3, buggy=False)),
]

# The gate controls: (label, pinned property name, replay path, [IRs]).
GATE_CONTROLS = [
    ("spendcap-correct", "spendcap_within_cap", ["spend_ok", "spend_ok",
                                                  "respond"],
     [lower_candidate(
         extract_file(os.path.join(CODE_FIX, "budget_enforced.py"))),
      lower_candidate(extract_cpg(CpgModel.from_file(CPG_FIX),
                                  shape="budget")),
      targets.build("spendcap-correct", 1)]),
    ("spendcap-buggy", "spendcap_within_cap", ["spend_ok", "spend_ok"],
     [lower_candidate(
         extract_file(os.path.join(CODE_FIX, "budget_bypassable.py"))),
      targets.build("spendcap-buggy", 1)]),
]


def _structural(ir_model):
    """The control: the ``to_dict()`` projection minus the producer
    provenance (``metadata`` and ``source_path`` are producer-specific;
    the oracle has no source directory, the frontends point at their
    inputs)."""
    d = ir_model.to_dict()
    d.pop("metadata", None)
    d.pop("source_path", None)
    return d


def _chain(ir_model, prop_name, replay_path):
    """``linearize -> emit -> check -> CEGAR -> replay``; the gate output.

    Returns a canonical (JSON-normalised) tuple so byte-for-byte equality is
    the assertion -- exactly what the Phase 0 gate demands."""
    prop_expr = ir_model.pinned_property
    linear_model = linearize(ir_model)
    module_src, op_name = Emitter(linear_model,
                                  module_name="TwoPC").emit(
        prop_name, prop_expr)
    eng = SymbolicEngine(linear_model, max_states=CFG.max_states)
    engine_result = eng.check(prop_expr, CFG.max_states)
    prop = Invariant(name=prop_name, description="Phase 0 gate",
                     expression=prop_expr)
    verdict = cegar(engine_result, prop, CFG, "symbolic",
                    model=linear_model)
    replay = replay_schedule(ir_model, prop_expr, replay_path)
    return (module_src, op_name,
            json.dumps(verdict.to_dict(), sort_keys=True),
            json.dumps(replay, sort_keys=True))



class ContractTest(unittest.TestCase):
    """The IR contract: one type, and the metadata keys every producer
    stamps (derived label + source-pinned provenance + lossiness manifest)."""

    def test_all_frontends_emit_the_same_protocol_ir_type(self):
        for label, ir_model in FRONTEND_IRS:
            self.assertIsInstance(
                ir_model, ir.ProtocolIR,
                "%s frontend must land in the ProtocolIR type" % label)

    def test_contract_metadata_is_stamped(self):
        for label, ir_model in FRONTEND_IRS:
            meta = ir_model.metadata
            # Derived label: the protocol family, derived from the control.
            self.assertIsInstance(meta.get("protocol"), str,
                                  "%s: missing derived protocol label" % label)
            self.assertTrue(meta.get("protocol"),
                            "%s: empty protocol label" % label)
            # Source-pinned provenance: where this model came from (a real
            # file/function/line pin, or the oracle module).
            prov = meta.get("provenance")
            self.assertIsInstance(prov, dict,
                                  "%s: missing source-pinned provenance"
                                  % label)
            self.assertTrue(prov, "%s: empty provenance" % label)
            # Lossiness manifest: what the source -> IR lowering dropped.
            loss = meta.get("lossiness")
            self.assertIsInstance(loss, list,
                                  "%s: missing lossiness manifest" % label)
            self.assertTrue(loss, "%s: empty lossiness manifest" % label)
            for entry in loss:
                self.assertIsInstance(entry.get("dropped"), str,
                                      "%s: lossiness entry without 'dropped'"
                                      % label)
                self.assertIsInstance(entry.get("reason"), str,
                                      "%s: lossiness entry without 'reason'"
                                      % label)
                self.assertTrue(entry.get("dropped"), label)
                self.assertTrue(entry.get("reason"), label)


class GateTest(unittest.TestCase):
    """The Phase 0 gate: the narrow waist is green -- the same control, from
    any frontend, runs ``linearize -> emit -> check -> CEGAR -> replay``
    byte-for-byte identically."""

    def test_same_control_is_structurally_identical(self):
        for label, _prop, _path, irs in GATE_CONTROLS:
            ref = _structural(irs[0])
            for other in irs[1:]:
                self.assertEqual(ref, _structural(other),
                                 "%s: the frontends' IRs of the same control "
                                 "must be structurally identical" % label)

    def test_code_and_cpg_agree_on_the_lossiness_manifest(self):
        # Both P1 producers share the lowering (rot.lower), so they must
        # agree on what was dropped -- the A/B parity gate compares it.
        for label, _prop, _path, irs in GATE_CONTROLS:
            cands = [m for m in irs
                     if m.metadata.get("candidate")]
            if len(cands) < 2:
                continue
            for other in cands[1:]:
                self.assertEqual(
                    cands[0].metadata["lossiness"],
                    other.metadata["lossiness"],
                    "%s: code and cpg must stamp the same lossiness "
                    "manifest" % label)

    def test_gate_chain_runs_byte_for_byte_on_all_frontends(self):
        for label, prop_name, path, irs in GATE_CONTROLS:
            ref = _chain(irs[0], prop_name, path)
            for other in irs[1:]:
                self.assertEqual(
                    ref, _chain(other, prop_name, path),
                    "%s: linearize -> emit -> check -> CEGAR -> replay must "
                    "be byte-for-byte identical across the frontends"
                    % label)


if __name__ == "__main__":
    unittest.main(verbosity=2)
