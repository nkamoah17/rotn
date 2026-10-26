# -*- coding: utf-8 -*-
"""Unit tests for rot.incremental: delta IR construction + delta emission.

Covers:
  * build_delta_ir keeps the full state schema
  * build_delta_ir keeps only init + the impacted transition actions
  * build_delta_ir excludes unrelated actions (ZAB tx2) but keeps them for 2PC
  * build_delta_ir does not mutate the source IR
  * build_delta_ir records delta metadata
  * emit_delta_spec: TLA contains the impacted action definitions
  * emit_delta_spec: TLA excludes the unrelated action definitions
  * emit_delta_spec: the affected invariant operator is emitted
  * emit_delta_spec: on-the-fly impact from changed_actions
  * emit_delta_spec: missing both impact_set and changed_actions raises
  * emit_delta_spec: writes .tla/.cfg into out_dir

Run: python tests/test_incremental.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.ir import V, C, eq, If
from rot.impact import compute_impact
from rot.invariants import Invariant
from rot.incremental import build_delta_ir, emit_delta_spec
from rot.emitter import emit_delta
from rot.zab import build_ir as zab_build_ir
from rot.twopc import build_ir as twopc_build_ir


def _action_defs(src):
    """The set of action/operator names defined as ``name ==`` in a module."""
    out = set()
    for line in src.splitlines():
        s = line.strip()
        if s.endswith("=="):
            out.add(s[:-2].strip())
    return out


# ---------------------------------------------------------------------------
# 1. build_delta_ir
# ---------------------------------------------------------------------------
class BuildDeltaIrTests(unittest.TestCase):

    def setUp(self):
        self.ir = zab_build_ir(3)
        self.impact = compute_impact(self.ir, ["apply_1_1"], invariants=[])
        self.delta = build_delta_ir(self.ir, self.impact)

    def test_keeps_full_state_schema(self):
        # Same state schema as the source (the spec says "same state schema").
        self.assertEqual(
            sorted(v.name for v in self.delta.variables),
            sorted(v.name for v in self.ir.variables))

    def test_keeps_init_and_impacted_only(self):
        names = [a.name for a in self.delta.actions]
        self.assertIn("init", names)
        for a in self.impact.impacted_actions:
            self.assertIn(a, names)
        # Nothing else.
        expected = set(self.impact.impacted_actions) | {"init"}
        self.assertEqual(set(names), expected)

    def test_excludes_unrelated_actions(self):
        names = set(a.name for a in self.delta.actions)
        for a in ("apply_2_1", "apply_2_2", "apply_2_3", "commit_2",
                  "persist_2_1", "persist_2_2", "persist_2_3",
                  "persist_1_2", "persist_1_3"):
            self.assertNotIn(a, names)

    def test_does_not_mutate_source(self):
        before = len(self.ir.actions)
        build_delta_ir(self.ir, self.impact)
        self.assertEqual(len(self.ir.actions), before)

    def test_metadata_marks_delta(self):
        self.assertTrue(self.delta.metadata.get("delta"))
        self.assertIn("apply_1_1", self.delta.metadata["changed_actions"])
        self.assertIn("commit_1", self.delta.metadata["impacted_actions"])

    def test_name_is_derived(self):
        self.assertTrue(self.delta.name.endswith("_delta"))

    def test_2pc_delta_is_full(self):
        ir = twopc_build_ir(4)
        impact = compute_impact(ir, ["vote_1_yes"], invariants=[])
        delta = build_delta_ir(ir, impact)
        # 2PC is fully coupled: every transition action is impacted, so the
        # delta keeps all of them (plus init).
        src_actions = set(a.name for a in ir.actions)
        self.assertEqual(set(a.name for a in delta.actions), src_actions)


# ---------------------------------------------------------------------------
# 2. emit_delta_spec
# ---------------------------------------------------------------------------
class EmitDeltaSpecTests(unittest.TestCase):

    def setUp(self):
        self.ir = zab_build_ir(3)
        # A scoped (transaction-1) invariant: keeps the delta schema minimal and
        # lets us assert the invariant operator is present.
        self.inv = Invariant(
            "zab_tx1_prop", "d",
            If(eq(V("applied_1_1"), C("done")),
               eq(V("committed_1"), C("done")), C(True)),
            "safety")
        self.impact = compute_impact(self.ir, ["apply_1_1"],
                                     invariants=[self.inv])
        self.result = emit_delta_spec(
            self.ir, impact_set=self.impact,
            invariant_name="zab_tx1_prop", invariant_expr=self.inv.expression,
            module_name="ZabDelta")

    def test_returns_tla_source_and_op(self):
        self.assertIn("---- MODULE ZabDelta ----", self.result["tla_source"])
        self.assertEqual(self.result["op_name"], "ZabTx1Prop")

    def test_impacted_actions_emitted(self):
        defs = _action_defs(self.result["tla_source"])
        for a in self.impact.impacted_actions:
            self.assertIn(a, defs, "missing impacted action %s" % a)
        self.assertIn("init", [a.name for a in self.result["delta_ir"].actions])

    def test_unrelated_actions_excluded(self):
        defs = _action_defs(self.result["tla_source"])
        for a in ("apply_2_1", "apply_2_2", "commit_2", "persist_2_1"):
            self.assertNotIn(a, defs, "unexpected action %s in delta" % a)

    def test_affected_invariant_emitted(self):
        self.assertIn("zab_tx1_prop", self.impact.affected_invariants)
        self.assertIn("ZabTx1Prop ==", self.result["tla_source"])

    def test_delta_ir_present(self):
        self.assertTrue(self.result["delta_ir"].metadata.get("delta"))


class EmitDeltaSpecInputTests(unittest.TestCase):

    def setUp(self):
        self.ir = zab_build_ir(3)
        self.inv = Invariant(
            "zab_tx1_prop", "d",
            If(eq(V("applied_1_1"), C("done")),
               eq(V("committed_1"), C("done")), C(True)),
            "safety")

    def test_on_the_fly_impact_from_changed_actions(self):
        r = emit_delta_spec(
            self.ir, changed_actions=["apply_1_1"],
            invariant_name="zab_tx1_prop", invariant_expr=self.inv.expression)
        self.assertIn("apply_1_1", r["impact_set"].changed_actions)
        self.assertIn("apply_1_1 ==", r["tla_source"])

    def test_neither_impact_set_nor_changed_actions_raises(self):
        with self.assertRaises(ValueError):
            emit_delta_spec(self.ir, invariant_name="p",
                            invariant_expr=self.inv.expression)

    def test_writes_files_to_out_dir(self):
        d = tempfile.mkdtemp(prefix="rotn_delta_")
        try:
            r = emit_delta_spec(
                self.ir, impact_set=self._impact(),
                invariant_name="zab_tx1_prop", invariant_expr=self.inv.expression,
                out_dir=d, module_name="ZabDelta")
            self.assertTrue(os.path.isfile(r["tla_path"]))
            self.assertTrue(os.path.isfile(r["cfg_path"]))
            with open(r["tla_path"]) as f:
                self.assertIn("---- MODULE ZabDelta ----", f.read())
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def _impact(self):
        return compute_impact(self.ir, ["apply_1_1"], invariants=[self.inv])


class EmitDeltaDirectTests(unittest.TestCase):

    def test_emit_delta_returns_source_op_emitter(self):
        ir = zab_build_ir(3)
        impact = compute_impact(ir, ["apply_1_1"], invariants=[])
        delta = build_delta_ir(ir, impact)
        inv = Invariant("p", "d",
                        If(eq(V("applied_1_1"), C("done")),
                           eq(V("committed_1"), C("done")), C(True)),
                        "safety")
        src, op, em = emit_delta(delta, "p", inv.expression, module_name="D")
        self.assertIn("---- MODULE D ----", src)
        self.assertEqual(op, "P")
        self.assertEqual(em.module_name, "D")


if __name__ == "__main__":
    unittest.main(verbosity=2)