# -*- coding: utf-8 -*-
"""Unit tests for rot.invariants: label constants, Invariant dataclass,
all five registered invariants, blocking_permission(), and VerdictReport
integration.

Run: python tests/test_invariants.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.invariants import (
    Invariant,
    LABEL_INDUCTIVE,
    LABEL_BOUNDED,
    LABEL_LIKELY,
    LABEL_EVENTUALLY,
    BLOCKING_LABELS,
    PERM_ALERT,
    PERM_WARN,
    PERM_BLOCK,
    RUNG_STRUCTURAL,
    RUNG_LOCAL,
    RUNG_PROTOCOL,
    RUNG_E2E,
    ALL_RUNGS,
    RUNG_CEILING,
    PERMISSION_NAMES,
    agreement,
    validity,
    no_spurious_abort,
    zab_no_premature_apply,
    zab_apply_persisted,
    pbft_quorum,
    pbft_prepare_before_commit,
    no_double_charge,
    charge_requires_order,
    settle_requires_charge,
    names,
    get,
)
from rot.verdicts import VerdictReport, PROVEN


# ---------------------------------------------------------------------------
# 1. Label constants
# ---------------------------------------------------------------------------

class LabelConstantTests(unittest.TestCase):

    def test_label_values(self):
        self.assertEqual(LABEL_INDUCTIVE, "inductive_at_bound")
        self.assertEqual(LABEL_BOUNDED, "bounded_depth")
        self.assertEqual(LABEL_LIKELY, "likely_on_traces")

    def test_blocking_labels_set(self):
        self.assertIn(LABEL_INDUCTIVE, BLOCKING_LABELS)
        self.assertIn(LABEL_BOUNDED, BLOCKING_LABELS)
        self.assertIn(LABEL_EVENTUALLY, BLOCKING_LABELS)
        self.assertNotIn(LABEL_LIKELY, BLOCKING_LABELS)
        self.assertEqual(len(BLOCKING_LABELS), 3)

    def test_all_labels_distinct(self):
        labels = {LABEL_INDUCTIVE, LABEL_BOUNDED, LABEL_LIKELY,
                  LABEL_EVENTUALLY}
        self.assertEqual(len(labels), 4)


# ---------------------------------------------------------------------------
# 2. Invariant dataclass -- constructor & to_dict
# ---------------------------------------------------------------------------

class InvariantDataclassTests(unittest.TestCase):

    def test_defaults(self):
        inv = Invariant(name="x", description="d", expression=None)
        self.assertIsNone(inv.label)
        self.assertFalse(inv.pinned)
        self.assertIsNone(inv.bound)
        d = inv.to_dict()
        self.assertIn("label", d)
        self.assertIn("pinned", d)
        self.assertIsNone(d["bound"])
        self.assertFalse(d["blocking_permission"])

    def test_to_dict_includes_bound_when_set(self):
        inv = Invariant(name="x", description="d", expression=None,
                        label=LABEL_BOUNDED, pinned=True, bound=10)
        d = inv.to_dict()
        self.assertEqual(d["bound"], 10)
        self.assertEqual(d["label"], LABEL_BOUNDED)
        self.assertTrue(d["pinned"])

    def test_repr(self):
        inv = Invariant(name="x", description="d", expression=None,
                        label=LABEL_BOUNDED, pinned=True)
        r = repr(inv)
        self.assertIn("x", r)
        self.assertIn("bounded_depth", r)


# ---------------------------------------------------------------------------
# 3. blocking_permission()
# ---------------------------------------------------------------------------

class BlockingPermissionTests(unittest.TestCase):

    def test_bounded_pinned_true_blocks(self):
        inv = Invariant(name="x", description="d", expression=None,
                        label=LABEL_BOUNDED, pinned=True)
        self.assertTrue(inv.blocking_permission())

    def test_inductive_pinned_true_blocks(self):
        inv = Invariant(name="x", description="d", expression=None,
                        label=LABEL_INDUCTIVE, pinned=True)
        self.assertTrue(inv.blocking_permission())

    def test_likely_pinned_true_does_not_block(self):
        inv = Invariant(name="x", description="d", expression=None,
                        label=LABEL_LIKELY, pinned=True)
        self.assertFalse(inv.blocking_permission())

    def test_bounded_pinned_false_does_not_block(self):
        inv = Invariant(name="x", description="d", expression=None,
                        label=LABEL_BOUNDED, pinned=False)
        self.assertFalse(inv.blocking_permission())

    def test_inductive_pinned_false_does_not_block(self):
        inv = Invariant(name="x", description="d", expression=None,
                        label=LABEL_INDUCTIVE, pinned=False)
        self.assertFalse(inv.blocking_permission())

    def test_none_label_does_not_block(self):
        inv = Invariant(name="x", description="d", expression=None)
        self.assertFalse(inv.blocking_permission())

    def test_invalid_label_raises(self):
        with self.assertRaises(ValueError):
            Invariant(name="x", description="d", expression=None,
                      label="not_a_real_label", pinned=True)

    def test_likely_pinned_false_does_not_block(self):
        inv = Invariant(name="x", description="d", expression=None,
                        label=LABEL_LIKELY, pinned=False)
        self.assertFalse(inv.blocking_permission())


# ---------------------------------------------------------------------------
# 4. All registered invariants
# ---------------------------------------------------------------------------

class RegisteredInvariantTests(unittest.TestCase):

    def test_names_complete(self):
        expected = ["agreement", "policy_conformance", "bounded_eventually",
                    "validity", "no_spurious_abort", "zab_no_premature_apply",
                    "zab_apply_persisted", "pbft_quorum",
                    "pbft_prepare_before_commit", "no_double_charge",
                    "charge_requires_order", "settle_requires_charge",
                    "spendcap_within_cap", "no_exfiltration",
                    "no_unapproved_irreversible", "no_privilege_escalation",
                    "no_deadlock", "task_ends_or_escalates",
                    "no_runaway_budget", "no_over_privileged_tool"]
        self.assertEqual(names(), expected)

    def test_agreement_label_and_pinned(self):
        inv = agreement(n=3)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertTrue(inv.pinned)
        self.assertTrue(inv.blocking_permission())

    def test_validity_label_and_pinned(self):
        inv = validity(n=3)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertTrue(inv.pinned)
        self.assertTrue(inv.blocking_permission())

    def test_no_spurious_abort_label_and_pinned(self):
        inv = no_spurious_abort(n=3)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertFalse(inv.pinned)
        self.assertFalse(inv.blocking_permission())

    def test_zab_no_premature_apply_label_and_pinned(self):
        inv = zab_no_premature_apply(n=3)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertTrue(inv.pinned)
        self.assertTrue(inv.blocking_permission())

    def test_zab_apply_persisted_label_and_pinned(self):
        inv = zab_apply_persisted(n=3)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertFalse(inv.pinned)
        self.assertFalse(inv.blocking_permission())

    def test_pbft_quorum_label_and_pinned(self):
        inv = pbft_quorum(n=3)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertTrue(inv.pinned)
        self.assertTrue(inv.blocking_permission())

    def test_pbft_prepare_before_commit_label_and_pinned(self):
        inv = pbft_prepare_before_commit(n=3)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertFalse(inv.pinned)
        self.assertFalse(inv.blocking_permission())

    def test_no_double_charge_label_and_pinned(self):
        inv = no_double_charge(n=1)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertTrue(inv.pinned)
        self.assertTrue(inv.blocking_permission())
        self.assertEqual(inv.rung, RUNG_E2E)

    def test_charge_requires_order_label_and_pinned(self):
        inv = charge_requires_order(n=1)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertFalse(inv.pinned)
        self.assertFalse(inv.blocking_permission())
        self.assertEqual(inv.rung, RUNG_E2E)

    def test_settle_requires_charge_label_and_pinned(self):
        inv = settle_requires_charge(n=1)
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertFalse(inv.pinned)
        self.assertFalse(inv.blocking_permission())
        self.assertEqual(inv.rung, RUNG_LOCAL)

    def test_all_invariants_have_expected_label(self):
        # The liveness invariants use the bounded-eventually label; all the
        # safety invariants use the bounded-depth label.
        liveness_names = {"bounded_eventually", "task_ends_or_escalates"}
        for name in names():
            inv = get(name, n=3)
            if name in liveness_names:
                self.assertEqual(inv.label, LABEL_EVENTUALLY, name)
            else:
                self.assertEqual(inv.label, LABEL_BOUNDED,
                                 "invariant %r should have bounded label"
                                 % name)

    def test_blocking_invariants(self):
        for name in names():
            inv = get(name, n=3)
            expected = inv.pinned
            self.assertEqual(inv.blocking_permission(), expected,
                             "invariant %r: blocking=%r, pinned=%r"
                             % (name, inv.blocking_permission(), inv.pinned))

    def test_get_unknown_raises(self):
        with self.assertRaises(KeyError):
            get("nonexistent_invariant")

    def test_all_invariants_to_dict_has_required_keys(self):
        for name in names():
            inv = get(name, n=3)
            d = inv.to_dict()
            for key in ("name", "description", "kind", "label", "pinned"):
                self.assertIn(key, d,
                              "invariant %r to_dict missing key %r" % (name, key))

    def test_different_participant_counts(self):
        for n in (1, 2, 4):
            inv = agreement(n=n)
            self.assertEqual(inv.label, LABEL_BOUNDED)
            self.assertTrue(inv.pinned)
            inv2 = zab_no_premature_apply(n=n)
            self.assertEqual(inv2.label, LABEL_BOUNDED)
            self.assertTrue(inv2.pinned)


# ---------------------------------------------------------------------------
# 5. VerdictReport integration
# ---------------------------------------------------------------------------

class VerdictReportInvariantTests(unittest.TestCase):

    def _make_verdict(self, status=PROVEN):
        from rot.verdicts import Verdict
        return Verdict(status=status, property_name="test_prop",
                       engine="test", cegar_iterations=0, note="")

    def test_report_without_invariant_dict(self):
        v = self._make_verdict()
        report = VerdictReport(
            target="t", property_name="p", engine="e",
            config_dict={}, abstraction_dict={}, verdict=v)
        d = report.to_dict()
        self.assertNotIn("invariant", d)
        md = report.to_markdown()
        self.assertNotIn("Invariant label", md)

    def test_report_with_invariant_dict(self):
        v = self._make_verdict()
        inv = agreement(n=3)
        report = VerdictReport(
            target="t", property_name="p", engine="e",
            config_dict={}, abstraction_dict={},
            verdict=v, invariant_dict=inv.to_dict())
        d = report.to_dict()
        self.assertIn("invariant", d)
        self.assertEqual(d["invariant"]["label"], LABEL_BOUNDED)
        self.assertTrue(d["invariant"]["pinned"])
        md = report.to_markdown()
        self.assertIn("Invariant label", md)
        self.assertIn("bounded_depth", md)
        self.assertIn("pinned=True", md)
        self.assertIn("blocking_permission=True", md)

    def test_report_with_non_blocking_invariant(self):
        v = self._make_verdict()
        inv = no_spurious_abort(n=3)
        report = VerdictReport(
            target="t", property_name="p", engine="e",
            config_dict={}, abstraction_dict={},
            verdict=v, invariant_dict=inv.to_dict())
        md = report.to_markdown()
        self.assertIn("pinned=False", md)
        self.assertIn("blocking_permission=False", md)

    def test_report_to_dict_roundtrip(self):
        import json
        v = self._make_verdict()
        inv = zab_no_premature_apply(n=3)
        report = VerdictReport(
            target="t", property_name="p", engine="e",
            config_dict={"k": "v"}, abstraction_dict={"keep": ["x"]},
            verdict=v, invariant_dict=inv.to_dict())
        s = report.to_json()
        d = json.loads(s)
        self.assertIn("invariant", d)
        self.assertEqual(d["invariant"]["name"], "zab_no_premature_apply")
        self.assertEqual(d["invariant"]["label"], LABEL_BOUNDED)
        self.assertTrue(d["invariant"]["pinned"])
        self.assertEqual(d["target"], "t")
        self.assertEqual(d["verdict"]["status"], PROVEN)


# ---------------------------------------------------------------------------
# 6. Module-level consistency
# ---------------------------------------------------------------------------

class ModuleConsistencyTests(unittest.TestCase):

    def test_get_and_direct_are_equivalent(self):
        for name, fn in [("agreement", agreement),
                         ("validity", validity),
                         ("no_spurious_abort", no_spurious_abort),
                         ("zab_no_premature_apply", zab_no_premature_apply),
                         ("zab_apply_persisted", zab_apply_persisted)]:
            a = fn(n=3)
            b = get(name, n=3)
            self.assertEqual(a.name, b.name)
            self.assertEqual(a.label, b.label)
            self.assertEqual(a.pinned, b.pinned)
            self.assertEqual(a.blocking_permission(), b.blocking_permission())

    def test_default_is_agreement(self):
        from rot.invariants import default
        inv = default(n=3)
        self.assertEqual(inv.name, "agreement")
        self.assertEqual(inv.label, LABEL_BOUNDED)
        self.assertTrue(inv.pinned)

    def test_all_five_have_expressions(self):
        for name in names():
            inv = get(name, n=3)
            self.assertIsNotNone(inv.expression,
                                 "invariant %r has no expression" % name)


# ---------------------------------------------------------------------------
# 7. Assurance ladder (severity rungs)
# ---------------------------------------------------------------------------

class AssuranceLadderConstantsTests(unittest.TestCase):

    def test_permission_ordering(self):
        self.assertLess(PERM_ALERT, PERM_WARN)
        self.assertLess(PERM_WARN, PERM_BLOCK)

    def test_rung_ordering(self):
        self.assertLess(RUNG_STRUCTURAL, RUNG_LOCAL)
        self.assertLess(RUNG_LOCAL, RUNG_PROTOCOL)
        self.assertLess(RUNG_PROTOCOL, RUNG_E2E)

    def test_all_rungs(self):
        self.assertEqual(
            set(ALL_RUNGS),
            {RUNG_STRUCTURAL, RUNG_LOCAL, RUNG_PROTOCOL, RUNG_E2E})

    def test_rung_ceiling_mapping(self):
        self.assertEqual(len(RUNG_CEILING), 4)
        self.assertEqual(RUNG_CEILING[RUNG_STRUCTURAL], PERM_ALERT)
        self.assertEqual(RUNG_CEILING[RUNG_LOCAL], PERM_WARN)
        self.assertEqual(RUNG_CEILING[RUNG_PROTOCOL], PERM_BLOCK)
        self.assertEqual(RUNG_CEILING[RUNG_E2E], PERM_BLOCK)

    def test_permission_names(self):
        self.assertEqual(PERMISSION_NAMES[PERM_ALERT], "alert")
        self.assertEqual(PERMISSION_NAMES[PERM_WARN], "warn")
        self.assertEqual(PERMISSION_NAMES[PERM_BLOCK], "block")


class AssuranceLadderInvariantTests(unittest.TestCase):

    def _inv(self, **kw):
        return Invariant(name="x", description="d", expression=None, **kw)

    def test_default_rung_is_protocol(self):
        inv = self._inv()
        self.assertEqual(inv.rung, RUNG_PROTOCOL)

    def test_invalid_rung_raises(self):
        with self.assertRaises(ValueError):
            self._inv(rung=99)

    def test_declared_permission_blocking(self):
        inv = self._inv(label=LABEL_BOUNDED, pinned=True)
        self.assertEqual(inv.declared_permission(), PERM_BLOCK)
        inv = self._inv(label=LABEL_INDUCTIVE, pinned=True)
        self.assertEqual(inv.declared_permission(), PERM_BLOCK)

    def test_declared_permission_nonblocking(self):
        inv = self._inv(label=LABEL_BOUNDED, pinned=False)
        self.assertEqual(inv.declared_permission(), PERM_WARN)
        inv = self._inv(label=LABEL_LIKELY, pinned=True)
        self.assertEqual(inv.declared_permission(), PERM_WARN)
        inv = self._inv()
        self.assertEqual(inv.declared_permission(), PERM_WARN)

    def test_effective_permission_respects_ceiling(self):
        # declared BLOCK, rung caps it
        inv = self._inv(label=LABEL_BOUNDED, pinned=True, rung=RUNG_STRUCTURAL)
        self.assertEqual(inv.declared_permission(), PERM_BLOCK)
        self.assertEqual(inv.effective_permission(), PERM_ALERT)
        inv = self._inv(label=LABEL_BOUNDED, pinned=True, rung=RUNG_LOCAL)
        self.assertEqual(inv.effective_permission(), PERM_WARN)
        # rung can never raise the permission
        inv = self._inv(label=LABEL_BOUNDED, pinned=False, rung=RUNG_PROTOCOL)
        self.assertEqual(inv.effective_permission(), PERM_WARN)

    def test_blocking_permission_blocked_by_rung(self):
        inv = self._inv(label=LABEL_BOUNDED, pinned=True, rung=RUNG_STRUCTURAL)
        self.assertFalse(inv.blocking_permission())
        inv = self._inv(label=LABEL_BOUNDED, pinned=True, rung=RUNG_LOCAL)
        self.assertFalse(inv.blocking_permission())

    def test_blocking_permission_allows_high_rungs(self):
        inv = self._inv(label=LABEL_BOUNDED, pinned=True, rung=RUNG_PROTOCOL)
        self.assertTrue(inv.blocking_permission())
        inv = self._inv(label=LABEL_BOUNDED, pinned=True, rung=RUNG_E2E)
        self.assertTrue(inv.blocking_permission())
        inv = self._inv(label=LABEL_INDUCTIVE, pinned=True, rung=RUNG_E2E)
        self.assertTrue(inv.blocking_permission())

    def test_likely_label_never_blocks_even_on_high_rung(self):
        inv = self._inv(label=LABEL_LIKELY, pinned=True, rung=RUNG_E2E)
        self.assertEqual(inv.effective_permission(), PERM_WARN)
        self.assertFalse(inv.blocking_permission())

    def test_registered_local_invariants(self):
        self.assertEqual(zab_apply_persisted(n=3).rung, RUNG_LOCAL)
        self.assertEqual(pbft_prepare_before_commit(n=3).rung, RUNG_LOCAL)

    def test_registered_protocol_invariants_default_rung(self):
        for name in ("agreement", "validity", "no_spurious_abort",
                     "zab_no_premature_apply", "pbft_quorum"):
            inv = get(name, n=3)
            self.assertEqual(inv.rung, RUNG_PROTOCOL, name)

    def test_to_dict_includes_rung_and_permission(self):
        inv = self._inv(label=LABEL_BOUNDED, pinned=True, rung=RUNG_LOCAL)
        d = inv.to_dict()
        self.assertEqual(d["rung"], RUNG_LOCAL)
        self.assertEqual(d["permission"], "warn")
        self.assertFalse(d["blocking_permission"])
        inv = self._inv(label=LABEL_BOUNDED, pinned=True)
        d = inv.to_dict()
        self.assertEqual(d["rung"], RUNG_PROTOCOL)
        self.assertEqual(d["permission"], "block")
        self.assertTrue(d["blocking_permission"])


# ---------------------------------------------------------------------------
# Phase 1: constraint-vs-property
#   TypeInvariant as a state *constraint* (drops ill-formed states, never a
#   VIOLATED counterexample); no_deadlock with a DEADLOCK violation code;
#   task_ends_or_escalates as liveness; and the CEGAR wiring of the DEADLOCK
#   code on a refuted circular-wait witness.
# ---------------------------------------------------------------------------

class Phase1ConstraintVsPropertyTests(unittest.TestCase):

    def _int_model(self):
        import rot.ir as ir
        return ir.ProtocolIR(
            name="int-model",
            variables=[ir.StateVar("counter", ir.IntRange(0, 2))],
            init={"counter": 0})

    def test_type_invariant_is_a_constraint(self):
        from rot.invariants import type_invariant, KIND_CONSTRAINT
        inv = type_invariant(self._int_model())
        self.assertEqual(inv.name, "type_invariant")
        self.assertEqual(inv.kind, KIND_CONSTRAINT)
        # A state constraint restricts the state space; it is not a blocking
        # MR-gate claim (never a VIOLATED counterexample).
        self.assertFalse(inv.pinned)
        self.assertFalse(inv.blocking_permission())

    def test_type_invariant_drops_out_of_domain_states(self):
        from rot.invariants import type_invariant
        e = type_invariant(self._int_model()).expression
        # in-range -> well-formed (kept)
        self.assertIs(e.eval({"counter": 0}), True)
        self.assertIs(e.eval({"counter": 1}), True)
        self.assertIs(e.eval({"counter": 2}), True)
        # out-of-range -> ill-formed (dropped, not a VIOLATED counterexample)
        self.assertIs(e.eval({"counter": 3}), False)
        self.assertIs(e.eval({"counter": -1}), False)

    def test_type_invariant_label_membership(self):
        import rot.ir as ir
        from rot.invariants import type_invariant
        m = ir.ProtocolIR(
            name="enum-model",
            variables=[ir.StateVar("state", ir.Enum(["idle", "active", "done"]))],
            init={"state": "idle"})
        e = type_invariant(m).expression
        self.assertIs(e.eval({"state": "idle"}), True)
        self.assertIs(e.eval({"state": "active"}), True)
        # a value outside the label set -> ill-formed (dropped)
        self.assertIs(e.eval({"state": "bogus"}), False)

    def test_type_invariant_budget_bounds_and_history_shape(self):
        # covers the remaining two well-formedness categories:
        #   * budget bounds  -- a budget/spend IntRange [0, cap] is in range
        #   * history shape  -- a history variable holds one of the declared
        #                        shapes (an Enum)
        import rot.ir as ir
        from rot.invariants import type_invariant
        m = ir.ProtocolIR(
            name="budget-model",
            variables=[
                ir.StateVar("balance", ir.IntRange(0, 100)),
                ir.StateVar("history", ir.Enum(["open", "settled", "closed"])),
            ],
            init={"balance": 0, "history": "open"})
        e = type_invariant(m).expression
        # well-formed: balance within [0, cap], history a declared shape
        self.assertIs(e.eval({"balance": 50, "history": "open"}), True)
        # budget bounds: over the cap -> ill-formed (dropped)
        self.assertIs(e.eval({"balance": 150, "history": "open"}), False)
        # budget bounds: negative -> ill-formed (dropped)
        self.assertIs(e.eval({"balance": -5, "history": "settled"}), False)
        # history shape: undeclared shape -> ill-formed (dropped)
        self.assertIs(e.eval({"balance": 50, "history": "bogus"}), False)

    def test_no_deadlock_safety_with_deadlock_code(self):
        from rot.invariants import get, KIND_SAFETY
        from rot.verdicts import DEADLOCK
        inv = get("no_deadlock", 1)
        self.assertEqual(inv.kind, KIND_SAFETY)
        self.assertEqual(inv.violation_code, DEADLOCK)

    def test_task_ends_or_escalates_is_liveness(self):
        from rot.invariants import get, KIND_LIVENESS
        inv = get("task_ends_or_escalates", 1)
        self.assertEqual(inv.kind, KIND_LIVENESS)

    def test_buggy_deadlock_refuted_with_deadlock_code(self):
        import rot.approval as approval
        import rot.cegar as cegar
        from rot.modelfind import ModelFinder
        from rot.symbolic import EngineResult
        from rot.config import Config
        from rot.invariants import get
        from rot.verdicts import DEADLOCK, VIOLATED
        prop = get("no_deadlock", 1)
        model = approval.orchestration_build_ir(buggy=True)
        # The buggy orchestration reaches the circular-wait state.
        mf = ModelFinder.from_ir(model)
        status, witness = mf.exists_reachable(
            lambda s: (not prop.expression.eval(s)))
        self.assertEqual(status, "SAT", "buggy orchestration should deadlock")
        # the circular-wait witness: every agent blocked on another, task open.
        self.assertTrue(witness["task_pending"])
        self.assertTrue(witness["a_waiting"])
        self.assertTrue(witness["b_waiting"])
        self.assertTrue(witness["approver_waiting"])
        # and the CEGAR layer stamps the VIOLATED verdict with DEADLOCK
        # (not the default POLICY_DENIAL).
        res = EngineResult(status="violated", witness=witness, n_states=1)
        v = cegar.cegar(res, prop, Config(cegar_max_iter=1, max_states=1000),
                        "symbolic")
        self.assertEqual(v.status, VIOLATED)
        self.assertEqual(v.violation_code, DEADLOCK)

    def test_correct_orchestration_holds_no_deadlock(self):
        import rot.approval as approval
        from rot.modelfind import ModelFinder
        from rot.invariants import get
        prop = get("no_deadlock", 1)
        mf = ModelFinder.from_ir(approval.orchestration_build_ir(buggy=False))
        status, witness = mf.forall_reachable(
            lambda s: prop.expression.eval(s))
        self.assertIs(status, True,
                      "correct orchestration should be deadlock-free: %r"
                      % (witness,))


if __name__ == "__main__":
    unittest.main(verbosity=2)