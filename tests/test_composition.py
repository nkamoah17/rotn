# -*- coding: utf-8 -*-
"""Phase 2 (composition plane) checks on the payment vertical-slice target.

Verifies that the composition plane merges the client and payment service
IRs into one well-formed concurrent IR, that the cross-service invariant
``no_double_charge`` discriminates the correct and buggy variants, and that
the end-to-end merge-request gate BLOCKS a regression (with a deterministic
failing test) while an unchanged pair PASSES.

Run: python tests/test_composition.py
"""

import os
import sys
import unittest

# --- import bootstrap (mirror tests/test_zab_target.py) ---------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.payment as payment
import rot.invariants as invariants
from rot.composition import (
    CompositionError,
    compose,
    shared_variables,
)
from rot.modelfind import ModelFinder, SAT, UNSAT
from rot.mr_gate import PASS, BLOCK, evaluate_mr


def _forall(prop, ir):
    """(ok, witness) -- ok is True iff ``prop`` holds in every reachable state.

    Raises if the state space exceeds the bounded-checking budget (UNKNOWN):
    the payment slice is small, so UNKNOWN would mean a modelling error.
    """
    mf = ModelFinder.from_ir(ir)
    status, witness = mf.forall_reachable(lambda s: prop.eval(s))
    if status is True:
        return True, None
    if status is False:
        return False, witness
    raise AssertionError("model finder returned UNKNOWN; state space too large "
                         "for the payment slice (saturation fix regressed?)")


def _exists_violation(prop, ir):
    """(violated, witness_state) over reachable states."""
    mf = ModelFinder.from_ir(ir)
    status, witness = mf.exists_reachable(lambda s: (not prop.eval(s)))
    if status == SAT:
        return True, witness
    if status == UNSAT:
        return False, None
    raise AssertionError("model finder returned UNKNOWN; state space too large "
                         "for the payment slice (saturation fix regressed?)")


class ServiceIRTests(unittest.TestCase):
    """Per-service IRs are well-formed and expose the expected surface."""

    def test_client_ir_is_well_formed(self):
        client = payment.build_client_ir()
        self.assertFalse(client.validate())
        self.assertEqual([v.name for v in client.variables],
                         ["ordered", "cancelled"])
        self.assertTrue(any(a.is_initial for a in client.actions))
        for a in client.actions:
            self.assertEqual(a.owner, "client")

    def test_payment_ir_structure_both_variants(self):
        for buggy in (False, True):
            svc = payment.build_payment_ir(buggy=buggy)
            self.assertEqual([v.name for v in svc.variables],
                             ["charges", "settled"])
            names = [a.name for a in svc.actions]
            self.assertEqual(names, ["init", "charge", "settle"])

    def test_service_ir_may_reference_other_services(self):
        # Composition contract: a *service* IR need not be self-contained --
        # it may reference variables owned by another service (``charge`` is
        # guarded on the client-owned ``ordered``).  Standalone validation
        # therefore flags that cross-reference; the *composed* IR must be the
        # one that validates cleanly.
        pay = payment.build_payment_ir()
        problems = pay.validate()
        self.assertTrue(
            any("ordered" in p for p in problems),
            "payment service references client-owned 'ordered'; standalone "
            "validate() should surface it (got %r)" % (problems,))
        composed = payment.build_ir(n=1, buggy=False)
        self.assertFalse(composed.validate(),
                         "the *composed* IR must be well-formed")

    def test_services_share_no_state(self):
        # The composition is *cross-reference* (the payment service guards
        # ``charge`` on the client-owned ``ordered``), not shared-state.
        client = payment.build_client_ir()
        pay = payment.build_payment_ir()
        self.assertEqual(shared_variables(client, pay), [])


class CompositionTests(unittest.TestCase):
    """compose() merges the service IRs into one well-formed concurrent IR."""

    def test_composed_ir_is_well_formed(self):
        for buggy in (False, True):
            composed = payment.build_ir(n=1, buggy=buggy)
            self.assertFalse(composed.validate(),
                             msg=str(composed.validate()))
            self.assertEqual(
                [v.name for v in composed.variables],
                ["ordered", "cancelled", "charges", "settled"])

    def test_actions_are_namespaced(self):
        composed = payment.build_ir(n=1, buggy=False)
        names = [a.name for a in composed.actions]
        for expected in ("client.order", "client.cancel",
                         "payment.charge", "payment.settle"):
            self.assertIn(expected, names,
                          "expected namespaced action %r in %r" % (expected,
                                                                  names))

    def test_single_merged_init_initializes_every_variable(self):
        composed = payment.build_ir(n=1, buggy=False)
        inits = [a for a in composed.actions if a.is_initial]
        self.assertEqual(len(inits), 1)
        self.assertEqual(inits[0].name, "init")
        covered = {e.var for e in inits[0].effects}
        self.assertEqual(covered, {"ordered", "cancelled", "charges",
                                   "settled"})
        # and the initial *state* is the joint init state
        states = ModelFinder.from_ir(composed).reachable_states()
        self.assertEqual(states[0],
                         {"ordered": False, "cancelled": False,
                          "charges": 0, "settled": False})

    def test_compose_rejects_duplicate_service_names(self):
        client = payment.build_client_ir()
        with self.assertRaises(CompositionError):
            compose("dup", [client, client])

    def test_compose_keeps_provenance(self):
        composed = payment.build_ir(n=1, buggy=False)
        comp = composed.metadata.get("composition")
        self.assertIsNotNone(comp, "composed IR must carry composition metadata")
        self.assertEqual([s["name"] for s in comp["services"]],
                         ["client", "payment"])


class InvariantTests(unittest.TestCase):
    """The named invariants discriminate the correct and buggy variants."""

    @classmethod
    def setUpClass(cls):
        cls.correct = payment.build_ir(n=1, buggy=False)
        cls.buggy = payment.build_ir(n=1, buggy=True)

    def test_correct_model_holds_all_three_invariants(self):
        for name in ("no_double_charge", "charge_requires_order",
                     "settle_requires_charge"):
            prop = invariants.get(name, n=1).expression
            ok, witness = _forall(prop, self.correct)
            self.assertTrue(ok, "correct payment should satisfy %s, "
                                "but found: %s" % (name, witness))

    def test_buggy_model_violates_no_double_charge(self):
        prop = invariants.get("no_double_charge", n=1).expression
        violated, witness = _exists_violation(prop, self.buggy)
        self.assertTrue(violated,
                        "buggy payment should violate no_double_charge")
        # the seeded regression is a *double* charge: charges saturates at 2
        self.assertEqual(witness.get("charges"), 2,
                         "witness should show a double-charged order: %s"
                         % witness)

    def test_buggy_model_discriminators_still_hold(self):
        # These hold in *both* variants: they must be real properties,
        # not a vacuous PASS.
        for name in ("charge_requires_order", "settle_requires_charge"):
            prop = invariants.get(name, n=1).expression
            ok, witness = _forall(prop, self.buggy)
            self.assertTrue(ok, "buggy payment should still satisfy %s, "
                                "but found: %s" % (name, witness))

    def test_invariant_registrations(self):
        inv = invariants.get("no_double_charge", n=1)
        self.assertTrue(inv.pinned,
                        "no_double_charge is the blocking gate; it must be pinned")
        self.assertIn(inv.label, invariants.BLOCKING_LABELS)
        self.assertEqual(inv.rung, invariants.RUNG_E2E)


class MergeRequestGateTests(unittest.TestCase):
    """End-to-end: the MR gate BLOCKS the regression and PASSES the no-op."""

    def test_evaluate_mr_blocks_payment_regression(self):
        verdict = evaluate_mr("payment-correct", "payment-buggy", n=1)
        self.assertEqual(verdict.verdict, BLOCK)
        by_name = {r.name: r for r in verdict.invariants}
        self.assertIn("no_double_charge", by_name)
        ndc = by_name["no_double_charge"]
        self.assertFalse(ndc.violated_before,
                         "no_double_charge must hold on the baseline")
        self.assertTrue(ndc.violated_after,
                        "no_double_charge must be violated on the candidate")
        self.assertTrue(ndc.blocking)
        self.assertTrue(ndc.regression)
        self.assertTrue(ndc.witness_path,
                        "a blocked invariant must carry a replayable witness path")
        # the discriminator invariants are unaffected by the change
        for name in ("charge_requires_order", "settle_requires_charge"):
            self.assertFalse(by_name[name].violated_after,
                             "%s must hold on both variants" % name)
            self.assertFalse(by_name[name].regression)
        # the gate ships a deterministic failing test for the regression
        self.assertIsNotNone(verdict.deterministic)
        self.assertEqual(verdict.deterministic.invariant_name,
                         "no_double_charge")
        self.assertTrue(verdict.deterministic.path)

    def test_evaluate_mr_passes_unchanged_pair(self):
        verdict = evaluate_mr("payment-correct", "payment-correct", n=1)
        self.assertEqual(verdict.verdict, PASS)
        for r in verdict.invariants:
            self.assertFalse(r.violated_after)
            self.assertFalse(r.regression)


if __name__ == "__main__":
    unittest.main(verbosity=2)