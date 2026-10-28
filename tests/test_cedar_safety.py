# -*- coding: utf-8 -*-
"""Cedar safety + non-vacuity property tests (G2 -- "Flip Cedar to safety").

The front-end (``rot.frontends.cedar``) compiles Cedar policy text into the IR,
exposing the bounded request space together with two precise signals written by
the ``decide`` action:

  * ``decision``  -- the final verdict (True = permitted);
  * ``forbidden`` -- the raw disjunction of the ``forbid`` rules.

``rot.policy_verify`` then checks two *complementary* properties over the whole
bounded request space (a sweep, not a single witness):

  * ``policy_denies_forbidden`` -- **safety (universal)**: for *every* reachable
    request, a matching ``forbid`` rule implies the verdict is Deny.  This is the
    "forbid rules hold / permit rules don't over-grant" check -- the direction a
    realizability-only query cannot express.
  * ``policy_permits_request``  -- **non-vacuity (existential)**: there *exists*
    a reachable request whose verdict is Permit.  The policy is not vacuous.

These tests pin that contract end-to-end: they parse Cedar, build the IR, and
ask the verifier to sweep the bounded request space in both directions.  They
cover the ``forbidden`` signal (present, boolean, precise), the safety property
(holds for well-formed policies -- including forbid-overrides-permit -- and
*violates with a concrete counterexample* on a hand-built inconsistent IR), and
the non-vacuity twin (SAT when the policy permits a request, UNSAT when it
permits none).

Run: python tests/test_cedar_safety.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir
from rot.frontends.cedar import parse_cedar
from rot.frontends.policy import build_ir as pkg_build_ir
from rot.frontends.policy import cedar as cedar_adapter
from rot.modelfind import SAT, UNSAT
from rot.policy_verify import policy_denies_forbidden, policy_permits_request


def _forbidden_var(p):
    """Return the list of ``forbidden`` StateVars from the IR."""
    return [v for v in p.variables if v.name == "forbidden"]


def _inconsistent_ir():
    """Build a hand-authored IR that is *inconsistent* with Cedar semantics.

    The initial state has ``forbidden=True`` yet ``decision=True`` -- a
    forbidden request that is nevertheless permitted.  No Cedar source can
    produce this (the front-end always folds the forbid rules into the
    decision), so this is a *model* that violates the safety property.  It is
    the counterexample the verifier must find.
    """
    variables = [
        ir.StateVar("forbidden", ir.Bool(), mode=ir.MODE_PRECISE,
                    desc="forbid-rule match"),
        ir.StateVar("decision", ir.Bool(), mode=ir.MODE_PRECISE,
                    desc="policy decision"),
    ]
    actions = [
        ir.Action(name="init", owner="test", is_initial=True, guard=ir.T(),
                  effects=[("forbidden", ir.T()), ("decision", ir.T())]),
    ]
    return ir.ProtocolIR(name="inconsistent", variables=variables,
                         actions=actions, init=ir.T())


class ForbiddenSignalTests(unittest.TestCase):
    def test_forbidden_var_present(self):
        p = parse_cedar('permit(principal, action, resource) when { true };')
        self.assertTrue(_forbidden_var(p),
                        "the IR must expose the ``forbidden`` signal")

    def test_forbidden_var_is_bool(self):
        p = parse_cedar('permit(principal, action, resource) when { true };')
        (v,) = _forbidden_var(p)
        self.assertIsInstance(v.domain, ir.Bool)

    def test_forbidden_var_is_precise(self):
        p = parse_cedar('permit(principal, action, resource) when { true };')
        (v,) = _forbidden_var(p)
        self.assertEqual(v.mode, ir.MODE_PRECISE)


class SafetyTests(unittest.TestCase):
    def test_forbid_overrides_permit_is_safe(self):
        # A permit and a forbid that match the same request: the forbid wins,
        # so the request is denied.  Safety must hold (no forbidden request is
        # permitted), and the policy must be vacuous (nothing is permitted).
        p = parse_cedar(
            'action transfer;\n'
            'permit(principal, action, resource) when { action == "transfer" };\n'
            'forbid(principal, action, resource) when { action == "transfer" };')
        status, detail = policy_denies_forbidden(p)
        self.assertEqual(status, True, "forbid-overrides-permit must be safe")
        self.assertIsNone(detail)
        # And the twin: the policy permits nothing (the only permit is vetoed).
        self.assertEqual(policy_permits_request(p)[0], UNSAT)

    def test_safety_holds_when_no_forbid_rules(self):
        # No forbid rules: ``forbidden`` is False everywhere, so the safety
        # property holds vacuously.  The policy does permit a request.
        p = parse_cedar(
            'action transfer;\n'
            'permit(principal, action, resource) when { action == "transfer" };')
        status, detail = policy_denies_forbidden(p)
        self.assertEqual(status, True)
        self.assertIsNone(detail)
        self.assertEqual(policy_permits_request(p)[0], SAT)

    def test_safety_holds_when_forbid_is_narrower(self):
        # A forbid that matches a *different* action than the permit: the
        # permitted action is not forbidden, so it stays permitted, and the
        # forbidden action is denied.  Safety holds and the policy is non-vacuous.
        p = parse_cedar(
            'action transfer;\n'
            'action withdraw;\n'
            'permit(principal, action, resource) when { action == "transfer" };\n'
            'forbid(principal, action, resource) when { action == "withdraw" };')
        status, detail = policy_denies_forbidden(p)
        self.assertEqual(status, True, "narrower forbid must not break safety")
        self.assertIsNone(detail)
        # "transfer" is still permitted (the forbid only covers "withdraw").
        self.assertEqual(policy_permits_request(p)[0], SAT)

    def test_safety_violated_returns_concrete_counterexample(self):
        # A hand-built IR where a forbidden request is nonetheless permitted.
        # The verifier must refute the safety property and name the offending
        # request (the counterexample carries the violating assignment).
        bad = _inconsistent_ir()
        status, counter = policy_denies_forbidden(bad)
        self.assertEqual(status, False, "inconsistent IR must refute safety")
        self.assertIsNotNone(counter, "a violation must carry a counterexample")
        self.assertIs(counter.get("forbidden"), True)
        self.assertIs(counter.get("decision"), True)


class NonVacuityTwinTests(unittest.TestCase):
    def test_permits_when_a_request_matches(self):
        p = parse_cedar(
            'action transfer;\n'
            'permit(principal, action, resource) when { action == "transfer" };')
        status, witness = policy_permits_request(p)
        self.assertEqual(status, SAT)
        self.assertIsNotNone(witness, "a SAT result must carry a witness")
        self.assertIs(witness.get("decision"), True)

    def test_unsat_when_everything_is_forbidden(self):
        p = parse_cedar('forbid(principal, action, resource) when { true };')
        self.assertEqual(policy_permits_request(p)[0], UNSAT)

    def test_safety_and_nonvacuity_are_independent(self):
        # A policy can be *safe* (forbids hold) while *vacuous* (permits
        # nothing) -- the two properties check different directions.
        p = parse_cedar(
            'action transfer;\n'
            'forbid(principal, action, resource) when { action == "transfer" };')
        self.assertEqual(policy_denies_forbidden(p)[0], True)
        self.assertEqual(policy_permits_request(p)[0], UNSAT)


class AdapterPinTests(unittest.TestCase):
    """The front-end adapter (``rot.frontends.policy.cedar``) pins the twin
    properties; the package dispatcher routes ``kind`` to the right adapter."""

    @staticmethod
    def _write_cedar(source):
        fd, path = tempfile.mkstemp(suffix=".cedar")
        with os.fdopen(fd, "w") as fh:
            fh.write(source)
        return path

    def test_adapter_pins_safety_property(self):
        path = self._write_cedar(
            'action transfer;\n'
            'permit(principal, action, resource) when { action == "transfer" };\n'
            'forbid(principal, action, resource) when { action == "withdraw" };')
        try:
            model = cedar_adapter.build_ir(path, kind="safety")
        finally:
            os.remove(path)
        self.assertEqual(model.metadata["property_kind"], "safety")
        self.assertEqual(model.metadata["property_name"],
                         "policy_denies_forbidden")
        # The pinned predicate is ``forbidden -> not decision``: it must be
        # False exactly when a forbidden request is permitted.
        prop = model.pinned_property
        self.assertIs(prop.eval({"forbidden": True, "decision": True}), False)
        self.assertIs(prop.eval({"forbidden": True, "decision": False}), True)
        self.assertIs(prop.eval({"forbidden": False, "decision": True}), True)
        self.assertIs(prop.eval({"forbidden": False, "decision": False}), True)
        model.validate()

    def test_adapter_default_is_realizability(self):
        # Backward compatibility: no ``kind`` -> the non-vacuity twin.
        path = self._write_cedar(
            'action transfer;\n'
            'permit(principal, action, resource) when { action == "transfer" };')
        try:
            model = cedar_adapter.build_ir(path)
        finally:
            os.remove(path)
        self.assertEqual(model.metadata["property_kind"], "realizability")
        self.assertEqual(model.metadata["property_name"],
                         "policy_permits_request")
        # The pinned predicate is ``decision == True``.
        self.assertIs(model.pinned_property.eval({"decision": True}), True)
        self.assertIs(model.pinned_property.eval({"decision": False}), False)

    def test_adapter_rejects_unknown_kind(self):
        path = self._write_cedar(
            'permit(principal, action, resource) when { true };')
        try:
            with self.assertRaises(cedar_adapter.CedarFrontendError):
                cedar_adapter.build_ir(path, kind="liveness")
        finally:
            os.remove(path)

    def test_package_dispatcher_routes_cedar_safety(self):
        path = self._write_cedar(
            'action transfer;\n'
            'permit(principal, action, resource) when { action == "transfer" };')
        try:
            model = pkg_build_ir(path, kind="safety")
        finally:
            os.remove(path)
        self.assertEqual(model.metadata["family"], "CEDAR_POLICY")
        self.assertEqual(model.metadata["property_kind"], "safety")
        self.assertEqual(model.metadata["property_name"],
                         "policy_denies_forbidden")

    def test_package_dispatcher_routes_cedar_default_realizability(self):
        path = self._write_cedar(
            'action transfer;\n'
            'permit(principal, action, resource) when { action == "transfer" };')
        try:
            model = pkg_build_ir(path)
        finally:
            os.remove(path)
        self.assertEqual(model.metadata["family"], "CEDAR_POLICY")
        self.assertEqual(model.metadata["property_kind"], "realizability")
        self.assertEqual(model.metadata["property_name"],
                         "policy_permits_request")

    def test_adapter_safety_pin_discharges_via_model_finder(self):
        # End-to-end: the adapter's safety pin is a real, checkable predicate
        # over the bounded request space -- the model finder proves it holds
        # for a well-formed policy (forbid rules hold, no over-granting).
        from rot.modelfind import ModelFinder
        path = self._write_cedar(
            'action transfer;\n'
            'action withdraw;\n'
            'permit(principal, action, resource) when { action == "transfer" };\n'
            'forbid(principal, action, resource) when { action == "withdraw" };')
        try:
            model = cedar_adapter.build_ir(path, kind="safety")
            ok, counter = ModelFinder.from_ir(model).forall_reachable(
                lambda s: model.pinned_property.eval(s))
        finally:
            os.remove(path)
        self.assertIs(ok, True, "a well-formed policy must discharge safety")
        self.assertIsNone(counter)


if __name__ == "__main__":
    unittest.main(verbosity=2)