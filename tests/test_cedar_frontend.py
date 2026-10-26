# -*- coding: utf-8 -*-
"""Cedar front-end tests (Cedar policy source -> ``rot.ir.ProtocolIR``).

The front-end (``rot.frontends.cedar``) is the "narrow-waist" compiler half:
it turns Cedar policy text into the IR that ``rot.modelfind`` / ``rot.sat``
consume.  The IR exposes the request -- ``principal`` / ``action`` /
``resource`` plus one existential variable per attribute read -- and a final
``decision`` variable that the policy set evaluates into.  Cedar is
default-deny and ``forbid`` overrides ``permit``, so ``decision`` is ``True``
iff some permit policy matches and no forbid policy matches.

These tests pin that contract end-to-end: they parse Cedar, build the IR, and
ask the model finder whether a permitted (``decision is True``) state is
reachable.  They cover the policy shape (request slots, staged picks, the
``decide`` action, declared ``action``/``entity`` declarations, attribute
variables), the semantics (permit, default-deny, forbid-overrides-permit,
arithmetic over existential attribute values, boolean operators, ``is`` /
``in`` / ``has``), and the error surface (``CedarError`` with line numbers).

Run: python tests/test_cedar_frontend.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir
from rot.frontends.cedar import CedarError, parse_cedar, parse_cedar_file
from rot.modelfind import ModelFinder


def _allowed(irp):
    """Whether a permitted request (``decision is True``) is reachable."""
    return ModelFinder.from_ir(irp).exists_reachable(
        lambda s: s.get("decision") is True)[0]


class IrStructureTests(unittest.TestCase):
    def test_returns_protocol_ir(self):
        p = parse_cedar('permit(principal, action, resource) when { action == "transfer" };')
        self.assertIsInstance(p, ir.ProtocolIR)

    def test_request_slots_and_decision_present(self):
        p = parse_cedar('permit(principal, action, resource) when { true };')
        names = [v.name for v in p.variables]
        for req in ("stage", "principal", "action", "resource", "decision"):
            self.assertIn(req, names)

    def test_decision_var_is_bool(self):
        p = parse_cedar('permit(principal, action, resource) when { true };')
        d = [v for v in p.variables if v.name == "decision"][0]
        self.assertIsInstance(d.domain, ir.Bool)

    def test_request_slots_are_existential(self):
        p = parse_cedar('permit(principal, action, resource) when { true };')
        for name in ("principal", "action", "resource"):
            v = [x for x in p.variables if x.name == name][0]
            self.assertEqual(v.mode, ir.MODE_EXISTENTIAL)

    def test_staged_picks_and_decide_action(self):
        p = parse_cedar('permit(principal, action, resource) when { true };')
        names = [a.name for a in p.actions]
        self.assertIn("init", names)
        self.assertIn("decide", names)
        self.assertTrue(any(n.startswith("pick_principal_") for n in names))
        self.assertTrue(any(n.startswith("pick_action_") for n in names))
        self.assertTrue(any(n.startswith("pick_resource_") for n in names))

    def test_single_initial_action(self):
        p = parse_cedar('permit(principal, action, resource) when { true };')
        initials = [a for a in p.actions if a.is_initial]
        self.assertEqual(len(initials), 1)
        self.assertEqual(initials[0].name, "init")

    def test_declared_action_extends_request_universe(self):
        p = parse_cedar('action transfer;\n'
                        'permit(principal, action, resource) when { action == "transfer" };')
        act = [v for v in p.variables if v.name == "action"][0]
        self.assertIn("transfer", list(act.domain.values))

    def test_attribute_read_creates_existential_var(self):
        p = parse_cedar('permit(principal, action, resource) when { resource.amount > 100 };')
        v = [x for x in p.variables if x.name == "resource.amount"]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].mode, ir.MODE_EXISTENTIAL)


class SemanticsTests(unittest.TestCase):
    def test_permit_is_reachable(self):
        p = parse_cedar('action transfer;\n'
                        'permit(principal, action, resource) when { action == "transfer" };')
        self.assertEqual(_allowed(p), ir.SAT)

    def test_default_deny_with_no_policies(self):
        self.assertEqual(_allowed(parse_cedar('')), ir.UNSAT)

    def test_forbid_overrides_permit(self):
        p = parse_cedar(
            'action transfer;\n'
            'permit(principal, action, resource) when { action == "transfer" };\n'
            'forbid(principal, action, resource) when { action == "transfer" };')
        self.assertEqual(_allowed(p), ir.UNSAT)

    def test_forbid_only_is_deny(self):
        p = parse_cedar(
            'action transfer;\n'
            'forbid(principal, action, resource) when { action == "transfer" };')
        self.assertEqual(_allowed(p), ir.UNSAT)

    def test_attribute_threshold_sat_and_complement_sat(self):
        self.assertEqual(
            _allowed(parse_cedar(
                'permit(principal, action, resource) when { resource.amount > 100 };')),
            ir.SAT)
        self.assertEqual(
            _allowed(parse_cedar(
                'permit(principal, action, resource) when { resource.amount <= 100 };')),
            ir.SAT)

    def test_conjunction_sat_and_unsat(self):
        sat = parse_cedar(
            'permit(principal, action, resource) when { resource.amount > 100 && resource.amount < 200 };')
        unsat = parse_cedar(
            'permit(principal, action, resource) when { resource.amount > 100 && resource.amount < 0 };')
        self.assertEqual(_allowed(sat), ir.SAT)
        self.assertEqual(_allowed(unsat), ir.UNSAT)

    def test_disjunction(self):
        p = parse_cedar(
            'action a;\naction b;\n'
            'permit(principal, action, resource) when { action == "a" || action == "b" };')
        self.assertEqual(_allowed(p), ir.SAT)

    def test_negation(self):
        p = parse_cedar('permit(principal, action, resource) when { action != "ghost" };')
        self.assertEqual(_allowed(p), ir.SAT)

    def test_is_subtype_reaches(self):
        p = parse_cedar(
            'entity Person;\n'
            'entity User in Person;\n'
            'permit(principal, action, resource) when { principal is Person };')
        self.assertEqual(_allowed(p), ir.SAT)

    def test_in_type_reaches(self):
        p = parse_cedar(
            'entity Person;\n'
            'entity User in Person;\n'
            'permit(principal, action, resource) when { principal in Person };')
        self.assertEqual(_allowed(p), ir.SAT)

    def test_has_attribute_holds(self):
        p = parse_cedar('permit(principal, action, resource) when { resource has balance };')
        self.assertEqual(_allowed(p), ir.SAT)

    def test_contains_operator(self):
        p = parse_cedar(
            'permit(principal, action, resource) when { resource.tags contains "admin" };')
        self.assertEqual(_allowed(p), ir.SAT)
        # The compared value is folded into the attribute's existential domain.
        v = [x for x in p.variables if x.name == "resource.tags"][0]
        self.assertIn("admin", list(v.domain.values))

    def test_contains_contradiction_is_unsat(self):
        # Two different ``contains`` values on one scalar attribute cannot
        # both hold, so the permit is unreachable (a real constraint, not a
        # trivially-true read).
        p = parse_cedar(
            'permit(principal, action, resource) when { '
            'resource.tags contains "admin" && resource.tags contains "secret" };')
        self.assertEqual(_allowed(p), ir.UNSAT)

    def test_bool_attribute_conjunction(self):
        p = parse_cedar(
            'permit(principal, action, resource) when { resource.flag && resource.amount > 0 };')
        self.assertEqual(_allowed(p), ir.SAT)

    def test_parenthesization(self):
        p = parse_cedar(
            'action a;\n'
            'permit(principal, action, resource) when { (action == "a" && resource.amount > 0) || (action == "a" && resource.amount < 0) };')
        self.assertEqual(_allowed(p), ir.SAT)


class ErrorTests(unittest.TestCase):
    def test_bad_policy_header(self):
        with self.assertRaises(CedarError):
            parse_cedar('foo(principal, action, resource) when { true };')

    def test_unknown_identifier(self):
        with self.assertRaises(CedarError):
            parse_cedar('permit(principal, action, resource) when { ghost == 1 };')

    def test_mismatched_paren(self):
        with self.assertRaises(CedarError):
            parse_cedar('permit(principal, action, resource when { true };')

    def test_error_carries_line_number(self):
        try:
            parse_cedar('permit(principal, action, resource when { true };')
            self.fail("expected CedarError")
        except CedarError as e:
            self.assertIn("line", str(e))

    def test_cedar_error_is_value_error(self):
        self.assertTrue(issubclass(CedarError, ValueError))


class ApiTests(unittest.TestCase):
    def test_parse_cedar_file_roundtrip(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "policy.cedar")
        with open(path, "w") as fh:
            fh.write('action transfer;\n'
                     'permit(principal, action, resource) when { action == "transfer" };')
        p = parse_cedar_file(path)
        self.assertIsInstance(p, ir.ProtocolIR)
        self.assertEqual(_allowed(p), ir.SAT)

    def test_package_reexports_public_api(self):
        import rot.frontends as f
        self.assertTrue(hasattr(f, "parse_cedar"))
        self.assertTrue(hasattr(f, "parse_cedar_file"))
        self.assertTrue(hasattr(f, "CedarError"))

    def test_parse_cedar_rejects_non_string(self):
        with self.assertRaises(CedarError):
            parse_cedar(12345)


if __name__ == "__main__":
    unittest.main(verbosity=2)