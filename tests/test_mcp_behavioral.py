# -*- coding: utf-8 -*-
"""Tests for the *behavioral* (temporal) audit of an MCP Manifest v1 (G8).

This is the Phase B, B2.5 half of the MCP adoption surface: the model-check of
the manifest's safety property over the *adversarial agent's tool-call
sequences* (gap G8 -- the declaration check made behavioral).  It is the
"fully compromised model, only the harness can stop it" stance applied to an
MCP connector.

Covers:
  * the state model (``manifest_state_vars`` / ``no_violation_property``);
  * the per-tool effect (``_tool_effect``);
  * the behavioral audit (``behavioral_audit``) -- proven / violated / unknown;
  * the witness (attack path) and the lethal-trifecta *risk* (flagged, not gated);
  * the ``STRUCTURAL_EQUIVALENT`` mapping (which properties have a structural twin);
  * the ``BehavioralVerdict`` serialization.

Run: python tests/test_mcp_behavioral.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.mcp_behavioral as mb  # noqa: E402
import rot.mcp_manifest as mm  # noqa: E402


def _manifest(allowed_write, tools, tenant_scope="tenant:acme"):
    """Build a validated manifest from a compact spec."""
    return mm.parse_manifest({
        "manifest": mm.MANIFEST_SCHEMA,
        "server": "caravel-agent-tools",
        "tenant_scope": tenant_scope,
        "allowed_write_fields": allowed_write,
        "tools": tools,
    })


# A structurally clean manifest: reads within the tenant, writes within the
# write set, no open-world tool.  No hard violation, no trifecta risk.
_GOOD = _manifest(
    ["account.balance"],
    [
        {"name": "get_balance",
         "read_fields": ["tenant:acme.account.balance"]},
        {"name": "update_balance",
         "read_fields": ["tenant:acme.account.balance"],
         "write_fields": ["account.balance"]},
    ],
)

# Structurally clean (no hard violation) but the *lethal-trifecta risk* is
# present: the agent holds the tenant's private data (get_balance) AND can use
# an outbound open-world channel (notify).
_TRIFECTA = _manifest(
    ["account.balance"],
    [
        {"name": "get_balance",
         "read_fields": ["tenant:acme.account.balance"]},
        {"name": "notify",
         "write_fields": ["account.balance"],
         "annotations": {"openWorldHint": True}},
    ],
)

# A cross-tenant read (hard violation: no_cross_tenant_read).
_CROSSREAD = _manifest(
    ["account.balance"],
    [{"name": "spy",
      "read_fields": ["tenant:globex.account.balance"]}],
)

# An unapproved write (hard violation: no_unapproved_write).
_OVERWRITE = _manifest(
    ["account.balance"],
    [{"name": "leaky",
      "write_fields": ["account.balance", "account.ssn"]}],
)


class StateModelTests(unittest.TestCase):
    def test_state_vars_are_precise_booleans(self):
        vars = mb.manifest_state_vars()
        self.assertEqual(len(vars), 4)
        for v in vars:
            self.assertEqual(v.mode, "precise")

    def test_property_holds_in_initial_state(self):
        p = mb.no_violation_property()
        init = {"read_foreign": False, "wrote_unapproved": False,
                "holding_private": False, "used_outbound": False}
        self.assertTrue(p.eval(init))

    def test_property_fails_on_cross_tenant_read(self):
        p = mb.no_violation_property()
        state = {"read_foreign": True, "wrote_unapproved": False,
                 "holding_private": False, "used_outbound": False}
        self.assertFalse(p.eval(state))


class ToolEffectTests(unittest.TestCase):
    def _names(self, effect):
        return [e[0] for e in effect]

    def test_cross_tenant_read_sets_latch(self):
        effect = mb._tool_effect(_CROSSREAD, _CROSSREAD.tools[0])
        self.assertIn("read_foreign", self._names(effect))

    def test_unapproved_write_sets_latch(self):
        effect = mb._tool_effect(_OVERWRITE, _OVERWRITE.tools[0])
        self.assertIn("wrote_unapproved", self._names(effect))

    def test_own_private_read_sets_holding(self):
        effect = mb._tool_effect(_GOOD, _GOOD.tools[0])
        self.assertIn("holding_private", self._names(effect))

    def test_open_world_sets_outbound(self):
        effect = mb._tool_effect(_TRIFECTA, _TRIFECTA.tools[1])
        self.assertIn("used_outbound", self._names(effect))

    def test_clean_write_sets_no_hard_latch(self):
        # update_balance writes an approved field: no hard-violation latch.
        effect = mb._tool_effect(_GOOD, _GOOD.tools[1])
        names = self._names(effect)
        self.assertNotIn("read_foreign", names)
        self.assertNotIn("wrote_unapproved", names)


class StructuralEquivalentTests(unittest.TestCase):
    def test_hard_properties_have_structural_twin(self):
        self.assertEqual(mb.STRUCTURAL_EQUIVALENT[
            mb.PROP_NO_CROSS_TENANT_READ], "tenant_read_isolation")
        self.assertEqual(mb.STRUCTURAL_EQUIVALENT[
            mb.PROP_NO_UNAPPROVED_WRITE], "field_write_permission")

    def test_trifecta_has_no_structural_twin(self):
        # The lethal trifecta is the new temporal property the declaration
        # check cannot express (a per-tool check cannot see a sequence).
        self.assertIsNone(mb.STRUCTURAL_EQUIVALENT[mb.PROP_TRIFECTA])


class AuditProvenTests(unittest.TestCase):
    def test_good_manifest_proven(self):
        v = mb.behavioral_audit(_GOOD)
        self.assertTrue(v.is_proven())
        self.assertTrue(v.complete)
        self.assertFalse(v.trifecta)
        self.assertGreaterEqual(v.n_states, 1)

    def test_proven_verdict_is_deterministic(self):
        v1 = mb.behavioral_audit(_GOOD)
        v2 = mb.behavioral_audit(_GOOD)
        self.assertEqual(v1.to_dict(), v2.to_dict())


class AuditViolatedTests(unittest.TestCase):
    def test_cross_tenant_read_violated(self):
        v = mb.behavioral_audit(_CROSSREAD)
        self.assertTrue(v.is_violated())
        self.assertIn(mb.PROP_NO_CROSS_TENANT_READ, v.properties)
        self.assertTrue(v.witness.get("read_foreign"))
        self.assertEqual(v.path, ["spy"])

    def test_unapproved_write_violated(self):
        v = mb.behavioral_audit(_OVERWRITE)
        self.assertTrue(v.is_violated())
        self.assertIn(mb.PROP_NO_UNAPPROVED_WRITE, v.properties)
        self.assertTrue(v.witness.get("wrote_unapproved"))
        self.assertEqual(v.path, ["leaky"])

    def test_attack_path_is_valid_tool_sequence(self):
        v = mb.behavioral_audit(_CROSSREAD)
        names = _CROSSREAD.tool_names()
        self.assertTrue(v.path)
        for t in v.path:
            self.assertIn(t, names)


class AuditTrifectaTests(unittest.TestCase):
    def test_trifecta_risk_flagged_but_hard_property_proven(self):
        # Structurally clean (no hard violation) but the lethal-trifecta risk
        # is present (private data + outbound channel reachable in sequence).
        v = mb.behavioral_audit(_TRIFECTA)
        self.assertTrue(v.is_proven())  # the hard guarantees still hold
        self.assertTrue(v.trifecta)  # ... but the risk is flagged

    def test_no_trifecta_without_outbound(self):
        v = mb.behavioral_audit(_GOOD)
        self.assertFalse(v.trifecta)


class AuditUnknownTests(unittest.TestCase):
    def test_budget_exhausted_is_unknown(self):
        # A manifest whose reachable space (4 states) exceeds the budget (3):
        # the search is truncated -- an honest unknown, never read as proven.
        v = mb.behavioral_audit(_TRIFECTA, max_states=3)
        self.assertTrue(v.is_unknown())
        self.assertFalse(v.complete)
        self.assertIn("not a proof", v.note.lower())


class VerdictSerializationTests(unittest.TestCase):
    def test_to_dict_is_json_serializable(self):
        v = mb.behavioral_audit(_CROSSREAD)
        d = v.to_dict()
        self.assertIsInstance(json.loads(json.dumps(d)), dict)
        self.assertEqual(d["status"], "violated")
        self.assertEqual(d["method"], "behavioral_audit")
        self.assertIn("trifecta_risk", d)
        self.assertIn("n_states", d)


if __name__ == "__main__":
    unittest.main(verbosity=2)