# -*- coding: utf-8 -*-
"""Tests for the MCP Manifest v1 structural audit in :mod:`rot.mcp_adapter`.

This is the Phase B, B2 half of the MCP adoption surface: the two pure
structural checks (field permission + tenant isolation) and their mapping to
the Cedar-AR ``Overly Permissive`` finding, the ``audit_manifest`` entry
point, the exit-code mapping, and the manifest narrative.

Covers:
  * ``_field_tenant`` / ``_is_cross_tenant`` (tenant-namespace parsing);
  * ``manifest_findings`` -- the two checks in isolation and combined;
  * ``audit_manifest`` -- report shape, result/exit-code mapping, determinism;
  * ``render_narrative`` -- the manifest provenance + PASS/BLOCK wording.

Run: python tests/test_mcp_manifest_adapter.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.mcp_adapter as mcp  # noqa: E402
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


# A compliant manifest: writes within the write set, reads within the tenant.
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

# Over-permissive write: writes account.ssn, which is not in the write set.
_OVERWRITE = _manifest(
    ["account.balance"],
    [{"name": "leaky",
      "write_fields": ["account.balance", "account.ssn"]}],
)

# Cross-tenant read: reads a field namespaced under another tenant.
_CROSSREAD = _manifest(
    ["account.balance"],
    [{"name": "spy",
      "read_fields": ["tenant:acme.account.balance",
                      "tenant:globex.account.balance"]}],
)


class FieldTenantTests(unittest.TestCase):
    def test_tenant_namespaced_field(self):
        self.assertEqual(mcp._field_tenant("tenant:acme.account.balance"),
                         "tenant:acme")

    def test_tenant_namespaced_field_no_dot(self):
        self.assertEqual(mcp._field_tenant("tenant:acme"), "tenant:acme")

    def test_global_field_is_none(self):
        self.assertIsNone(mcp._field_tenant("account.balance"))

    def test_non_string_is_none(self):
        self.assertIsNone(mcp._field_tenant(42))


class CrossTenantTests(unittest.TestCase):
    def test_global_field_never_cross_tenant(self):
        self.assertFalse(mcp._is_cross_tenant("account.balance",
                                              "tenant:acme"))

    def test_same_tenant_not_cross(self):
        self.assertFalse(mcp._is_cross_tenant(
            "tenant:acme.account.balance", "tenant:acme"))

    def test_different_tenant_is_cross(self):
        self.assertTrue(mcp._is_cross_tenant(
            "tenant:globex.account.balance", "tenant:acme"))

    def test_none_scope_makes_tenant_read_cross(self):
        # A tool bound to no tenant reading a tenant-namespaced field is
        # out of scope (fail-closed).
        self.assertTrue(mcp._is_cross_tenant(
            "tenant:acme.account.balance", None))


class ManifestFindingsTests(unittest.TestCase):
    def test_good_manifest_no_findings(self):
        self.assertEqual(mcp.manifest_findings(_GOOD), [])

    def test_overwrite_single_finding(self):
        findings = mcp.manifest_findings(_OVERWRITE)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.finding, mcp.FINDING_OVERLY_PERMISSIVE)
        self.assertEqual(f.property_name, "field_write_permission")
        self.assertEqual(f.severity, mcp.SEVERITY_ERROR)
        self.assertEqual(f.witness["over_permission"], ["account.ssn"])

    def test_crossread_single_finding(self):
        findings = mcp.manifest_findings(_CROSSREAD)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.finding, mcp.FINDING_OVERLY_PERMISSIVE)
        self.assertEqual(f.property_name, "tenant_read_isolation")
        self.assertEqual(f.witness["cross_tenant_fields"],
                         ["tenant:globex.account.balance"])

    def test_both_violations_two_findings(self):
        manifest = _manifest(
            ["account.balance"],
            [{"name": "leaky",
              "read_fields": ["tenant:globex.account.balance"],
              "write_fields": ["account.ssn"]}],
        )
        findings = mcp.manifest_findings(manifest)
        self.assertEqual(len(findings), 2)
        props = [f.property_name for f in findings]
        self.assertEqual(props, ["field_write_permission",
                                 "tenant_read_isolation"])

    def test_global_read_field_not_flagged(self):
        # A global (un-namespaced) read is never a cross-tenant read.
        manifest = _manifest(
            ["account.balance"],
            [{"name": "reader", "read_fields": ["account.balance"]}],
        )
        self.assertEqual(mcp.manifest_findings(manifest), [])

    def test_empty_write_set_permits_no_writes(self):
        # Fail-closed: with an empty allowed_write set, any write is a
        # violation.
        manifest = _manifest(
            [],
            [{"name": "writer", "write_fields": ["account.balance"]}],
        )
        findings = mcp.manifest_findings(manifest)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].property_name, "field_write_permission")


class AuditManifestTests(unittest.TestCase):
    def test_good_manifest_pass(self):
        report = mcp.audit_manifest(_GOOD)
        self.assertIsInstance(report, mcp.McpFindingsReport)
        self.assertFalse(report.has_findings())
        self.assertEqual(report.result(), "proven")
        self.assertEqual(report.exit_code(), 0)
        self.assertFalse(report.any_unknown)

    def test_bad_manifest_block(self):
        manifest = _manifest(
            ["account.balance"],
            [{"name": "leaky",
              "read_fields": ["tenant:globex.account.balance"],
              "write_fields": ["account.ssn"]}],
        )
        report = mcp.audit_manifest(manifest)
        self.assertTrue(report.has_findings())
        self.assertEqual(report.result(), "violated")
        self.assertEqual(report.exit_code(), 1)

    def test_report_carries_manifest_provenance(self):
        report = mcp.audit_manifest(_GOOD)
        self.assertEqual(report.policy["server"], "caravel-agent-tools")
        self.assertEqual(report.policy["tenant_scope"], "tenant:acme")
        self.assertEqual(report.policy["allowed_write_fields"],
                         ["account.balance"])
        self.assertIn("hash", report.policy)
        self.assertEqual(report.tools, ["get_balance", "update_balance"])

    def test_facets_are_skipped_stubs(self):
        report = mcp.audit_manifest(_GOOD)
        for facet in ("safety", "liveness", "conformance"):
            self.assertEqual(report.facets[facet]["status"], "skipped")

    def test_to_json_deterministic(self):
        r1 = mcp.audit_manifest(_GOOD).to_json()
        r2 = mcp.audit_manifest(_GOOD).to_json()
        self.assertEqual(r1, r2)
        self.assertIsInstance(json.loads(r1), dict)

    def test_manifest_hash_stable(self):
        self.assertEqual(mcp._manifest_hash(_GOOD),
                         mcp._manifest_hash(_GOOD))


class NarrativeTests(unittest.TestCase):
    def test_pass_narrative_manifest_wording(self):
        text = mcp.render_narrative(mcp.audit_manifest(_GOOD))
        self.assertIn("manifest server=caravel-agent-tools", text)
        self.assertIn("RESULT: PASS", text)
        self.assertIn("field and tenant structural checks clean", text)
        self.assertNotIn("all three facets proven", text)

    def test_block_narrative_lists_findings(self):
        manifest = _manifest(
            ["account.balance"],
            [{"name": "leaky",
              "read_fields": ["tenant:globex.account.balance"],
              "write_fields": ["account.ssn"]}],
        )
        text = mcp.render_narrative(mcp.audit_manifest(manifest))
        self.assertIn("RESULT: BLOCK -- 2 Cedar-AR finding(s)", text)
        self.assertIn("Overly Permissive", text)
        self.assertIn("field_write_permission", text)
        self.assertIn("tenant_read_isolation", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)

