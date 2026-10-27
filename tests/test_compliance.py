# -*- coding: utf-8 -*-
"""Tests for :mod:`rot.compliance` (SOC 2 + AIUC control mapping).

Covers:
  * the finding -> control mapping (``controls_for``) for every Cedar-AR
    finding, including the property-specific refinements (CC6.1 vs CC6.3);
  * the deterministic, sorted ``controls_touched`` helper;
  * the ``compliance_section`` report shape (profile, frameworks, result,
    controls, evidence);
  * the ``--mcp`` (allowed/denied) report carrying per-finding ``controls`` and
    a ``compliance`` section;
  * the MCP Manifest v1 (Phase B) report carrying the same;
  * the narrative rendering showing the per-finding controls line;
  * the fail-closed behaviour (unknown finding -> ValueError);
  * JSON determinism of the compliance section.

Run: python tests/test_compliance.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.compliance as compliance  # noqa: E402
import rot.mcp_adapter as mcp  # noqa: E402
import rot.mcp_manifest as mcp_manifest  # noqa: E402


def _finding(finding, property_name):
    """A minimal valid :class:`rot.mcp_adapter.Finding` for a test."""
    return mcp.Finding(
        finding=finding,
        facet="policy",
        severity=mcp.SEVERITY_ERROR,
        property_name=property_name,
        message="test finding",
    )


class ControlsForTests(unittest.TestCase):
    """The finding -> control mapping (``controls_for``)."""

    def test_every_finding_maps_to_controls(self):
        for finding in mcp.ALL_FINDINGS:
            controls = compliance.controls_for(finding, "some_property")
            self.assertTrue(controls)
            self.assertIn("AIUC-1", controls)

    def test_overly_permissive_write_is_cc61(self):
        self.assertEqual(
            compliance.controls_for("Overly Permissive",
                                   "field_write_permission"),
            ["CC6.1", "AIUC-1"])

    def test_overly_permissive_cross_tenant_is_cc63(self):
        self.assertEqual(
            compliance.controls_for("Overly Permissive",
                                   "tenant_read_isolation"),
            ["CC6.3", "AIUC-1"])

    def test_overly_permissive_default_is_cc61(self):
        # A facet-derived Overly Permissive (no property refinement) -> CC6.1.
        self.assertEqual(
            compliance.controls_for("Overly Permissive", "policy_conformance"),
            ["CC6.1", "AIUC-1"])

    def test_contradictions_is_cc61(self):
        self.assertEqual(
            compliance.controls_for("contradictions",
                                   "allowed_denied_disjoint"),
            ["CC6.1", "AIUC-1"])

    def test_unreachable_rules_is_cc66(self):
        self.assertEqual(
            compliance.controls_for("unreachable rules", "tool_governed"),
            ["CC6.6", "AIUC-1"])

    def test_overly_restrictive_is_cc66(self):
        self.assertEqual(
            compliance.controls_for("Overly Restrictive", "liveness"),
            ["CC6.6", "AIUC-1"])

    def test_ineffective_is_cc66(self):
        self.assertEqual(
            compliance.controls_for("Ineffective", "conformance"),
            ["CC6.6", "AIUC-1"])

    def test_unknown_finding_raises(self):
        self.assertRaises(ValueError, compliance.controls_for, "bogus", "x")

    def test_none_property_falls_back_to_finding(self):
        self.assertEqual(
            compliance.controls_for("contradictions", None),
            ["CC6.1", "AIUC-1"])


class ControlsTouchedTests(unittest.TestCase):
    """The deterministic ``controls_touched`` helper."""

    def test_sorted_and_unique(self):
        findings = [
            _finding("Overly Permissive", "tenant_read_isolation"),
            _finding("unreachable rules", "tool_governed"),
            _finding("contradictions", "allowed_denied_disjoint"),
        ]
        touched = compliance.controls_touched(findings)
        self.assertEqual(touched, ["AIUC-1", "CC6.1", "CC6.3", "CC6.6"])

    def test_empty(self):
        self.assertEqual(compliance.controls_touched([]), [])

    def test_dedup(self):
        findings = [
            _finding("contradictions", "x"),
            _finding("Overly Permissive", "field_write_permission"),
        ]
        # Both map to CC6.1 + AIUC-1 -> deduped.
        self.assertEqual(compliance.controls_touched(findings),
                         ["AIUC-1", "CC6.1"])


class ComplianceSectionTests(unittest.TestCase):
    """The ``compliance_section`` report shape."""

    def test_shape(self):
        findings = [
            _finding("Overly Permissive", "field_write_permission"),
            _finding("Overly Permissive", "tenant_read_isolation"),
        ]
        section = compliance.compliance_section(findings, "violated")
        self.assertEqual(section["profile"], compliance.COMPLIANCE_PROFILE)
        self.assertEqual(section["frameworks"], ["SOC2", "AIUC"])
        self.assertEqual(section["result"], "violated")
        self.assertEqual(section["controls_touched"],
                         ["AIUC-1", "CC6.1", "CC6.3"])
        self.assertIn("CC6.1", section["controls"])
        self.assertIn("AIUC-1", section["controls"])
        self.assertEqual(section["evidence"]["findings_total"], 2)
        self.assertEqual(section["evidence"]["by_control"]["AIUC-1"], 2)

    def test_empty_findings(self):
        section = compliance.compliance_section([], "proven")
        self.assertEqual(section["controls_touched"], [])
        self.assertEqual(section["controls"], {})
        self.assertEqual(section["result"], "proven")
        self.assertEqual(section["evidence"]["findings_total"], 0)

    def test_json_deterministic(self):
        findings = [_finding("contradictions", "x")]
        a = json.dumps(compliance.compliance_section(findings, "violated"),
                       sort_keys=True)
        b = json.dumps(compliance.compliance_section(findings, "violated"),
                       sort_keys=True)
        self.assertEqual(a, b)


class McpReportComplianceTests(unittest.TestCase):
    """The ``--mcp`` report carries per-finding controls + a compliance section."""

    def test_finding_has_controls(self):
        # A contradictory policy -> contradictions finding.
        report = mcp.audit_mcp(["read_log"], ["read_log", "update_balance"])
        d = report.to_dict()
        self.assertTrue(d["findings"])
        for f in d["findings"]:
            self.assertIn("controls", f)
            self.assertTrue(f["controls"])

    def test_report_has_compliance(self):
        report = mcp.audit_mcp(["read_log"], ["read_log", "update_balance"])
        d = report.to_dict()
        self.assertIn("compliance", d)
        self.assertEqual(d["compliance"]["profile"],
                         compliance.COMPLIANCE_PROFILE)
        self.assertEqual(d["compliance"]["result"], d["summary"]["result"])

    def test_compliance_consistent_with_findings(self):
        report = mcp.audit_mcp(["read_log"], ["read_log", "update_balance"])
        d = report.to_dict()
        touched = set(d["compliance"]["controls_touched"])
        expected = set()
        for f in d["findings"]:
            expected.update(f["controls"])
        self.assertEqual(touched, expected)


class ManifestReportComplianceTests(unittest.TestCase):
    """The MCP Manifest v1 (Phase B) report carries the same."""

    def _manifest(self, tools):
        doc = {
            "manifest": "caravel.mcp-manifest/v1",
            "server": "caravel-agent-tools",
            "version": "1.0.0",
            "tenant_scope": "tenant:acme",
            "allowed_write_fields": ["account.balance"],
            "tools": tools,
        }
        return mcp_manifest.parse_manifest(doc)

    def test_bad_manifest_controls(self):
        manifest = self._manifest([{
            "name": "leaky",
            "description": "leaky tool",
            "tenant_scope": "tenant:acme",
            "read_fields": ["tenant:globex.account.balance"],
            "write_fields": ["account.ssn"],
        }])
        report = mcp.audit_manifest(manifest)
        d = report.to_dict()
        props = sorted(f["property"] for f in d["findings"])
        self.assertEqual(props, ["field_write_permission",
                                 "tenant_read_isolation"])
        by_prop = dict((f["property"], f["controls"]) for f in d["findings"])
        self.assertEqual(by_prop["field_write_permission"], ["CC6.1", "AIUC-1"])
        self.assertEqual(by_prop["tenant_read_isolation"], ["CC6.3", "AIUC-1"])

    def test_bad_manifest_compliance_section(self):
        manifest = self._manifest([{
            "name": "leaky",
            "description": "leaky tool",
            "tenant_scope": "tenant:acme",
            "read_fields": ["tenant:globex.account.balance"],
            "write_fields": ["account.ssn"],
        }])
        report = mcp.audit_manifest(manifest)
        d = report.to_dict()
        self.assertIn("compliance", d)
        self.assertEqual(d["compliance"]["result"], "violated")
        self.assertEqual(d["compliance"]["controls_touched"],
                         ["AIUC-1", "CC6.1", "CC6.3"])

    def test_good_manifest_clean(self):
        manifest = self._manifest([{
            "name": "get_balance",
            "description": "read balance",
            "tenant_scope": "tenant:acme",
            "read_fields": ["tenant:acme.account.balance"],
            "write_fields": [],
        }])
        report = mcp.audit_manifest(manifest)
        d = report.to_dict()
        self.assertEqual(d["summary"]["result"], "proven")
        self.assertEqual(d["compliance"]["controls_touched"], [])


class NarrativeComplianceTests(unittest.TestCase):
    """The narrative shows the per-finding controls line."""

    def _bad_manifest(self):
        return mcp_manifest.parse_manifest({
            "manifest": "caravel.mcp-manifest/v1",
            "server": "caravel-agent-tools",
            "version": "1.0.0",
            "tenant_scope": "tenant:acme",
            "allowed_write_fields": ["account.balance"],
            "tools": [{
                "name": "leaky",
                "description": "leaky tool",
                "tenant_scope": "tenant:acme",
                "read_fields": ["tenant:globex.account.balance"],
                "write_fields": ["account.ssn"],
            }],
        })

    def test_manifest_block_narrative_shows_controls(self):
        report = mcp.audit_manifest(self._bad_manifest())
        text = mcp.render_narrative(report)
        self.assertIn("controls: CC6.1, AIUC-1", text)
        self.assertIn("controls: CC6.3, AIUC-1", text)

    def test_mcp_block_narrative_shows_controls(self):
        report = mcp.audit_mcp(["read_log"], ["read_log", "update_balance"])
        text = mcp.render_narrative(report)
        self.assertIn("controls:", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)