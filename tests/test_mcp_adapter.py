# -*- coding: utf-8 -*-
"""Tests for :mod:`rot.mcp_adapter` (the Cedar-AR findings adapter).

Covers:
  * the *structural* checks (contradictions / unreachable rules) in isolation;
  * a *conforming* policy (allowed non-empty, disjoint) -> PASS, no findings;
  * a *stuck* policy (allowed empty) -> BLOCK, Overly Restrictive + Ineffective;
  * a *contradictory* policy (allowed/denied overlap) -> BLOCK, contradictions,
    facets skipped (the audit short-circuits before the engine runs);
  * the facet -> finding mapping and the report structure;
  * JSON serialisability + determinism;
  * the exit-code mapping (0 PASS / 1 BLOCK);
  * the blog-ready narrative rendering.

Run: python tests/test_mcp_adapter.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.mcp_adapter as mcp  # noqa: E402


# A well-formed policy (allowed non-empty, disjoint from denied).
_GOOD_ALLOWED = ["read_log", "update_balance"]
_GOOD_DENIED = ["exfiltrate_secret"]

# A stuck policy (no allowed action).
_STUCK_ALLOWED = []
_STUCK_DENIED = ["read_log", "update_balance"]

# A contradictory policy (overlapping allowed/denied).
_CONTRA_ALLOWED = ["read_log"]
_CONTRA_DENIED = ["read_log", "update_balance"]


class StructuralFindingsTests(unittest.TestCase):
    def test_no_findings_for_conforming_policy(self):
        findings = mcp.structural_findings(_GOOD_ALLOWED, _GOOD_DENIED)
        self.assertEqual(findings, [])

    def test_contradictions_detected(self):
        findings = mcp.structural_findings(_CONTRA_ALLOWED, _CONTRA_DENIED)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding, mcp.FINDING_CONTRADICTIONS)
        self.assertEqual(findings[0].severity, mcp.SEVERITY_ERROR)
        self.assertEqual(findings[0].witness, {"overlap": ["read_log"]})

    def test_matching_catalog_no_findings(self):
        # Every policy action is a catalog tool and vice versa.
        tools = ["read_log", "update_balance", "exfiltrate_secret"]
        findings = mcp.structural_findings(_GOOD_ALLOWED, _GOOD_DENIED, tools)
        self.assertEqual(findings, [])

    def test_ungoverned_tool_flagged(self):
        # A catalog tool the policy never references.
        tools = ["read_log", "update_balance", "exfiltrate_secret",
                 "send_email"]
        findings = mcp.structural_findings(_GOOD_ALLOWED, _GOOD_DENIED, tools)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding, mcp.FINDING_UNREACHABLE_RULES)
        self.assertEqual(findings[0].witness, {"tool": "send_email"})

    def test_policy_action_without_tool_flagged(self):
        # A policy action (denied) with no catalog tool.
        tools = ["read_log", "update_balance"]
        findings = mcp.structural_findings(_GOOD_ALLOWED, _GOOD_DENIED, tools)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding, mcp.FINDING_UNREACHABLE_RULES)
        self.assertEqual(findings[0].witness, {"action": "exfiltrate_secret"})


class FindingTypeTests(unittest.TestCase):
    def test_finding_rejects_unknown_name(self):
        with self.assertRaises(ValueError):
            mcp.Finding("not-a-finding", "policy", mcp.SEVERITY_ERROR,
                        "p", "m")

    def test_finding_rejects_bad_severity(self):
        with self.assertRaises(ValueError):
            mcp.Finding(mcp.FINDING_CONTRADICTIONS, "policy", "bogus",
                        "p", "m")

    def test_finding_to_dict(self):
        f = mcp.Finding(mcp.FINDING_CONTRADICTIONS, "policy",
                        mcp.SEVERITY_ERROR, "allowed_denied_disjoint",
                        "overlap", witness={"overlap": ["a"]},
                        evidence={"check": "x"})
        d = f.to_dict()
        self.assertEqual(d["finding"], mcp.FINDING_CONTRADICTIONS)
        self.assertEqual(d["facet"], "policy")
        self.assertEqual(d["severity"], mcp.SEVERITY_ERROR)
        self.assertEqual(d["property"], "allowed_denied_disjoint")
        self.assertEqual(d["witness"], {"overlap": ["a"]})
        self.assertEqual(d["evidence"], {"check": "x"})


class AuditMcpTests(unittest.TestCase):
    def test_conforming_policy_pass(self):
        report = mcp.audit_mcp(_GOOD_ALLOWED, _GOOD_DENIED)
        self.assertIsInstance(report, mcp.McpFindingsReport)
        self.assertFalse(report.has_findings())
        self.assertEqual(report.result(), "proven")
        self.assertEqual(report.exit_code(), 0)
        self.assertFalse(report.any_unknown)

    def test_stuck_policy_block(self):
        report = mcp.audit_mcp(_STUCK_ALLOWED, _STUCK_DENIED)
        self.assertTrue(report.has_findings())
        self.assertEqual(report.result(), "violated")
        self.assertEqual(report.exit_code(), 1)
        names = [f.finding for f in report.findings]
        self.assertIn(mcp.FINDING_OVERLY_RESTRICTIVE, names)
        self.assertIn(mcp.FINDING_INEFFECTIVE, names)

    def test_contradictory_policy_short_circuits(self):
        report = mcp.audit_mcp(_CONTRA_ALLOWED, _CONTRA_DENIED)
        self.assertEqual(report.result(), "violated")
        self.assertEqual(report.exit_code(), 1)
        names = [f.finding for f in report.findings]
        self.assertEqual(names, [mcp.FINDING_CONTRADICTIONS])
        # The audit was skipped (facets are stubs, not verdicts).
        for facet in ("safety", "liveness", "conformance"):
            self.assertEqual(report.facets[facet]["status"], "skipped")

    def test_policy_info_and_hash(self):
        report = mcp.audit_mcp(_GOOD_ALLOWED, _GOOD_DENIED)
        self.assertEqual(report.policy["allowed"], sorted(_GOOD_ALLOWED))
        self.assertEqual(report.policy["denied"], sorted(_GOOD_DENIED))
        self.assertEqual(len(report.policy["hash"]), 64)  # SHA-256 hex

    def test_tools_recorded(self):
        tools = ["read_log", "send_email"]
        report = mcp.audit_mcp(_GOOD_ALLOWED, _GOOD_DENIED, tools=tools)
        self.assertEqual(report.tools, ["read_log", "send_email"])


class ReportSerialisationTests(unittest.TestCase):
    def test_to_dict_shape(self):
        report = mcp.audit_mcp(_GOOD_ALLOWED, _GOOD_DENIED)
        d = report.to_dict()
        for key in ("schema", "policy", "tools", "facets", "findings",
                    "summary"):
            self.assertIn(key, d)
        self.assertEqual(d["schema"], mcp.REPORT_SCHEMA)
        self.assertEqual(d["summary"]["result"], "proven")
        self.assertEqual(d["summary"]["total_findings"], 0)

    def test_to_json_deterministic(self):
        r1 = mcp.audit_mcp(_GOOD_ALLOWED, _GOOD_DENIED)
        r2 = mcp.audit_mcp(_GOOD_ALLOWED, _GOOD_DENIED)
        self.assertEqual(r1.to_json(), r2.to_json())
        parsed = json.loads(r1.to_json())
        self.assertEqual(parsed["schema"], mcp.REPORT_SCHEMA)

    def test_findings_json_serialisable(self):
        report = mcp.audit_mcp(_STUCK_ALLOWED, _STUCK_DENIED)
        json.loads(report.to_json())  # must not raise


class NarrativeTests(unittest.TestCase):
    def test_pass_narrative(self):
        report = mcp.audit_mcp(_GOOD_ALLOWED, _GOOD_DENIED)
        text = mcp.render_narrative(report)
        self.assertIn("RESULT: PASS", text)
        self.assertIn("Cedar-AR findings: none", text)

    def test_block_narrative(self):
        report = mcp.audit_mcp(_STUCK_ALLOWED, _STUCK_DENIED)
        text = mcp.render_narrative(report)
        self.assertIn("RESULT: BLOCK", text)
        self.assertIn(mcp.FINDING_OVERLY_RESTRICTIVE, text)

    def test_contradiction_narrative(self):
        report = mcp.audit_mcp(_CONTRA_ALLOWED, _CONTRA_DENIED)
        text = mcp.render_narrative(report)
        self.assertIn("RESULT: BLOCK", text)
        self.assertIn(mcp.FINDING_CONTRADICTIONS, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)