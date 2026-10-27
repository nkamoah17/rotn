# -*- coding: utf-8 -*-
"""Tests for the RTF v1 deterministic, hashable reasoning trace in
:mod:`rot.trace`.

Covers:
  * ``canonical_json`` / ``trace_hash`` / ``manifest_id`` -- the low-level
    determinism + hashing primitives;
  * ``build_trace`` -- the RTF v1 body: required fields, verdict mapping,
    budget tier, source hash, findings + controls, graph, decision tree,
    timeline, narration, counterexample;
  * determinism -- the same input always yields the same trace hash;
  * hashability -- the top-level ``hash`` is the SHA-256 of the canonical
    body.

Run: python tests/test_trace.py
"""

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.license as lic  # noqa: E402
import rot.mcp_adapter as mcp  # noqa: E402
import rot.mcp_manifest as mm  # noqa: E402
import rot.trace as trace  # noqa: E402


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

# Over-permissive write + cross-tenant read: two findings.
_BAD = _manifest(
    ["account.balance"],
    [{"name": "leaky",
      "read_fields": ["tenant:globex.account.balance"],
      "write_fields": ["account.ssn"]}],
)

#: The RTF v1 required body fields (excluding the top-level ``hash``).
_REQUIRED = (
    "schema", "manifest_id", "verdict", "engines", "horizon", "budget",
    "source", "policy", "graph", "counterexample", "decision_tree",
    "timeline", "narration", "findings",
)


def _trace(manifest, budget=None, tier=None):
    """Build a trace for a manifest (helper for the tests below)."""
    report = mcp.audit_manifest(manifest, budget=budget)
    return trace.build_trace(
        manifest, report, budget=budget, tier=tier,
        source_path="test-manifest.json",
    )


class PrimitivesTests(unittest.TestCase):
    def test_schema_tag(self):
        self.assertEqual(trace.SCHEMA, "caravel.rtf/v1")

    def test_canonical_json_deterministic(self):
        a = {"b": 2, "a": [1, 2, 3]}
        self.assertEqual(trace.canonical_json(a), trace.canonical_json(a))
        # Keys are sorted, separators are compact.
        self.assertEqual(trace.canonical_json(a), '{"a":[1,2,3],"b":2}')

    def test_canonical_json_pretty(self):
        text = trace.canonical_json({"x": 1}, indent=2)
        self.assertIn("\n", text)
        self.assertEqual(json.loads(text), {"x": 1})

    def test_canonical_json_handles_sets(self):
        # Sets serialise as a sorted list (deterministic).
        self.assertEqual(trace.canonical_json({"s": {"b", "a"}}),
                         '{"s":["a","b"]}')

    def test_trace_hash_deterministic(self):
        body = {"verdict": "proven", "n": 1}
        self.assertEqual(trace.trace_hash(body), trace.trace_hash(body))
        self.assertEqual(len(trace.trace_hash(body)), 64)

    def test_trace_hash_changes_with_body(self):
        self.assertNotEqual(trace.trace_hash({"a": 1}),
                            trace.trace_hash({"a": 2}))

    def test_manifest_id_derived_from_hash(self):
        h = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        self.assertEqual(trace.manifest_id(h), "mf-a1b2c3d4e5f60718")

    def test_manifest_id_unknown(self):
        self.assertEqual(trace.manifest_id(None), "mf-unknown")
        self.assertEqual(trace.manifest_id(""), "mf-unknown")


class BuildTraceTests(unittest.TestCase):
    def test_good_manifest_proven(self):
        result = _trace(_GOOD)
        self.assertEqual(result.verdict(), "proven")
        self.assertEqual(result.body["findings"], [])
        self.assertIsNone(result.body["counterexample"])

    def test_bad_manifest_violated(self):
        result = _trace(_BAD)
        self.assertEqual(result.verdict(), "violated")
        self.assertEqual(len(result.body["findings"]), 2)

    def test_required_fields_present(self):
        for manifest in (_GOOD, _BAD):
            body = _trace(manifest).body
            for field in _REQUIRED:
                self.assertIn(field, body, "missing %r" % field)

    def test_budget_tier_free(self):
        body = _trace(_GOOD).body
        self.assertEqual(body["budget"]["tier"], "free")
        self.assertEqual(body["budget"]["source"], "free")
        self.assertIn("max_states", body["budget"]["limits"])

    def test_budget_tier_paid(self):
        paid = lic.DepthBudget.from_limits(lic.PAID_LIMITS, "action")
        body = _trace(_GOOD, budget=paid, tier="paid").body
        self.assertEqual(body["budget"]["tier"], "paid")
        self.assertEqual(body["budget"]["source"], "action")
        self.assertEqual(body["budget"]["limits"]["max_states"],
                         int(lic.PAID_LIMITS["max_states"]))

    def test_findings_have_controls(self):
        findings = _trace(_BAD).body["findings"]
        self.assertTrue(findings)
        for finding in findings:
            self.assertIn("controls", finding)
            self.assertTrue(finding["controls"],
                            "finding has no controls: %r" % finding)

    def test_source_hash_matches_manifest(self):
        body = _trace(_GOOD).body
        self.assertEqual(body["source"]["hash"],
                         mcp._manifest_hash(_GOOD))
        self.assertEqual(body["source"]["schema"], mm.MANIFEST_SCHEMA)
        self.assertEqual(body["source"]["path"], "test-manifest.json")

    def test_manifest_id_consistent_with_source(self):
        body = _trace(_GOOD).body
        self.assertEqual(body["manifest_id"],
                         trace.manifest_id(body["source"]["hash"]))

    def test_narration_present(self):
        text = _trace(_BAD).body["narration"]
        self.assertIsInstance(text, str)
        self.assertIn("Overly Permissive", text)

    def test_graph_nodes(self):
        body = _trace(_GOOD).body
        node_ids = [n["id"] for n in body["graph"]["nodes"]]
        self.assertEqual(node_ids, ["get_balance", "update_balance"])
        self.assertEqual(body["graph"]["kind"], "manifest")

    def test_decision_tree_checks(self):
        body = _trace(_BAD).body
        checks = {c["check"]: c["result"] for c in
                  body["decision_tree"]["checks"]}
        self.assertEqual(checks["field_write_permission"], "fail")
        self.assertEqual(checks["tenant_read_isolation"], "fail")
        self.assertEqual(body["decision_tree"]["verdict"], "violated")

    def test_decision_tree_pass(self):
        body = _trace(_GOOD).body
        checks = {c["check"]: c["result"] for c in
                  body["decision_tree"]["checks"]}
        self.assertEqual(checks["field_write_permission"], "pass")
        self.assertEqual(checks["tenant_read_isolation"], "pass")

    def test_timeline_steps(self):
        body = _trace(_BAD).body
        steps = [s["step"] for s in body["timeline"]]
        self.assertEqual(steps, ["parse_manifest", "field_write_permission",
                                 "tenant_read_isolation", "verdict"])
        self.assertEqual(body["timeline"][-1]["status"], "violated")

    def test_counterexample_for_violated(self):
        body = _trace(_BAD).body
        self.assertIsNotNone(body["counterexample"])

    def test_engines_structural(self):
        self.assertEqual(_trace(_GOOD).body["engines"], ["structural"])

    def test_horizon_default(self):
        self.assertEqual(_trace(_GOOD).body["horizon"], 12)

    def test_horizon_override(self):
        report = mcp.audit_manifest(_GOOD)
        result = trace.build_trace(_GOOD, report, horizon=42)
        self.assertEqual(result.body["horizon"], 42)


class DeterminismTests(unittest.TestCase):
    def test_same_input_same_hash(self):
        r1 = _trace(_BAD)
        r2 = _trace(_BAD)
        self.assertEqual(r1.hash, r2.hash)
        self.assertEqual(r1.to_json(), r2.to_json())

    def test_different_input_different_hash(self):
        self.assertNotEqual(_trace(_GOOD).hash, _trace(_BAD).hash)

    def test_hash_is_sha256_of_body(self):
        result = _trace(_BAD)
        expected = hashlib.sha256(
            trace.canonical_json(result.body).encode("utf-8")).hexdigest()
        self.assertEqual(result.hash, expected)

    def test_to_dict_includes_hash(self):
        result = _trace(_GOOD)
        d = result.to_dict()
        self.assertEqual(d["hash"], result.hash)
        self.assertNotIn("hash", result.body)

    def test_to_json_is_valid_json(self):
        result = _trace(_BAD)
        d = json.loads(result.to_json())
        self.assertEqual(d["schema"], trace.SCHEMA)
        self.assertEqual(d["verdict"], "violated")


if __name__ == "__main__":
    unittest.main(verbosity=2)


