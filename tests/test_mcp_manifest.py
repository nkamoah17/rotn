# -*- coding: utf-8 -*-
"""Tests for :mod:`rot.mcp_manifest` (MCP Manifest v1 ingestion; Phase B, B1).

Covers:
  * schema validation -- required keys, the schema tag, strict (unknown-key)
    rejection, tool/annotation/inputSchema/field-list/tenant-scope checks;
  * round-trip -- ``parse_manifest(doc).to_dict()`` re-parses to an equal
    manifest, and ``to_dict()`` is JSON-serialisable;
  * convenience accessors -- ``tool_names`` / ``get_tool`` /
    ``effective_tenant_scope``;
  * file ingestion -- ``parse_manifest_file`` (valid, missing, malformed).

Run: python tests/test_mcp_manifest.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.mcp_manifest as mm  # noqa: E402


# A minimal well-formed manifest (the "good" baseline).
def _good_doc():
    return {
        "manifest": mm.MANIFEST_SCHEMA,
        "server": "caravel-agent-tools",
        "version": "1.0.0",
        "tenant_scope": "tenant:acme",
        "allowed_write_fields": ["account.balance"],
        "tools": [
            {
                "name": "get_balance",
                "title": "Read account balance",
                "description": "Return the balance.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"account_id": {"type": "string"}},
                    "required": ["account_id"],
                },
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
                "read_fields": ["tenant:acme.account.balance"],
            },
            {
                "name": "update_balance",
                "annotations": {"readOnlyHint": False, "destructiveHint": True},
                "read_fields": ["tenant:acme.account.balance"],
                "write_fields": ["account.balance"],
            },
        ],
    }


class SchemaValidationTests(unittest.TestCase):
    def test_valid_manifest_parses(self):
        m = mm.parse_manifest(_good_doc())
        self.assertIsInstance(m, mm.McpManifest)
        self.assertEqual(m.manifest, mm.MANIFEST_SCHEMA)
        self.assertEqual(len(m.tools), 2)
        self.assertEqual(m.allowed_write_fields, ["account.balance"])
        self.assertEqual(m.tenant_scope, "tenant:acme")

    def test_missing_required_key(self):
        doc = _good_doc()
        del doc["tools"]
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_missing_manifest_tag(self):
        doc = _good_doc()
        del doc["manifest"]
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_wrong_schema_tag(self):
        doc = _good_doc()
        doc["manifest"] = "caravel.mcp-manifest/v2"
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_unknown_top_level_key_rejected(self):
        doc = _good_doc()
        doc["bogus"] = 1
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_non_object_manifest_rejected(self):
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(["not", "a", "dict"])

    def test_tools_must_be_array(self):
        doc = _good_doc()
        doc["tools"] = {"name": "x"}
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_tool_missing_name_rejected(self):
        doc = _good_doc()
        doc["tools"][0] = {"description": "no name"}
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_duplicate_tool_name_rejected(self):
        doc = _good_doc()
        doc["tools"].append({"name": "get_balance"})
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_unknown_tool_key_rejected(self):
        doc = _good_doc()
        doc["tools"][0]["typo"] = True
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_annotation_must_be_boolean(self):
        doc = _good_doc()
        doc["tools"][0]["annotations"] = {"readOnlyHint": "yes"}
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_unknown_annotation_rejected(self):
        doc = _good_doc()
        doc["tools"][0]["annotations"] = {"notAHint": True}
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_input_schema_type_must_be_object(self):
        doc = _good_doc()
        doc["tools"][0]["inputSchema"] = {"type": "array"}
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_field_list_must_be_strings(self):
        doc = _good_doc()
        doc["tools"][1]["write_fields"] = ["account.balance", 42]
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)

    def test_tenant_scope_must_be_string(self):
        doc = _good_doc()
        doc["tenant_scope"] = 7
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest(doc)


class RoundTripTests(unittest.TestCase):
    def test_parse_to_dict_round_trips(self):
        doc = _good_doc()
        m1 = mm.parse_manifest(doc)
        doc2 = m1.to_dict()
        m2 = mm.parse_manifest(doc2)
        self.assertEqual(m1.to_dict(), m2.to_dict())

    def test_to_dict_is_json_serialisable(self):
        m = mm.parse_manifest(_good_doc())
        text = json.dumps(m.to_dict(), sort_keys=True)
        self.assertEqual(json.loads(text), m.to_dict())

    def test_optional_fields_omitted_when_absent(self):
        # A bare manifest (no server/version/tenant_scope) round-trips and
        # does not fabricate the optional keys.
        doc = {
            "manifest": mm.MANIFEST_SCHEMA,
            "tools": [{"name": "noop"}],
        }
        m = mm.parse_manifest(doc)
        out = m.to_dict()
        self.assertNotIn("server", out)
        self.assertNotIn("version", out)
        self.assertNotIn("tenant_scope", out)
        self.assertNotIn("allowed_write_fields", out)
        self.assertEqual(out["tools"][0], {"name": "noop"})


class ConvenienceTests(unittest.TestCase):
    def test_tool_names_sorted(self):
        m = mm.parse_manifest(_good_doc())
        self.assertEqual(m.tool_names(),
                         ["get_balance", "update_balance"])

    def test_get_tool(self):
        m = mm.parse_manifest(_good_doc())
        self.assertEqual(m.get_tool("update_balance").write_fields,
                         ["account.balance"])
        self.assertIsNone(m.get_tool("nope"))

    def test_effective_tenant_scope_falls_back(self):
        m = mm.parse_manifest(_good_doc())
        tool = m.get_tool("get_balance")
        self.assertEqual(m.effective_tenant_scope(tool), "tenant:acme")

    def test_effective_tenant_scope_override(self):
        doc = _good_doc()
        doc["tools"][0]["tenant_scope"] = "tenant:globex"
        m = mm.parse_manifest(doc)
        self.assertEqual(m.effective_tenant_scope(m.get_tool("get_balance")),
                         "tenant:globex")


class ParseFileTests(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_parse_valid_file(self):
        path = self._write(json.dumps(_good_doc()))
        m = mm.parse_manifest_file(path)
        self.assertEqual(len(m.tools), 2)

    def test_missing_file_raises(self):
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest_file(os.path.join(tempfile.gettempdir(),
                                                "no-such-manifest-xyz.json"))

    def test_malformed_json_raises(self):
        path = self._write("{ this is not json")
        with self.assertRaises(mm.McpManifestError):
            mm.parse_manifest_file(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)

