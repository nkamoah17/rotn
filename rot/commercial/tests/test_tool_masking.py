# -*- coding: utf-8 -*-
"""Tests for the masked MCP ``tools/list`` (the Product 2 *service* surface).

This is the commercial-layer half of the tool-masking story: the deterministic
masking core (``RuntimeGuard.enabled_tools`` / ``blocked_tools`` /
``rot runtime tools``) is covered by the **core** suite in
``tests/test_tool_masking.py`` (Apache-2.0).  Here we test the MCP
``tools/list`` gateway (``rot.commercial.runtime.mcp``), which is the
**service** surface (Apache-2.0).

Requires the ``rotn-commercial`` distribution.

Run: python rot/commercial/tests/test_tool_masking.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from rot.runtime.rules import spendcap_rule  # noqa: E402
from rot.commercial.runtime.mcp import McpGateway  # noqa: E402


# ---------------------------------------------------------------------------
# The masked MCP tools/list (state present -> only the enabled tools are kept)
# ---------------------------------------------------------------------------
class McpMaskedToolsListTests(unittest.TestCase):
    """``tools/list`` with a state is masked to the enabled tools only."""

    def _gw(self):
        return McpGateway(rules={"transfer": spendcap_rule()})

    def test_no_state_returns_full_catalog(self):
        resp = self._gw().handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp["result"]["masked"], False)
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertEqual(names, {"transfer"})

    def test_high_inflight_masks_transfer(self):
        resp = self._gw().handle_message({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list",
            "params": {"state": {"completed": 0, "inflight": 3}}})
        self.assertEqual(resp["result"]["masked"], True)
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertNotIn("transfer", names)

    def test_low_inflight_keeps_transfer(self):
        resp = self._gw().handle_message({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list",
            "params": {"state": {"completed": 0, "inflight": 0}}})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertIn("transfer", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)