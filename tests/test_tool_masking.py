# -*- coding: utf-8 -*-
"""Tests for tool masking (B1, thesis 4.1).

Tool masking is the deterministic half of the runtime plane: the *same* guard
the offline engine proved safe, re-applied per tool, decides which tools are
enabled **now**.  No new proof engine, no LLM.

This pins three properties (the B1.3 acceptance), plus the two surfaces:

  (i)   ``RuntimeGuard.enabled_tools(state)`` equals ``{t : guard_t.eval(state)
        is True}`` over the rule's tool universe (the IR's decision actions) --
        for every state in a battery;
  (ii)  ``enabled ⊆ catalog`` -- the enabled set is a subset of the catalog
        (the tool universe);
  (iii) ``blocked ∉ enabled`` -- the enabled and blocked sets are disjoint
        (together they partition the catalog).

Surfaces: ``rot runtime tools`` (the CLI mask) and the masked MCP
``tools/list`` (state present -> only the enabled tools are kept).

Run: python tests/test_tool_masking.py
"""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.runtime.core import RuntimeGuard  # noqa: E402
from rot.runtime.rules import spendcap_rule  # noqa: E402
from rot.runtime.mcp import McpGateway  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _guard():
    """A RuntimeGuard for the spend-cap rule (defaults: K=4, A=100, C=200)."""
    return RuntimeGuard(spendcap_rule())


def _tool_universe(rule):
    """The rule's tool universe: the IR's non-initial (decision) actions."""
    return [a.name for a in rule.ir.actions if not a.is_initial]


def _state_battery():
    """A battery of (completed, inflight) states across the cap boundary."""
    for completed in (0, 100, 200):
        for inflight in (0, 1, 2, 3):
            yield {"completed": completed, "inflight": inflight}


# ---------------------------------------------------------------------------
# (i) enabled_tools(state) == {t : guard_t.eval(state) is True}
# ---------------------------------------------------------------------------
class EnabledToolsTests(unittest.TestCase):
    """The mask is exactly the per-tool guard evaluation over the universe."""

    def test_enabled_tools_matches_guard_eval(self):
        rule = spendcap_rule()
        rg = _guard()
        for state in _state_battery():
            expected = {a.name: (a.guard.eval(state) is True)
                        for a in rule.ir.actions if not a.is_initial}
            self.assertEqual(rg.enabled_tools(state), expected,
                             "enabled_tools disagrees with the guard at %s"
                             % state)

    def test_tool_universe_is_the_decision_actions(self):
        rule = spendcap_rule()
        rg = _guard()
        self.assertEqual(sorted(rg.enabled_tools({}).keys()),
                         sorted(_tool_universe(rule)))

    def test_fail_closed_on_undefined_state(self):
        # A state missing the guard's atoms is UNDEF -> every tool disabled.
        rg = _guard()
        self.assertEqual(rg.enabled_tools({}),
                         {t: False for t in _tool_universe(spendcap_rule())})


# ---------------------------------------------------------------------------
# (ii) enabled ⊆ catalog; (iii) blocked ∉ enabled (they partition the catalog)
# ---------------------------------------------------------------------------
class MaskPartitionTests(unittest.TestCase):
    """The enabled set is a subset of the catalog and disjoint from blocked."""

    def test_enabled_subset_of_catalog(self):
        rg = _guard()
        for state in _state_battery():
            et = rg.enabled_tools(state)
            self.assertTrue(set(rg.enabled(state)) <= set(et.keys()),
                            "enabled not ⊆ catalog at %s" % state)

    def test_enabled_and_blocked_are_disjoint(self):
        rg = _guard()
        for state in _state_battery():
            overlap = set(rg.enabled(state)) & set(rg.blocked_tools(state))
            self.assertFalse(overlap,
                             "enabled and blocked overlap at %s: %s"
                             % (state, sorted(overlap)))

    def test_enabled_union_blocked_is_catalog(self):
        rg = _guard()
        for state in _state_battery():
            et = rg.enabled_tools(state)
            self.assertEqual(set(rg.enabled(state))
                             | set(rg.blocked_tools(state)),
                             set(et.keys()),
                             "enabled ∪ blocked != catalog at %s" % state)

    def test_blocked_names_spend_ok_when_inflight_high(self):
        # The beachhead: 3 inflight spends -> spend_ok blocked, spend_deny on.
        rg = _guard()
        state = {"completed": 0, "inflight": 3}
        self.assertIn("spend_ok", rg.blocked_tools(state))
        self.assertIn("spend_deny", rg.enabled(state))


# ---------------------------------------------------------------------------
# Surface 1: the CLI (rot runtime tools)
# ---------------------------------------------------------------------------
class CliToolsTests(unittest.TestCase):
    """``rot runtime tools``: the mask, exit 0, enabled/blocked printed."""

    def _run(self, *argv):
        proc = subprocess.run(
            [sys.executable, "-m", "rot"] + list(argv),
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")

    def test_tools_blocked_state_is_exit_0_and_lists_blocked(self):
        code, out = self._run(
            "runtime", "tools",
            "--state", json.dumps({"completed": 0, "inflight": 3}))
        self.assertEqual(code, 0)
        self.assertIn("spend_ok", out)
        self.assertIn("blocked", out)

    def test_tools_allowed_state_is_exit_0_and_lists_enabled(self):
        code, out = self._run(
            "runtime", "tools",
            "--state", json.dumps({"completed": 0, "inflight": 0}))
        self.assertEqual(code, 0)
        self.assertIn("spend_ok", out)
        self.assertIn("enabled", out)

    def test_tools_json_is_well_formed(self):
        code, out = self._run(
            "runtime", "tools",
            "--state", json.dumps({"completed": 0, "inflight": 0}),
            "--json")
        self.assertEqual(code, 0)
        body = json.loads(out)
        self.assertEqual(body["enabled"], ["spend_ok"])
        self.assertEqual(body["blocked"], ["respond", "spend_deny"])

    def test_tools_unknown_rule_is_exit_3(self):
        code, _ = self._run("runtime", "tools", "--rule", "nope")
        self.assertEqual(code, 3)


# ---------------------------------------------------------------------------
# Surface 2: the masked MCP tools/list
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

