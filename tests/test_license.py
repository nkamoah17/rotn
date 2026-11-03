# -*- coding: utf-8 -*-
"""Tests for the ROTN depth-budget model in :mod:`rot.license`.

ROTN is full-strength for everyone: there is no free/paid budget split and no
local license gate. This suite covers:

  * **D2. DepthBudget** -- the resolved budget (``free`` / ``from_limits`` /
    ``to_dict`` / ``repr``) and the ``resolve_budget`` "full-strength default
    + optional ``depth`` bound" rule (a ``depth`` input is a user-set bound
    that may only lower the budget).
  * **D3. Full-strength end-to-end** -- a catalog is in scope and PROVEN
    (full-strength), while a tight user-set ``DepthBudget`` still caps the
    budget (the user-set bound is the highest authority).

Pure stdlib, Python 3.6 compatible.

Run: python tests/test_license.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.license as lic  # noqa: E402
import rot.mcp_adapter as mcp  # noqa: E402
import rot.mcp_manifest as mm  # noqa: E402


# ---------------------------------------------------------------------------
# D2. DepthBudget
# ---------------------------------------------------------------------------

class DepthBudgetTests(unittest.TestCase):
    def test_free(self):
        b = lic.DepthBudget.free()
        self.assertEqual(b.max_states, lic.FREE_LIMITS["max_states"])
        self.assertEqual(b.max_horizon, lic.FREE_LIMITS["max_horizon"])
        self.assertEqual(b.max_tools, lic.FREE_LIMITS["max_tools"])
        self.assertEqual(b.max_tenant_scopes,
                         lic.FREE_LIMITS["max_tenant_scopes"])
        self.assertEqual(b.source, "free")

    def test_from_limits(self):
        limits = {"max_states": 50, "max_horizon": 3,
                  "max_tools": 7, "max_tenant_scopes": 2}
        b = lic.DepthBudget.from_limits(limits, "custom")
        self.assertEqual(b.max_states, 50)
        self.assertEqual(b.max_horizon, 3)
        self.assertEqual(b.max_tools, 7)
        self.assertEqual(b.max_tenant_scopes, 2)
        self.assertEqual(b.source, "custom")

    def test_to_dict(self):
        b = lic.DepthBudget.free()
        d = b.to_dict()
        self.assertEqual(
            set(d.keys()),
            {"max_states", "max_horizon", "max_tools",
             "max_tenant_scopes", "source"})

    def test_repr(self):
        b = lic.DepthBudget.free()
        r = repr(b)
        self.assertIn("DepthBudget", r)
        self.assertIn("free", r)


# ---------------------------------------------------------------------------
# D2. resolve_budget (full-strength default + optional depth bound)
# ---------------------------------------------------------------------------

class ResolveBudgetTests(unittest.TestCase):
    def test_no_input_full_strength(self):
        # Everyone is full-strength: the default budget is the generous
        # FREE_LIMITS (there is no tier to resolve).
        b = lic.resolve_budget()
        self.assertEqual(b.source, "free")
        self.assertEqual(b.max_states, lic.FREE_LIMITS["max_states"])
        self.assertEqual(b.max_tools, lic.FREE_LIMITS["max_tools"])

    def test_depth_caps_max_states(self):
        # --depth is a user-set bound: it may only lower the budget.
        b = lic.resolve_budget(depth=2000)
        self.assertEqual(b.max_states, 2000)
        self.assertEqual(b.source, "depth-bound")
        # A depth larger than the budget leaves the budget unchanged.
        b2 = lic.resolve_budget(depth=10 ** 9)
        self.assertEqual(b2.max_states, lic.FREE_LIMITS["max_states"])

    def test_depth_does_not_raise_other_limits(self):
        # A depth bound touches max_states only; the other limits keep the
        # full-strength values.
        b = lic.resolve_budget(depth=100)
        self.assertEqual(b.max_horizon, lic.FREE_LIMITS["max_horizon"])
        self.assertEqual(b.max_tools, lic.FREE_LIMITS["max_tools"])
        self.assertEqual(b.max_tenant_scopes,
                         lic.FREE_LIMITS["max_tenant_scopes"])


# ---------------------------------------------------------------------------
# D3. Full-strength end-to-end
# ---------------------------------------------------------------------------

class EndToEndTests(unittest.TestCase):
    def _six_tool_catalog(self):
        return ["tool_%d" % i for i in range(6)]

    def test_full_strength_proves_six_tool_catalog(self):
        # Everyone is full-strength (max_tools=100), so a 6-tool catalog is in
        # scope and PROVEN. The policy governs exactly the six catalog tools
        # (3 allowed, 3 denied).
        catalog = self._six_tool_catalog()
        allowed, denied = catalog[:3], catalog[3:]

        budget = lic.resolve_budget()
        r = mcp.audit_mcp(allowed, denied, tools=catalog, budget=budget)
        self.assertEqual(r.result(), "proven")
        self.assertEqual(r.exit_code(), 0)
        self.assertFalse(r.any_unknown)
        self.assertEqual(r.note, "")

    def test_within_scope(self):
        # A 3-tool catalog is well within the full-strength cap (max_tools=100)
        # -> PROVEN (exit 0). The policy governs exactly the three catalog
        # tools (2 allowed, 1 denied).
        catalog = ["tool_0", "tool_1", "tool_2"]
        allowed, denied = catalog[:2], catalog[2:]

        budget = lic.resolve_budget()
        r = mcp.audit_mcp(allowed, denied, tools=catalog, budget=budget)
        self.assertEqual(r.result(), "proven")
        self.assertEqual(r.exit_code(), 0)
        self.assertFalse(r.any_unknown)

    def test_depth_budget_caps_tools(self):
        # A user-set DepthBudget with a tight max_tools cap (3) makes a 6-tool
        # catalog out of scope (UNKNOWN) -- the user-set bound is the highest
        # authority and can cap the full-strength budget. The policy governs
        # exactly the six catalog tools (3 allowed, 3 denied).
        limits = {"max_states": 1000000, "max_horizon": 12,
                  "max_tools": 3, "max_tenant_scopes": 10}
        budget = lic.DepthBudget.from_limits(limits, "depth-bound")

        catalog = self._six_tool_catalog()
        allowed, denied = catalog[:3], catalog[3:]

        r = mcp.audit_mcp(allowed, denied, tools=catalog, budget=budget)
        self.assertEqual(r.result(), "unknown")
        self.assertEqual(r.exit_code(), 2)
        self.assertTrue(r.any_unknown)

    def _multi_tenant_manifest(self, n):
        # A manifest whose tools reference ``n`` distinct tenant scopes.
        tools = []
        for i in range(n):
            tools.append({
                "name": "tool_%d" % i,
                "read_fields": ["tenant:t%d.account.balance" % i],
            })
        return mm.parse_manifest({
            "manifest": mm.MANIFEST_SCHEMA,
            "server": "caravel-agent-tools",
            "tenant_scope": "tenant:t0",
            "allowed_write_fields": [],
            "tools": tools,
        })

    def test_manifest_tenant_scope_in_scope(self):
        # Everyone is full-strength (max_tenant_scopes=10), so a manifest with
        # 3 distinct tenant scopes is in scope.
        manifest = self._multi_tenant_manifest(3)
        budget = lic.resolve_budget()
        r = mcp.audit_manifest(manifest, budget=budget)
        self.assertFalse(r.any_unknown)
        self.assertEqual(r.note, "")

    def test_manifest_within_tenant_scope(self):
        # A manifest with a single tenant scope is in scope (full-strength).
        manifest = self._multi_tenant_manifest(1)
        budget = lic.resolve_budget()
        r = mcp.audit_manifest(manifest, budget=budget)
        self.assertFalse(r.any_unknown)
        self.assertEqual(r.note, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)