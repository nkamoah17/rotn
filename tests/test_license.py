# -*- coding: utf-8 -*-
"""Tests for the Caravel tier-gating license model in :mod:`rot.license`.

This is the Phase D (tier gating) test suite (D4). It covers:

  * **D1. License model** -- HMAC-SHA256 signing/verification round-trip,
    tamper rejection, wrong-key rejection, expiry (fail-closed), and the
    ``License`` value object (``from_dict`` / ``to_dict`` / ``is_expired``).
  * **D2. DepthBudget** -- the resolved budget (``free`` / ``from_limits`` /
    ``to_dict``) and the ``resolve_budget`` precedence
    (license -> action input -> free defaults), including the D3 rule that a
    ``depth`` input is capped to the free maximum when ``tier: free``.
  * **D3. Tier gating end-to-end** -- a catalog that exceeds the free tier
    cap (``max_tools`` / ``max_tenant_scopes``) is reported ``UNKNOWN``
    (exit 2) on the free tier while the paid tier produces a verdict,
    demonstrating the "cap the bounded-search budget" contract.

Pure stdlib, Python 3.6 compatible.

Run: python tests/test_license.py
"""

import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.license as lic  # noqa: E402
import rot.mcp_adapter as mcp  # noqa: E402
import rot.mcp_manifest as mm  # noqa: E402

#: A fixed Caravel key for deterministic signing/verification tests.
KEY = "test-caravel-key"

#: A fixed reference date for deterministic expiry tests.
NOW = datetime.date(2026, 6, 1)


# ---------------------------------------------------------------------------
# D1. Signing / verification
# ---------------------------------------------------------------------------

class SigningTests(unittest.TestCase):
    def test_sign_has_prefix(self):
        body = lic.make_license("org", "paid", key=KEY)
        self.assertTrue(body["hmac"].startswith(lic.HMAC_PREFIX))

    def test_sign_verify_roundtrip(self):
        body = lic.make_license("org", "paid", key=KEY)
        self.assertTrue(lic.verify_signature(body, key=KEY))

    def test_sign_deterministic(self):
        body = lic.make_license("org", "paid", key=KEY)
        self.assertEqual(lic.sign(body, key=KEY), body["hmac"])

    def test_verify_wrong_key_rejected(self):
        body = lic.make_license("org", "paid", key=KEY)
        self.assertFalse(lic.verify_signature(body, key="a-different-key"))

    def test_verify_missing_hmac_rejected(self):
        body = lic.make_license("org", "paid", key=KEY)
        del body["hmac"]
        self.assertFalse(lic.verify_signature(body, key=KEY))

    def test_verify_tampered_body_rejected(self):
        body = lic.make_license("org", "paid", key=KEY)
        body["limits"]["max_tools"] = 999  # tamper after signing
        self.assertFalse(lic.verify_signature(body, key=KEY))

    def test_verify_tampered_org_rejected(self):
        body = lic.make_license("org-a", "paid", key=KEY)
        body["org"] = "org-b"  # tamper after signing
        self.assertFalse(lic.verify_signature(body, key=KEY))

    def test_verify_non_dict_rejected(self):
        self.assertFalse(lic.verify_signature("not-a-dict", key=KEY))


# ---------------------------------------------------------------------------
# D1. make_license
# ---------------------------------------------------------------------------

class MakeLicenseTests(unittest.TestCase):
    def test_make_license_valid(self):
        body = lic.make_license("acme", "paid", key=KEY)
        self.assertEqual(body["schema"], lic.SCHEMA)
        self.assertEqual(body["org"], "acme")
        self.assertEqual(body["tier"], "paid")
        ok, note = lic.check_license(body, key=KEY)
        self.assertTrue(ok, note)

    def test_make_license_free_defaults(self):
        body = lic.make_license("acme", "free", key=KEY)
        self.assertEqual(body["limits"], lic.FREE_LIMITS)

    def test_make_license_paid_defaults(self):
        body = lic.make_license("acme", "paid", key=KEY)
        self.assertEqual(body["limits"], lic.PAID_LIMITS)

    def test_make_license_custom_limits(self):
        limits = {"max_states": 50, "max_horizon": 3,
                  "max_tools": 7, "max_tenant_scopes": 2}
        body = lic.make_license("acme", "paid", limits=limits, key=KEY)
        self.assertEqual(body["limits"], limits)
        ok, note = lic.check_license(body, key=KEY)
        self.assertTrue(ok, note)

    def test_make_license_unknown_tier_rejected(self):
        with self.assertRaises(lic.LicenseError):
            lic.make_license("acme", "gold", key=KEY)

    def test_make_license_bad_limits_rejected(self):
        limits = {"max_states": 0, "max_horizon": 3,
                  "max_tools": 7, "max_tenant_scopes": 2}
        with self.assertRaises(lic.LicenseError):
            lic.make_license("acme", "paid", limits=limits, key=KEY)

    def test_make_license_bool_limits_rejected(self):
        limits = {"max_states": True, "max_horizon": 3,
                  "max_tools": 7, "max_tenant_scopes": 2}
        with self.assertRaises(lic.LicenseError):
            lic.make_license("acme", "paid", limits=limits, key=KEY)


# ---------------------------------------------------------------------------
# D1. check_license
# ---------------------------------------------------------------------------

class CheckLicenseTests(unittest.TestCase):
    def test_check_valid_license(self):
        body = lic.make_license("acme", "paid",
                                issued="2026-01-01", expiry="2026-12-31",
                                key=KEY)
        ok, note = lic.check_license(body, key=KEY, now=NOW)
        self.assertTrue(ok, note)
        self.assertEqual(note, "")

    def test_check_tampered_rejected(self):
        body = lic.make_license("acme", "paid", key=KEY)
        body["limits"]["max_tools"] = 999
        ok, note = lic.check_license(body, key=KEY, now=NOW)
        self.assertFalse(ok)
        self.assertIn("HMAC", note)

    def test_check_wrong_key_rejected(self):
        body = lic.make_license("acme", "paid", key=KEY)
        ok, note = lic.check_license(body, key="a-different-key", now=NOW)
        self.assertFalse(ok)
        self.assertIn("HMAC", note)

    def test_check_expired_rejected(self):
        body = lic.make_license("acme", "paid",
                                issued="2025-01-01", expiry="2026-05-31",
                                key=KEY)
        ok, note = lic.check_license(body, key=KEY, now=NOW)
        self.assertFalse(ok)
        self.assertIn("expired", note)

    def test_expiry_inclusive(self):
        # A license is valid on its expiry day (inclusive).
        body = lic.make_license("acme", "paid",
                                issued="2026-01-01", expiry="2026-06-01",
                                key=KEY)
        ok, note = lic.check_license(body, key=KEY, now=NOW)
        self.assertTrue(ok, note)

    def test_expiry_day_after_rejected(self):
        # One day past expiry is rejected.
        body = lic.make_license("acme", "paid",
                                issued="2026-01-01", expiry="2026-05-31",
                                key=KEY)
        ok, note = lic.check_license(
            body, key=KEY, now=datetime.date(2026, 6, 1))
        self.assertFalse(ok)

    def test_check_bad_schema_rejected(self):
        body = lic.make_license("acme", "paid", key=KEY)
        body["schema"] = "caravel.license/v0"
        ok, note = lic.check_license(body, key=KEY, now=NOW)
        self.assertFalse(ok)
        self.assertIn("schema", note)

    def test_check_bad_tier_rejected(self):
        body = lic.make_license("acme", "paid", key=KEY)
        body["tier"] = "gold"
        ok, note = lic.check_license(body, key=KEY, now=NOW)
        self.assertFalse(ok)
        self.assertIn("tier", note)

    def test_check_bad_limits_rejected(self):
        body = lic.make_license("acme", "paid", key=KEY)
        body["limits"]["max_tools"] = -1
        ok, note = lic.check_license(body, key=KEY, now=NOW)
        self.assertFalse(ok)

    def test_check_issued_after_expiry_rejected(self):
        body = lic.make_license("acme", "paid",
                                issued="2026-12-31", expiry="2026-01-01",
                                key=KEY)
        ok, note = lic.check_license(body, key=KEY, now=NOW)
        self.assertFalse(ok)
        self.assertIn("after expiry", note)

    def test_check_non_dict_rejected(self):
        ok, note = lic.check_license("not-a-dict", key=KEY, now=NOW)
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# D1. load_license (file-based, fail-closed)
# ---------------------------------------------------------------------------

class LoadLicenseTests(unittest.TestCase):
    def _write(self, doc):
        fh = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False)
        json.dump(doc, fh)
        fh.close()
        return fh.name

    def _cleanup(self, path):
        if os.path.exists(path):
            os.unlink(path)

    def test_load_valid(self):
        body = lic.make_license("acme", "paid", key=KEY)
        path = self._write(body)
        try:
            license_obj = lic.load_license(path, key=KEY, now=NOW)
            self.assertEqual(license_obj.org, "acme")
            self.assertEqual(license_obj.tier, "paid")
            self.assertEqual(license_obj.limits, lic.PAID_LIMITS)
        finally:
            self._cleanup(path)

    def test_load_tampered_rejected(self):
        body = lic.make_license("acme", "paid", key=KEY)
        body["limits"]["max_tools"] = 999
        path = self._write(body)
        try:
            with self.assertRaises(lic.LicenseError):
                lic.load_license(path, key=KEY, now=NOW)
        finally:
            self._cleanup(path)

    def test_load_expired_rejected(self):
        body = lic.make_license("acme", "paid",
                                issued="2025-01-01", expiry="2026-05-31",
                                key=KEY)
        path = self._write(body)
        try:
            with self.assertRaises(lic.LicenseError):
                lic.load_license(path, key=KEY, now=NOW)
        finally:
            self._cleanup(path)

    def test_load_missing_rejected(self):
        with self.assertRaises(lic.LicenseError):
            lic.load_license("/nonexistent/license.json", key=KEY, now=NOW)

    def test_load_malformed_rejected(self):
        path = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False)
        path.write("{not valid json")
        path.close()
        try:
            with self.assertRaises(lic.LicenseError):
                lic.load_license(path.name, key=KEY, now=NOW)
        finally:
            self._cleanup(path.name)


# ---------------------------------------------------------------------------
# D1. License value object
# ---------------------------------------------------------------------------

class LicenseModelTests(unittest.TestCase):
    def test_from_dict_to_dict_roundtrip(self):
        body = lic.make_license("acme", "paid",
                                issued="2026-01-01", expiry="2026-12-31",
                                key=KEY)
        obj = lic.License.from_dict(body)
        self.assertEqual(obj.to_dict(), body)

    def test_is_expired_false(self):
        body = lic.make_license("acme", "paid",
                                issued="2026-01-01", expiry="2026-12-31",
                                key=KEY)
        obj = lic.License.from_dict(body)
        self.assertFalse(obj.is_expired(now=NOW))

    def test_is_expired_true(self):
        body = lic.make_license("acme", "paid",
                                issued="2025-01-01", expiry="2026-05-31",
                                key=KEY)
        obj = lic.License.from_dict(body)
        self.assertTrue(obj.is_expired(now=NOW))

    def test_is_expired_inclusive(self):
        body = lic.make_license("acme", "paid",
                                issued="2026-01-01", expiry="2026-06-01",
                                key=KEY)
        obj = lic.License.from_dict(body)
        self.assertFalse(obj.is_expired(now=NOW))

    def test_repr(self):
        body = lic.make_license("acme", "paid", key=KEY)
        obj = lic.License.from_dict(body)
        r = repr(obj)
        self.assertIn("acme", r)
        self.assertIn("paid", r)

    def test_from_dict_non_dict_rejected(self):
        with self.assertRaises(lic.LicenseError):
            lic.License.from_dict("not-a-dict")


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
# D2/D3. resolve_budget precedence
# ---------------------------------------------------------------------------

class ResolveBudgetTests(unittest.TestCase):
    def test_no_input_free_defaults(self):
        b = lic.resolve_budget()
        self.assertEqual(b.source, "free")
        self.assertEqual(b.max_states, lic.FREE_LIMITS["max_states"])
        self.assertEqual(b.max_tools, lic.FREE_LIMITS["max_tools"])

    def test_tier_free(self):
        b = lic.resolve_budget(tier="free")
        self.assertEqual(b.source, "action")
        self.assertEqual(b.max_states, lic.FREE_LIMITS["max_states"])
        self.assertEqual(b.max_tools, lic.FREE_LIMITS["max_tools"])

    def test_tier_paid(self):
        b = lic.resolve_budget(tier="paid")
        self.assertEqual(b.source, "action")
        self.assertEqual(b.max_states, lic.PAID_LIMITS["max_states"])
        self.assertEqual(b.max_tools, lic.PAID_LIMITS["max_tools"])

    def test_depth_free_capped(self):
        # D3: a depth input is capped to the free maximum when tier: free.
        b = lic.resolve_budget(tier="free", depth=2000)
        self.assertEqual(b.max_states, lic.FREE_LIMITS["max_states"])

    def test_depth_paid_as_is(self):
        # A depth input is used as-is when tier: paid.
        b = lic.resolve_budget(tier="paid", depth=3)
        self.assertEqual(b.max_states, 3)

    def test_depth_paid_large(self):
        b = lic.resolve_budget(tier="paid", depth=999)
        self.assertEqual(b.max_states, 999)

    def test_unknown_tier_free_defaults(self):
        b = lic.resolve_budget(tier="gold")
        self.assertEqual(b.source, "free")

    def test_license_highest_authority(self):
        # A license overrides tier/depth (highest authority).
        limits = {"max_states": 50, "max_horizon": 3,
                  "max_tools": 7, "max_tenant_scopes": 2}
        body = lic.make_license("acme", "paid", limits=limits, key=KEY)
        license_obj = lic.License.from_dict(body)
        b = lic.resolve_budget(license=license_obj,
                               tier="free", depth=1)
        self.assertEqual(b.source, "license")
        self.assertEqual(b.max_states, 50)
        self.assertEqual(b.max_tools, 7)

    def test_license_overrides_paid(self):
        limits = {"max_states": 10, "max_horizon": 2,
                  "max_tools": 3, "max_tenant_scopes": 1}
        body = lic.make_license("acme", "paid", limits=limits, key=KEY)
        license_obj = lic.License.from_dict(body)
        b = lic.resolve_budget(license=license_obj, tier="paid", depth=999)
        self.assertEqual(b.source, "license")
        self.assertEqual(b.max_states, 10)
        self.assertEqual(b.max_tools, 3)


# ---------------------------------------------------------------------------
# D3. Tier gating end-to-end (free -> UNKNOWN, paid -> verdict)
# ---------------------------------------------------------------------------

class EndToEndTests(unittest.TestCase):
    def _six_tool_catalog(self):
        return ["tool_%d" % i for i in range(6)]

    def test_free_tier_out_of_scope_paid_tier_verdict(self):
        # A 6-tool catalog exceeds the free tier cap (max_tools=5) ->
        # UNKNOWN (exit 2). The paid tier (max_tools=100) proves it ->
        # PROVEN (exit 0). The policy governs exactly the six catalog tools
        # (3 allowed, 3 denied) so the structural check is clean.
        catalog = self._six_tool_catalog()
        allowed, denied = catalog[:3], catalog[3:]

        free = lic.resolve_budget(tier="free")
        paid = lic.resolve_budget(tier="paid")

        r_free = mcp.audit_mcp(allowed, denied, tools=catalog, budget=free)
        self.assertEqual(r_free.result(), "unknown")
        self.assertEqual(r_free.exit_code(), 2)
        self.assertTrue(r_free.any_unknown)
        self.assertIn("tool catalog", r_free.note)

        r_paid = mcp.audit_mcp(allowed, denied, tools=catalog, budget=paid)
        self.assertEqual(r_paid.result(), "proven")
        self.assertEqual(r_paid.exit_code(), 0)
        self.assertFalse(r_paid.any_unknown)
        self.assertEqual(r_paid.note, "")

    def test_free_tier_within_scope(self):
        # A 3-tool catalog is within the free tier cap (max_tools=5) ->
        # PROVEN (exit 0) even on the free tier. The policy governs exactly
        # the three catalog tools (2 allowed, 1 denied).
        catalog = ["tool_0", "tool_1", "tool_2"]
        allowed, denied = catalog[:2], catalog[2:]

        free = lic.resolve_budget(tier="free")
        r = mcp.audit_mcp(allowed, denied, tools=catalog, budget=free)
        self.assertEqual(r.result(), "proven")
        self.assertEqual(r.exit_code(), 0)
        self.assertFalse(r.any_unknown)

    def test_license_budget_caps_tools(self):
        # A license with a tight max_tools cap (3) makes a 6-tool catalog
        # out of scope (UNKNOWN), while the paid tier proves it. The policy
        # governs exactly the six catalog tools (3 allowed, 3 denied).
        limits = {"max_states": 1000000, "max_horizon": 12,
                  "max_tools": 3, "max_tenant_scopes": 10}
        body = lic.make_license("acme", "paid", limits=limits, key=KEY)
        license_obj = lic.License.from_dict(body)
        budget = lic.resolve_budget(license=license_obj)

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

    def test_manifest_tenant_scope_cap(self):
        # A manifest with 3 distinct tenant scopes exceeds the free tier cap
        # (max_tenant_scopes=1) -> out of scope (any_unknown). The paid tier
        # (max_tenant_scopes=10) is in scope.
        manifest = self._multi_tenant_manifest(3)
        free = lic.resolve_budget(tier="free")
        paid = lic.resolve_budget(tier="paid")

        r_free = mcp.audit_manifest(manifest, budget=free)
        self.assertTrue(r_free.any_unknown)
        self.assertIn("tenant scopes", r_free.note)

        r_paid = mcp.audit_manifest(manifest, budget=paid)
        self.assertFalse(r_paid.any_unknown)
        self.assertEqual(r_paid.note, "")

    def test_manifest_within_tenant_scope(self):
        # A manifest with a single tenant scope is in scope on the free tier.
        manifest = self._multi_tenant_manifest(1)
        free = lic.resolve_budget(tier="free")
        r = mcp.audit_manifest(manifest, budget=free)
        self.assertFalse(r.any_unknown)
        self.assertEqual(r.note, "")


# ---------------------------------------------------------------------------
# D1. key_from_env
# ---------------------------------------------------------------------------

class KeyFromEnvTests(unittest.TestCase):
    def test_default_key(self):
        saved = os.environ.pop(lic.KEY_ENV, None)
        try:
            self.assertEqual(lic.key_from_env(), lic.DEFAULT_KEY)
        finally:
            if saved is not None:
                os.environ[lic.KEY_ENV] = saved

    def test_env_override(self):
        saved = os.environ.get(lic.KEY_ENV)
        os.environ[lic.KEY_ENV] = "env-override-key"
        try:
            self.assertEqual(lic.key_from_env(), "env-override-key")
        finally:
            if saved is None:
                os.environ.pop(lic.KEY_ENV, None)
            else:
                os.environ[lic.KEY_ENV] = saved

    def test_env_empty_falls_back(self):
        saved = os.environ.get(lic.KEY_ENV)
        os.environ[lic.KEY_ENV] = ""
        try:
            self.assertEqual(lic.key_from_env(), lic.DEFAULT_KEY)
        finally:
            if saved is None:
                os.environ.pop(lic.KEY_ENV, None)
            else:
                os.environ[lic.KEY_ENV] = saved


if __name__ == "__main__":
    unittest.main(verbosity=2)
