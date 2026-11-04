# -*- coding: utf-8 -*-
"""Tests for the one-pager AS AN ATTESTATION (:mod:`rot.attestation`, B3).

The attestation is the underwriter's view -- a deterministic, hashable,
re-issuable artifact derived FROM the RTF v1 trace (the source of truth).
These tests pin the B3 contract:

  * **B3.2** -- the attestation carries the trace's SHA-256 hash + the exact
    re-verify command + the expected hash (so the underwriter re-derives it
    byte-for-byte); the assumptions rendered as coverage conditions (K >= 2,
    CAP, AMOUNT, bounded pool); verdict / scope / out-of-scope /
    counterexample; SOC 2 / AIUC controls; ``version = policy-hash +
    engine-version``; and the bounded caveat (C4).
  * **B3.3** -- the artifact hierarchy is stated once (RTF v1 = source of
    truth -> one-pager = underwriter view -> site = demo view).
  * **B3.4** -- determinism: re-running on the same trace yields byte-identical
    Markdown and HTML; and staleness: tampering the policy (a different trace)
    changes the hash and marks the attestation STALE (a liability, never a
    silent re-proof).

Run: python tests/test_attestation.py
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot  # noqa: E402
import rot.attestation as att  # noqa: E402
import rot.__main__ as m  # noqa: E402


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FIX = os.path.join(_REPO, "tests", "fixtures", "aws_dogwood", "spendcap",
                    "policies")
_BUGGY = os.path.join(_FIX, "spendcap-buggy.dw")
_CORRECT = os.path.join(_FIX, "spendcap-correct.dw")


def _build_trace(policy_path):
    """Build a full RTF v1 trace dict for a spend-cap policy (the source of
    truth the attestation is derived from)."""
    a = argparse.Namespace(
        policy=policy_path, kind=None, max_inflight=None, amount=None,
        cap=None, out=None, quiet=True, liveness_horizon=None,
        depth=None)
    budget = m._resolve_budget(a)
    result, _code = m._trace_policy(policy_path, a, budget, 12)
    return result.to_dict()


def _att(policy_path):
    """Build the attestation for a policy (helper for the tests below)."""
    return att.build_attestation(_build_trace(policy_path))


class BuildTests(unittest.TestCase):
    """B3.2 -- the attestation carries the required underwriter fields."""

    def test_verdict_matches_trace(self):
        self.assertEqual(_att(_BUGGY).verdict(), "violated")
        self.assertEqual(_att(_CORRECT).verdict(), "proven")

    def test_pins_the_trace_hash(self):
        trace = _build_trace(_BUGGY)
        a = att.build_attestation(trace)
        self.assertEqual(a.body["source_trace"]["hash"], trace["hash"])
        self.assertEqual(a.body["reverify"]["expected_hash"], trace["hash"])

    def test_verify_trace_hash_recomputes(self):
        trace = _build_trace(_BUGGY)
        self.assertEqual(att.verify_trace_hash(trace), trace["hash"])

    def test_version_is_policy_hash_plus_engine(self):
        v = _att(_BUGGY).body["version"]
        self.assertTrue(v["id"].endswith("+%s" % rot.__version__))
        self.assertIn(v["policy_hash"][:16], v["id"])
        self.assertEqual(v["engine_version"], rot.__version__)

    def test_different_policies_different_versions(self):
        vb = _att(_BUGGY).body["version"]
        vc = _att(_CORRECT).body["version"]
        self.assertNotEqual(vb["id"], vc["id"])
        self.assertNotEqual(vb["policy_hash"], vc["policy_hash"])

    def test_coverage_conditions_rendered(self):
        conds = "\n".join(_att(_BUGGY).body["coverage_conditions"])
        for token in ("AMOUNT =", "CAP =", "bounded pool", "K >= 2", "n_states"):
            self.assertIn(token, conds, "missing: %s" % token)

    def test_controls_split_soc2_and_aiuc(self):
        controls = _att(_BUGGY).body["controls"]
        self.assertTrue(all(c.startswith("CC") for c in controls["soc2"]))
        self.assertTrue(all(c.startswith("AIUC") for c in controls["aiuc"]))
        self.assertIn("CC6.1", controls["soc2"])
        self.assertIn("AIUC-1", controls["aiuc"])
        self.assertIn("CC6.1", controls["labels"])

    def test_counterexample_present_for_violated(self):
        self.assertIsNotNone(_att(_BUGGY).body["counterexample"])
        self.assertIsNone(_att(_CORRECT).body["counterexample"])

    def test_reverify_command_carries_expected_hash(self):
        a = _att(_BUGGY)
        cmd = a.body["reverify"]["command"]
        self.assertIn(a.body["reverify"]["expected_hash"], cmd)
        self.assertIn("rot report --verify-trace", cmd)
        self.assertIn("--expect", cmd)

    def test_bounded_caveat_always_present(self):
        for path in (_BUGGY, _CORRECT):
            caveat = _att(path).body["bounded_caveat"]
            self.assertIn("BOUNDED", caveat)
            self.assertIn("n_states", caveat)

    def test_scope_carries_property_and_bounds(self):
        scope = _att(_BUGGY).body["scope"]
        self.assertEqual(scope["property"], "spendcap_within_cap")
        self.assertEqual(scope["kind"], "safety")
        self.assertEqual(scope["amount"], 100)
        self.assertEqual(scope["cap"], 200)
        self.assertEqual(scope["max_inflight"], 4)
        self.assertEqual(scope["verdict"], "violated")

    def test_artifact_hierarchy_stated_once(self):
        hier = _att(_BUGGY).body["artifact_hierarchy"]
        self.assertEqual(hier[0]["schema"], "caravel.rtf/v1")
        self.assertEqual(hier[1]["schema"], att.SCHEMA)
        self.assertEqual(hier[1]["role"].split()[0], "underwriter")
        self.assertEqual(hier[2]["role"].split()[0], "demo")


class DeterminismTests(unittest.TestCase):
    """B3.4 -- re-running on the same trace yields byte-identical output."""

    def test_markdown_byte_identical(self):
        a1 = _att(_BUGGY)
        a2 = _att(_BUGGY)
        self.assertEqual(a1.to_markdown(), a2.to_markdown())
        self.assertEqual(a1.hash, a2.hash)

    def test_html_byte_identical(self):
        a1 = _att(_BUGGY)
        a2 = _att(_BUGGY)
        self.assertEqual(a1.to_html(), a2.to_html())

    def test_attestation_hash_is_sha256_of_body(self):
        a = _att(_BUGGY)
        self.assertEqual(a.hash, att.attestation_hash(a.body))

    def test_to_dict_includes_hash(self):
        a = _att(_BUGGY)
        d = a.to_dict()
        self.assertEqual(d["hash"], a.hash)
        self.assertNotIn("hash", a.body)

    def test_to_json_is_valid_json(self):
        d = json.loads(_att(_BUGGY).to_json())
        self.assertEqual(d["schema"], att.SCHEMA)
        self.assertEqual(d["verdict"], "violated")


class StalenessTests(unittest.TestCase):
    """B3.4 -- tamper the policy: hash changes and the attestation is STALE."""

    def test_same_trace_not_stale(self):
        a = _att(_BUGGY)
        self.assertFalse(att.is_stale(a.body, _build_trace(_BUGGY)))

    def test_tampered_policy_is_stale(self):
        # Issued for the BUGGY policy; the underwriter re-derives from the
        # CORRECTED policy -- a different hash, so STALE.
        a = _att(_BUGGY)
        self.assertTrue(att.is_stale(a.body, _build_trace(_CORRECT)))

    def test_hashes_differ(self):
        self.assertNotEqual(_build_trace(_BUGGY)["hash"],
                            _build_trace(_CORRECT)["hash"])

    def test_missing_pin_is_stale(self):
        self.assertTrue(att.is_stale(
            {"source_trace": {"hash": None}}, _build_trace(_BUGGY)))


class CliTests(unittest.TestCase):
    """B3.1 -- the ``rot report`` command (one-pager + the re-verify step)."""

    def _run(self, *argv):
        proc = subprocess.run(
            [sys.executable, "-m", "rot"] + list(argv),
            cwd=_REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=180)
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), \
            proc.stderr.decode("utf-8", "replace")

    def test_one_pager_emits_md_and_html(self):
        out_dir = tempfile.mkdtemp(prefix="rot-report-")
        trace_path = os.path.join(out_dir, "trace.json")
        try:
            # Build the trace (buggy -> exit 1 is expected; the trace file is
            # still written to the --out FILE path).
            self._run("trace", "--policy", _BUGGY, "--out", trace_path,
                      "--quiet")
            self.assertTrue(os.path.isfile(trace_path), "trace file missing")

            code, out, err = self._run(
                "report", "--one-pager", "--trace", trace_path,
                "--out", out_dir)
            self.assertEqual(code, 0, "one-pager failed:\n%s\n%s" % (out, err))
            md = os.path.join(out_dir, "one_pager.md")
            html = os.path.join(out_dir, "one_pager.html")
            self.assertTrue(os.path.isfile(md), "one_pager.md missing")
            self.assertTrue(os.path.isfile(html), "one_pager.html missing")
            self.assertIn("Attestation", open(md, encoding="utf-8").read())
            self.assertIn("<html", open(html, encoding="utf-8").read())

            # Re-run -> byte-identical (B3.4 determinism through the CLI).
            first_md = open(md, encoding="utf-8").read()
            code, _o, _e = self._run(
                "report", "--one-pager", "--trace", trace_path,
                "--out", out_dir)
            self.assertEqual(code, 0)
            self.assertEqual(first_md, open(md, encoding="utf-8").read())
        finally:
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)

    def test_verify_trace_match_and_stale(self):
        out_dir = tempfile.mkdtemp(prefix="rot-report-verify-")
        trace_path = os.path.join(out_dir, "trace.json")
        try:
            self._run("trace", "--policy", _BUGGY, "--out", trace_path,
                      "--quiet")
            self.assertTrue(os.path.isfile(trace_path), "trace file missing")
            with open(trace_path, encoding="utf-8") as fh:
                good_hash = json.load(fh)["hash"]

            # MATCH -> exit 0.
            code, out, _e = self._run(
                "report", "--verify-trace", trace_path, "--expect", good_hash)
            self.assertEqual(code, 0, "expected MATCH:\n%s" % out)
            self.assertIn("MATCH", out)

            # MISMATCH -> exit 1 (STALE).
            bad = "0" * 64
            code, _o, err = self._run(
                "report", "--verify-trace", trace_path, "--expect", bad)
            self.assertEqual(code, 1, "expected STALE (exit 1)")
            self.assertIn("STALE", err)
        finally:
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)


class UnderwriterAttestationTests(unittest.TestCase):
    """The underwriter attestation (v2): re-centered on the corrected policy,
    carrying the 3-engine cross-check, the finding (the buggy policy), and a
    distinct signature block over the content hash."""

    _CC = {
        "smt": {"engine": "smtz3", "status": "proven", "note": ""},
        "tlc": {"engine": "tlc", "status": "proven",
                "note": "TLC: invariant holds in all 6 reachable states",
                "n_states": 6},
        "policy_direct": {"engine": "policy_direct", "status": "proven",
                          "note": "policy_direct: obligation holds (steps=5)"},
        "joined": "proven",
    }
    _FINDING = {
        "artifact": "buggy policy (the original)",
        "verdict": "violated",
        "buggy_guard": "settled_count < cap",
        "fix": "charge in-flight",
        "corrected_guard": "inflight < cap",
    }

    def _uw(self, **kw):
        return att.build_underwriter_attestation(
            _build_trace(_CORRECT), crosscheck=dict(self._CC),
            finding=dict(self._FINDING), **kw)

    def test_schema_is_v2(self):
        self.assertEqual(self._uw().body["schema"], "caravel.attestation/v2")

    def test_subject_is_corrected_policy(self):
        s = self._uw().body["subject"]
        self.assertEqual(s["artifact"], "corrected policy")
        self.assertEqual(s["verdict"], "proven")

    def test_headline_verdict_is_corrected(self):
        self.assertEqual(self._uw().verdict(), "proven")

    def test_engines_carried(self):
        self.assertEqual(self._uw().body["engines"],
                         ["smtz3", "tlc", "policy_direct"])

    def test_crosscheck_joined_proven(self):
        self.assertEqual(self._uw().body["crosscheck"]["joined"], "proven")

    def test_finding_is_buggy_policy(self):
        f = self._uw().body["finding"]
        self.assertEqual(f["artifact"], "buggy policy (the original)")
        self.assertEqual(f["verdict"], "violated")

    def test_content_hash_is_attestation_hash(self):
        d = self._uw().to_dict()
        self.assertEqual(d["signature"]["signed_over"], d["hash"])

    def test_signature_degraded_without_key(self):
        sig = self._uw().body["signature"]
        self.assertTrue(sig["degraded"])
        self.assertEqual(sig["algorithm"], "content-hash-only")
        self.assertIsNone(sig.get("signature"))

    def test_verify_signature_ok(self):
        ok, _detail = att.verify_signature(self._uw().to_dict())
        self.assertTrue(ok)

    def test_tampered_body_rejects(self):
        d = self._uw().to_dict()
        d["verdict"] = "violated"
        ok, _detail = att.verify_signature(d)
        self.assertFalse(ok)

    def test_deterministic(self):
        a = self._uw()
        b = self._uw()
        self.assertEqual(a.to_json(), b.to_json())
        self.assertEqual(a.to_markdown(), b.to_markdown())
        self.assertEqual(a.to_html(), b.to_html())

    def test_markdown_has_new_sections(self):
        md = self._uw().to_markdown()
        for section in ("Subject (the attested artifact)",
                        "Cross-check (three independent engines)",
                        "Finding (the buggy policy",
                        "Signature (distinct from the content hash)"):
            self.assertIn(section, md)


class Ed25519ZeroDepSignatureTests(unittest.TestCase):
    """GAP 3 -- the asymmetric signature works with ZERO dependencies.

    ``cryptography`` is NOT installed in this environment (that is the whole
    point: ``pip install rotn`` must sign out of the box).  So a real Ed25519
    signature -- not the degraded content-hash-only block -- must be produced
    and verified using only the stdlib (:mod:`rot.ed25519`).
    """

    def _signed(self, private_pem):
        return att.build_underwriter_attestation(
            _build_trace(_CORRECT),
            crosscheck=dict(UnderwriterAttestationTests._CC),
            finding=dict(UnderwriterAttestationTests._FINDING),
            private_key_pem=private_pem)

    def test_signs_ed25519_without_cryptography(self):
        import rot.ed25519 as ed
        seed, _ = ed.generate_keypair()
        sig = self._signed(ed.private_key_pem(seed)).body["signature"]
        self.assertFalse(sig["degraded"])
        self.assertEqual(sig["algorithm"], "ed25519")
        self.assertIsNotNone(sig["signature"])
        self.assertIn("BEGIN PUBLIC KEY", sig["public_key"])

    def test_verify_ed25519_signature(self):
        import rot.ed25519 as ed
        seed, _ = ed.generate_keypair()
        ok, detail = att.verify_signature(
            self._signed(ed.private_key_pem(seed)).to_dict())
        self.assertTrue(ok, detail)

    def test_signature_is_deterministic(self):
        import rot.ed25519 as ed
        seed, _ = ed.generate_keypair()
        pem = ed.private_key_pem(seed)
        s1 = self._signed(pem).body["signature"]["signature"]
        s2 = self._signed(pem).body["signature"]["signature"]
        self.assertEqual(s1, s2)

    def test_wrong_public_key_fails(self):
        import rot.ed25519 as ed
        seed_a, _ = ed.generate_keypair()
        seed_b, _ = ed.generate_keypair()
        d = self._signed(ed.private_key_pem(seed_a)).to_dict()
        # Swap in a DIFFERENT public key: verification must now fail.
        d["signature"]["public_key"] = ed.public_key_pem(
            ed.public_key_from_seed(seed_b))
        ok, _detail = att.verify_signature(d)
        self.assertFalse(ok)

    def test_tampered_body_fails(self):
        import rot.ed25519 as ed
        seed, _ = ed.generate_keypair()
        d = self._signed(ed.private_key_pem(seed)).to_dict()
        d["verdict"] = "violated"
        ok, _detail = att.verify_signature(d)
        self.assertFalse(ok)


class AttestationCliSignByDefaultTests(unittest.TestCase):
    """GAP 3 item 8 -- ``rot attestation`` signs by default (generate-or-supply).

    With no ``--key`` given, the command must produce a REAL asymmetric Ed25519
    signature (not the degraded content-hash-only block), using a key it
    auto-generates on first run and reuses (deterministically) thereafter.  The
    default key location is pinned via ``ROTN_ATT_KEY`` so the test never
    touches the real ``~/.rotn`` key.
    """

    def _run_attestation(self, out_dir, key_path):
        import rot.__main__ as m
        old = os.environ.get("ROTN_ATT_KEY")
        os.environ["ROTN_ATT_KEY"] = key_path
        try:
            a = argparse.Namespace(
                policy=_CORRECT, finding_policy=None, signer=None,
                key=None, max_inflight=4, out=out_dir, quiet=True,
                kind=None, amount=None, cap=None, liveness_horizon=None,
                depth=None, verify=False, attestation=None)
            code = m.cmd_attestation(a)
            with open(os.path.join(
                    out_dir, "attestation-spendcap-correct.json"), "r") as f:
                return code, json.load(f)
        finally:
            if old is None:
                os.environ.pop("ROTN_ATT_KEY", None)
            else:
                os.environ["ROTN_ATT_KEY"] = old

    def test_signs_by_default_without_key(self):
        tmp = tempfile.mkdtemp()
        key_path = os.path.join(tmp, "attest-key.pem")
        code, d = self._run_attestation(tmp, key_path)
        self.assertEqual(code, 0)
        sig = d["signature"]
        self.assertFalse(sig["degraded"])
        self.assertEqual(sig["algorithm"], "ed25519")
        self.assertIsNotNone(sig["signature"])
        self.assertIn("BEGIN PUBLIC KEY", sig["public_key"])
        self.assertTrue(os.path.isfile(key_path))  # the key was generated

    def test_verify_by_default_signature(self):
        tmp = tempfile.mkdtemp()
        _code, d = self._run_attestation(tmp, os.path.join(tmp, "attest-key.pem"))
        ok, _detail = att.verify_signature(d)
        self.assertTrue(ok, _detail)

    def test_deterministic_reuse_of_generated_key(self):
        tmp = tempfile.mkdtemp()
        key_path = os.path.join(tmp, "attest-key.pem")
        _c1, d1 = self._run_attestation(tmp, key_path)
        _c2, d2 = self._run_attestation(tmp, key_path)
        self.assertEqual(d1["signature"]["signature"],
                         d2["signature"]["signature"])

    def test_explicit_key_overrides_default(self):
        import rot.ed25519 as ed
        tmp = tempfile.mkdtemp()
        # A key the user explicitly supplies (--key) must be the one used.
        seed, _ = ed.generate_keypair()
        explicit = os.path.join(tmp, "explicit-key.pem")
        with open(explicit, "w") as f:
            f.write(ed.private_key_pem(seed))
        a = argparse.Namespace(
            policy=_CORRECT, finding_policy=None, signer=None,
            key=explicit, max_inflight=4, out=tmp, quiet=True,
            kind=None, amount=None, cap=None, liveness_horizon=None,
            depth=None, verify=False, attestation=None)
        import rot.__main__ as m
        code = m.cmd_attestation(a)
        self.assertEqual(code, 0)
        with open(os.path.join(tmp, "attestation-spendcap-correct.json"), "r") as f:
            d = json.load(f)
        self.assertEqual(d["signature"]["algorithm"], "ed25519")
        self.assertFalse(d["signature"]["degraded"])
        ok, _detail = att.verify_signature(d)
        self.assertTrue(ok, _detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)