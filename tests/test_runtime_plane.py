# -*- coding: utf-8 -*-
"""Tests for the runtime plane **core** (rot.runtime) -- Product 2, B1..B5.

The runtime plane enforces the *same* rules live that the offline plane proves
(statically): the agent proposes, the deterministic core decides, the refusal
is the exact shape ``{blocked, rule, why, to_proceed, allowed_now}``, and every
decision can land in an append-only hash-chained ledger.

This file covers the **core** (Apache-2.0) surface:
  * B1 core -- ``RuntimeGuard`` + the canonical rules;
  * B2 refusal -- the exact five-field shape, deterministic + hashable;
  * B5 ledger -- the append-only, hash-chained, fail-closed ledger;
  * the ``rot runtime eval`` CLI exit codes.

The **service** surface -- the B3 LangChain adapter, the B4 MCP ``tools/call``
gateway, and the B5 fleet aggregate (``rot coach --aggregate``) -- lives in
the commercial layer and is tested in ``rot/commercial/tests/test_runtime_plane_service.py``
(Apache-2.0).

Run: python tests/test_runtime_plane.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.runtime.core import ALLOWED, BLOCKED, RuntimeGuard  # noqa: E402
from rot.runtime.rules import (  # noqa: E402
    RULES, get_rule, spendcap_rule, exfiltration_rule)
from rot.runtime.refusal import Refusal, FIELDS, refusal_hash  # noqa: E402
from rot.runtime.ledger import (  # noqa: E402
    DecisionLedger, ChainBreak, LedgerError, GENESIS_HASH)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _spend_guard(**kw):
    """A RuntimeGuard for the spend-cap rule (defaults: K=4, A=100, C=200)."""
    return RuntimeGuard(spendcap_rule(**kw))


def _decide(guard, state):
    return guard.decide(state=state, request={"tool": "transfer"})


# ---------------------------------------------------------------------------
# B2: the refusal shape
# ---------------------------------------------------------------------------
class RefusalShapeTests(unittest.TestCase):
    """The refusal is the exact five-field shape, deterministic + hashable."""

    def test_exactly_the_five_fields(self):
        d = _decide(_spend_guard(), {"completed": 0, "inflight": 3})
        for f in FIELDS:
            self.assertIn(f, d.refusal.body, "missing refusal field %r" % f)

    def test_blocked_and_allowed_now_are_complements(self):
        d = _decide(_spend_guard(), {"completed": 0, "inflight": 3})
        self.assertTrue(d.refusal.blocked)
        self.assertFalse(d.refusal.allowed_now)
        d2 = _decide(_spend_guard(), {"completed": 0, "inflight": 0})
        self.assertFalse(d2.refusal.blocked)
        self.assertTrue(d2.refusal.allowed_now)
        # The two readings never disagree.
        self.assertEqual(d.refusal.blocked, not d.refusal.allowed_now)
        self.assertEqual(d2.refusal.blocked, not d2.refusal.allowed_now)

    def test_deterministic_hash(self):
        a = _decide(_spend_guard(), {"completed": 0, "inflight": 3})
        b = _decide(_spend_guard(), {"completed": 0, "inflight": 3})
        self.assertEqual(a.refusal.hash, b.refusal.hash)
        self.assertEqual(a.refusal.refusal_id, b.refusal.refusal_id)
        self.assertEqual(a.refusal.to_json(), b.refusal.to_json())

    def test_hash_changes_with_input(self):
        a = _decide(_spend_guard(), {"completed": 0, "inflight": 3})
        b = _decide(_spend_guard(), {"completed": 0, "inflight": 2})
        self.assertNotEqual(a.refusal.hash, b.refusal.hash)

    def test_refusal_hash_is_sha256_of_canonical_body(self):
        r = Refusal(blocked=True, rule="x", why="w", to_proceed="p")
        self.assertEqual(r.hash, refusal_hash(r.body))
        self.assertEqual(len(r.hash), 64)


# ---------------------------------------------------------------------------
# B1: the deterministic core
# ---------------------------------------------------------------------------
class RuntimeGuardTests(unittest.TestCase):
    """The core decides by evaluating the guard (the spec) in the state."""

    def test_spendcap_blocked_names_the_inflight_count(self):
        d = _decide(_spend_guard(), {"completed": 0, "inflight": 3})
        self.assertEqual(d.decision, BLOCKED)
        self.assertTrue(d.blocked)
        self.assertFalse(d.allowed)
        self.assertEqual(d.refusal.rule, "spendcap_within_cap")
        self.assertIn("3 in-flight", d.refusal.why)
        self.assertIn("complete 1 in-flight", d.refusal.to_proceed)

    def test_spendcap_allowed_within_cap(self):
        d = _decide(_spend_guard(), {"completed": 0, "inflight": 0})
        self.assertEqual(d.decision, ALLOWED)
        self.assertTrue(d.allowed)
        self.assertFalse(d.refusal.blocked)
        self.assertEqual(d.refusal.why, "")

    def test_boundary_is_exact(self):
        # 1 in-flight: 1*100 + 100 == 200 <= 200 -> allowed.
        self.assertTrue(_decide(_spend_guard(),
                                {"completed": 0, "inflight": 1}).allowed)
        # 2 in-flight: 2*100 + 100 > 200 -> blocked.
        self.assertTrue(_decide(_spend_guard(),
                                {"completed": 0, "inflight": 2}).blocked)

    def test_undefined_state_is_fail_closed(self):
        # An unset variable reads UNDEF -> never allowed (fail-closed).
        d = _decide(_spend_guard(), {})
        self.assertTrue(d.blocked)
        self.assertEqual(d.decision, BLOCKED)

    def test_exfiltration_rule(self):
        guard = RuntimeGuard(exfiltration_rule())
        d = guard.decide(state={"holding_private": True},
                         request={"tool": "send"})
        self.assertTrue(d.blocked)
        self.assertEqual(d.refusal.rule, "no_exfiltration")
        d2 = guard.decide(state={"holding_private": False},
                          request={"tool": "send"})
        self.assertTrue(d2.allowed)

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(ValueError):
            RuntimeGuard(spendcap_rule(), action="no_such_action")

    def test_guard_requires_a_rule(self):
        with self.assertRaises(TypeError):
            RuntimeGuard("not a rule")


class RulesRegistryTests(unittest.TestCase):
    """The registry of genuinely-reusable rules."""

    def test_get_rule_returns_known_rules(self):
        self.assertEqual(get_rule("spendcap_within_cap").rule_id,
                         "spendcap_within_cap")
        self.assertEqual(get_rule("no_exfiltration").rule_id,
                         "no_exfiltration")

    def test_unknown_rule_raises(self):
        with self.assertRaises(KeyError):
            get_rule("nope")

    def test_registry_covers_both_shapes(self):
        self.assertEqual(set(RULES), {"spendcap_within_cap",
                                      "no_exfiltration"})

    def test_rule_is_parametric(self):
        # The cap: a bigger cap admits a higher in-flight count (K=4).
        tight = _decide(_spend_guard(cap=200), {"completed": 0, "inflight": 1})
        loose = _decide(_spend_guard(cap=1000),
                        {"completed": 0, "inflight": 3})
        self.assertTrue(tight.allowed)   # 0+100+100 <= 200 and 1 < 4
        self.assertTrue(loose.allowed)   # 0+300+100 <= 1000 and 3 < 4
        # The pool bound K: a smaller K blocks even within the cap.
        k1 = _decide(_spend_guard(cap=1000, max_inflight=1),
                     {"completed": 0, "inflight": 1})
        self.assertTrue(k1.blocked)      # 200 <= 1000, but 1 < 1 fails


# ---------------------------------------------------------------------------
# B5: the append-only hash-chained ledger
# ---------------------------------------------------------------------------
class LedgerTests(unittest.TestCase):
    """Append-only, hash-chained, fail-closed on any tamper."""

    def _sample(self):
        guard = _spend_guard()
        ledger = DecisionLedger()
        for inflight in (0, 1, 3):
            d = _decide(guard, {"completed": 0, "inflight": inflight})
            ledger.record("transfer", {"amount": 100},
                          {"completed": 0, "inflight": inflight}, d)
        return ledger

    def test_chain_verifies(self):
        ledger = self._sample()
        self.assertTrue(ledger.verify())
        self.assertEqual(len(ledger), 3)
        self.assertEqual(ledger[0].prev_hash, GENESIS_HASH)

    def test_tampering_breaks_the_chain(self):
        text = self._sample().to_jsonl()
        # Flip the first entry's decision (a semantic edit).
        lines = text.splitlines()
        d = json.loads(lines[0])
        d["refusal"]["blocked"] = (not d["refusal"]["blocked"])
        lines[0] = json.dumps(d, sort_keys=True)
        with self.assertRaises((ChainBreak, LedgerError)):
            DecisionLedger.from_jsonl("\n".join(lines)).verify()

    def test_roundtrip_jsonl(self):
        ledger = self._sample()
        back = DecisionLedger.from_jsonl(ledger.to_jsonl())
        self.assertEqual(len(back), len(ledger))
        self.assertEqual(back.last_entry_hash(), ledger.last_entry_hash())
        self.assertTrue(back.verify())

    def test_roundtrip_file(self):
        ledger = self._sample()
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False)
        try:
            tmp.write(ledger.to_jsonl())
            tmp.close()
            back = DecisionLedger.from_file(tmp.name)
            self.assertEqual(back.last_entry_hash(), ledger.last_entry_hash())
            self.assertTrue(back.verify())
        finally:
            os.unlink(tmp.name)

    def test_deterministic_serialization(self):
        self.assertEqual(self._sample().to_jsonl(), self._sample().to_jsonl())
        self.assertEqual(self._sample().to_json(), self._sample().to_json())

    def test_empty_ledger_is_genesis(self):
        ledger = DecisionLedger()
        self.assertEqual(len(ledger), 0)
        self.assertEqual(ledger.last_entry_hash(), GENESIS_HASH)
        self.assertTrue(ledger.verify())


# ---------------------------------------------------------------------------
# The CLI (rot runtime eval) -- the core surface
# ---------------------------------------------------------------------------
class CliTests(unittest.TestCase):
    """Exit codes: 0 allowed, 1 blocked, 3 error (the core ``runtime eval``)."""

    def _run(self, *argv):
        proc = subprocess.run(
            [sys.executable, "-m", "rot"] + list(argv),
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")

    def test_runtime_eval_blocked_is_exit_1(self):
        code, out = self._run(
            "runtime", "eval", "--tool", "transfer",
            "--state", json.dumps({"completed": 0, "inflight": 3}),
            "--quiet")
        self.assertEqual(code, 1)
        self.assertIn('"blocked": true', out)

    def test_runtime_eval_allowed_is_exit_0(self):
        code, out = self._run(
            "runtime", "eval", "--tool", "transfer",
            "--state", json.dumps({"completed": 0, "inflight": 0}),
            "--quiet")
        self.assertEqual(code, 0)
        self.assertIn('"blocked": false', out)

    def test_runtime_eval_unknown_rule_is_exit_3(self):
        code, _ = self._run("runtime", "eval", "--rule", "nope",
                            "--tool", "x")
        self.assertEqual(code, 3)

    def test_runtime_eval_requires_a_tool(self):
        code, _ = self._run("runtime", "eval")
        self.assertEqual(code, 3)

if __name__ == "__main__":
    unittest.main(verbosity=2)