# -*- coding: utf-8 -*-
"""Tests for the runtime plane (rot.runtime) -- Product 2, the B1..B5 surface.

The runtime plane enforces the *same* rules live that the offline plane proves
(statically): the agent proposes, the deterministic core decides, the refusal
is the exact shape ``{blocked, rule, why, to_proceed, allowed_now}``, every
decision lands in an append-only hash-chained ledger, and the coach can
aggregate that ledger and re-prove (or refute) any relaxation.

Coverage: B1 core (RuntimeGuard + the canonical rules); B2 refusal (the exact
five-field shape, deterministic + hashable); B3 LangChain adapter (the
Runnable-protocol GuardRunner, fail-closed, optional glue); B4 MCP (the
tools/call interceptor, JSON-RPC 2.0, the Manifest as first-class input);
B5 coach (the hash-chained ledger + the aggregate: blocked_by /
legitimate_work / relaxation re-proof, fail-closed); and the CLI exit codes.

Run: python tests/test_runtime_plane.py
"""

import importlib.util
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
from rot.runtime.langchain import (  # noqa: E402
    GuardRunner, LangChainNotInstalled, langchain_runnable,
    tool_name, tool_args)
from rot.runtime.mcp import (  # noqa: E402
    McpGateway, intercept_tools_call, PARSE_ERROR, INVALID_REQUEST,
    METHOD_NOT_FOUND, INVALID_PARAMS)
from rot.runtime.ledger import (  # noqa: E402
    DecisionLedger, ChainBreak, LedgerError, GENESIS_HASH)
from rot.runtime import aggregate as agg  # noqa: E402

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
# B3: the LangChain adapter (pure-stdlib core)
# ---------------------------------------------------------------------------
class LangChainAdapterTests(unittest.TestCase):
    """GuardRunner routes every tool call through the core (Runnable protocol)."""

    def _runner(self, **kw):
        return GuardRunner(guard=_spend_guard(), **kw)

    def test_invoke_returns_the_envelope(self):
        env = self._runner().invoke(
            {"name": "transfer", "args": {"amount": 100},
             "state": {"completed": 0, "inflight": 3}})
        self.assertIn("refusal", env)
        self.assertTrue(env["refusal"]["blocked"])
        self.assertEqual(env["refusal"]["rule"], "spendcap_within_cap")
        self.assertEqual(env["tool"], "transfer")
        for f in FIELDS:
            self.assertIn(f, env["refusal"])

    def test_invoke_allowed(self):
        env = self._runner().invoke(
            {"name": "transfer", "state": {"completed": 0, "inflight": 0}})
        self.assertFalse(env["refusal"]["blocked"])
        self.assertTrue(env["refusal"]["allowed_now"])

    def test_invoke_records_to_the_ledger(self):
        ledger = DecisionLedger()
        self._runner(ledger=ledger).invoke(
            {"name": "transfer", "state": {"completed": 0, "inflight": 3}})
        self._runner(ledger=ledger).invoke(
            {"name": "transfer", "state": {"completed": 0, "inflight": 0}})
        self.assertEqual(len(ledger), 2)
        ledger.verify()

    def test_unruled_tool_is_fail_closed(self):
        runner = GuardRunner(rules={})  # no rules, no default
        with self.assertRaises(KeyError):
            runner.invoke({"name": "transfer"})

    def test_per_tool_rules(self):
        runner = GuardRunner(rules={"transfer": spendcap_rule(),
                                    "send": exfiltration_rule()})
        env = runner.invoke(
            {"name": "transfer", "state": {"completed": 0, "inflight": 3}})
        self.assertTrue(env["refusal"]["blocked"])
        env2 = runner.invoke(
            {"name": "send", "state": {"holding_private": True}})
        self.assertTrue(env2["refusal"]["blocked"])
        self.assertEqual(env2["refusal"]["rule"], "no_exfiltration")

    def test_guard_and_rules_are_exclusive(self):
        with self.assertRaises(ValueError):
            GuardRunner(guard=_spend_guard(), rules={"t": spendcap_rule()})

    def test_tool_call_normalization(self):
        self.assertEqual(tool_name({"name": "x"}), "x")
        self.assertEqual(tool_name({"tool": "x"}), "x")
        self.assertEqual(tool_name({"function": {"name": "x"}}), "x")
        self.assertIsNone(tool_name({"no_name": 1}))
        self.assertEqual(tool_args({"args": {"a": 1}}), {"a": 1})
        self.assertEqual(tool_args({"input": '{"a": 2}'}), {"a": 2})
        self.assertEqual(tool_args({}), {})

    def test_langchain_glue_requires_langchain(self):
        if importlib.util.find_spec("langchain_core") is None:
            with self.assertRaises(LangChainNotInstalled):
                langchain_runnable(_spend_guard())
        else:  # pragma: no cover - CI has no LangChain
            obj = langchain_runnable(_spend_guard())
            self.assertTrue(hasattr(obj, "invoke"))


# ---------------------------------------------------------------------------
# B4: the MCP adapter (the tools/call interceptor)
# ---------------------------------------------------------------------------
class McpGatewayTests(unittest.TestCase):
    """The JSON-RPC 2.0 gateway: ping / tools/* / rot/* + fail-closed."""

    def _gw(self, **kw):
        return McpGateway(default_rule=get_rule("spendcap_within_cap"), **kw)

    def _call(self, gw, **params):
        return gw.handle_message({"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/call", "params": params})

    def test_ping(self):
        resp = self._gw().handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(resp["result"], "pong")

    def test_tools_call_blocked(self):
        resp = self._call(self._gw(), name="transfer",
                          state={"completed": 0, "inflight": 3})
        sc = resp["result"]["structuredContent"]
        self.assertTrue(sc["blocked"])
        self.assertTrue(resp["result"]["isError"])
        self.assertEqual(sc["rule"], "spendcap_within_cap")

    def test_tools_call_allowed(self):
        resp = self._call(self._gw(), name="transfer",
                          state={"completed": 0, "inflight": 0})
        sc = resp["result"]["structuredContent"]
        self.assertFalse(sc["blocked"])
        self.assertFalse(resp["result"]["isError"])

    def test_unruled_tool_is_fail_closed(self):
        gw = McpGateway(rules={})  # no default rule
        resp = self._call(gw, name="transfer")
        self.assertTrue(resp["result"]["structuredContent"]["blocked"])

    def test_methods_and_error_codes(self):
        gw = self._gw()
        resp = gw.handle_message("{not json")
        self.assertEqual(resp["error"]["code"], PARSE_ERROR)
        resp = gw.handle_message({"id": 1, "method": "ping"})
        self.assertEqual(resp["error"]["code"], INVALID_REQUEST)
        resp = gw.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "nope"})
        self.assertEqual(resp["error"]["code"], METHOD_NOT_FOUND)
        resp = gw.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"state": {}}})
        self.assertEqual(resp["error"]["code"], INVALID_PARAMS)

    def test_json_string_messages(self):
        gw = self._gw()
        resp = gw.handle_message(json.dumps(
            {"jsonrpc": "2.0", "id": 9, "method": "ping"}))
        self.assertEqual(resp["id"], 9)
        self.assertEqual(resp["result"], "pong")

    def test_ledger_is_recorded_and_dumped(self):
        ledger = DecisionLedger()
        gw = self._gw(ledger=ledger)
        self._call(gw, name="transfer", state={"completed": 0, "inflight": 3})
        self._call(gw, name="transfer", state={"completed": 0, "inflight": 0})
        resp = gw.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "rot/ledger"})
        body = resp["result"]
        self.assertEqual(len(body["entries"]), 2)
        self.assertEqual(body["entries"][0]["seq"], 0)
        self.assertEqual(body["entries"][1]["seq"], 1)

    def test_rot_rules_and_info(self):
        gw = self._gw()
        resp = gw.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "rot/rules"})
        self.assertIn("spendcap_within_cap", json.dumps(resp["result"]))
        resp = gw.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "rot/info"})
        self.assertIn("result", resp)

    def test_intercept_tools_call_helper(self):
        out = intercept_tools_call(_spend_guard(), "transfer",
                                   state={"completed": 0, "inflight": 3})
        self.assertTrue(out["isError"])
        self.assertTrue(out["structuredContent"]["blocked"])
        self.assertEqual(out["_rotn"]["decision"], "blocked")

    def test_manifest_is_first_class_input(self):
        manifest = {
            "manifest": "caravel.mcp-manifest/v1",
            "server": "test", "version": "1", "tenant_scope": "tenant",
            "tools": [{"name": "transfer", "description": "x"}],
        }
        gw = McpGateway(default_rule=get_rule("spendcap_within_cap"),
                        manifest=manifest)
        resp = gw.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertIn("transfer", json.dumps(resp["result"]))


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
# B5: the aggregate (the runtime coach over the ledger)
# ---------------------------------------------------------------------------
class AggregateTests(unittest.TestCase):
    """blocked_by / legitimate_work / the relaxation re-proof (fail-closed)."""

    def _ledger(self):
        guard = _spend_guard()
        ledger = DecisionLedger()
        for inflight in (0, 1, 3):
            d = _decide(guard, {"completed": 0, "inflight": inflight})
            ledger.record("transfer", {"amount": 100},
                          {"completed": 0, "inflight": inflight}, d)
        return ledger

    def test_report_shape(self):
        res = agg.aggregate_ledger(
            self._ledger(), rule=get_rule("spendcap_within_cap"))
        body = res.body
        self.assertEqual(body["schema"], agg.SCHEMA)
        self.assertEqual(body["ledger"]["entries"], 3)
        self.assertEqual(body["ledger"]["blocked"], 1)
        self.assertEqual(body["ledger"]["allowed"], 2)
        self.assertEqual(body["blocked_by"]["by_tool"]["transfer"], 1)
        self.assertEqual(
            body["blocked_by"]["by_rule"]["spendcap_within_cap"],
            {"blocked": 1, "allowed": 2, "total": 3})
        self.assertEqual(len(body["legitimate_work"]), 1)
        self.assertEqual(body["legitimate_work"][0]["rule"],
                         "spendcap_within_cap")
        self.assertEqual(body["top_blockers"][0]["rule"],
                         "spendcap_within_cap")

    def test_relaxation_is_unsafe_with_the_rule(self):
        # Admitting the blocked call (3 in-flight) would take in-flight to
        # 4, which breaches the cap -> UNSAFE with a witness.
        res = agg.aggregate_ledger(
            self._ledger(), rule=get_rule("spendcap_within_cap"))
        rel = res.body["relaxation"]
        self.assertEqual(rel["status"], agg.UNSAFE)
        self.assertFalse(rel["safe"])
        self.assertIsNotNone(rel["witness"])

    def test_relaxation_is_unverified_without_a_rule(self):
        res = agg.aggregate_ledger(self._ledger())
        self.assertEqual(res.body["relaxation"]["status"], agg.UNVERIFIED)

    def test_no_blocks_is_not_applicable(self):
        guard = _spend_guard()
        ledger = DecisionLedger()
        d = _decide(guard, {"completed": 0, "inflight": 0})
        ledger.record("transfer", {}, {}, d)
        res = agg.aggregate_ledger(
            ledger, rule=get_rule("spendcap_within_cap"))
        self.assertEqual(res.body["relaxation"]["status"],
                         agg.NOT_APPLICABLE)

    def test_compliance_mapping_is_present(self):
        res = agg.aggregate_ledger(
            self._ledger(), rule=get_rule("spendcap_within_cap"))
        comp = res.body["compliance"]
        self.assertEqual(comp["finding"], "Overly Restrictive")
        self.assertIn("SOC2", comp["frameworks"])
        self.assertIn("CC6.6", comp["controls"])

    def test_deterministic_hash(self):
        rule = get_rule("spendcap_within_cap")
        self.assertEqual(
            agg.aggregate_ledger(self._ledger(), rule=rule).hash,
            agg.aggregate_ledger(self._ledger(), rule=rule).hash)

    def test_refuses_a_broken_chain(self):
        ledger = self._ledger()
        ledger[0].refusal["why"] = "edited"  # tamper
        with self.assertRaises((ChainBreak, LedgerError)):
            agg.aggregate_ledger(
                ledger, rule=get_rule("spendcap_within_cap"))


# ---------------------------------------------------------------------------
# The CLI (rot runtime eval / rot coach --aggregate)
# ---------------------------------------------------------------------------
class CliTests(unittest.TestCase):
    """Exit codes: 0 allowed/proven, 1 blocked/unsafe, 2 unverified, 3 error."""

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

    def test_coach_aggregate_unsafe_is_exit_1(self):
        guard = _spend_guard()
        ledger = DecisionLedger()
        for inflight in (0, 3):
            d = _decide(guard, {"completed": 0, "inflight": inflight})
            ledger.record("transfer", {}, {"inflight": inflight}, d)
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False)
        try:
            tmp.write(ledger.to_jsonl())
            tmp.close()
            code, out = self._run("coach", "--aggregate",
                                  "--ledger", tmp.name, "--quiet")
            self.assertEqual(code, 1)
            body = json.loads(out)
            self.assertEqual(body["schema"], agg.SCHEMA)
            self.assertEqual(body["relaxation"]["status"], agg.UNSAFE)
        finally:
            os.unlink(tmp.name)

    def test_coach_aggregate_requires_a_ledger(self):
        code, _ = self._run("coach", "--aggregate")
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)