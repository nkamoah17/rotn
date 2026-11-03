# -*- coding: utf-8 -*-
"""Tests for the Product 2 runtime **service** plane (SSPL / commercial).

The deterministic *core* of the runtime plane (B1 ``RuntimeGuard``, B2 refusal
shape, B3 rules registry, B5 ledger, and the ``rot runtime eval`` CLI) is
covered by the **core** suite in ``tests/test_runtime_plane.py`` (Apache-2.0).
Here we test the *service* surface that wraps that core:

  * B3 -- the LangChain adapter (``rot.commercial.runtime.langchain``);
  * B4 -- the MCP ``tools/call`` gateway (``rot.commercial.runtime.mcp``);
  * B5 -- the fleet near-miss aggregate (``rot.commercial.runtime.aggregate``)
          + the ``rot coach --aggregate`` CLI.

Requires the ``rotn-commercial`` distribution (which depends on the ``rotn``
core).  See ``rot/commercial/LICENSE`` and ``docs/licensing.md``.

Run: python rot/commercial/tests/test_runtime_plane_service.py
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from rot.runtime.core import RuntimeGuard  # noqa: E402
from rot.runtime.rules import (  # noqa: E402
    get_rule, spendcap_rule, exfiltration_rule)
from rot.runtime.refusal import FIELDS  # noqa: E402
from rot.commercial.runtime.langchain import (  # noqa: E402
    GuardRunner, LangChainNotInstalled, langchain_runnable,
    tool_name, tool_args)
from rot.commercial.runtime.mcp import (  # noqa: E402
    McpGateway, intercept_tools_call, PARSE_ERROR, INVALID_REQUEST,
    METHOD_NOT_FOUND, INVALID_PARAMS)
from rot.runtime.ledger import (  # noqa: E402
    DecisionLedger, ChainBreak, LedgerError)
from rot.commercial.runtime import aggregate as agg  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _spend_guard(**kw):
    """A RuntimeGuard for the spend-cap rule (defaults: K=4, A=100, C=200)."""
    return RuntimeGuard(spendcap_rule(**kw))


def _decide(guard, state):
    return guard.decide(state=state, request={"tool": "transfer"})


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
# The CLI (rot coach --aggregate)
# ---------------------------------------------------------------------------
class CoachAggregateCliTests(unittest.TestCase):
    """``rot coach --aggregate``: the fleet-learning CLI exit codes (commercial)."""

    def _run(self, *argv):
        proc = subprocess.run(
            [sys.executable, "-m", "rot"] + list(argv),
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")

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