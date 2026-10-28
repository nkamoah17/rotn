# -*- coding: utf-8 -*-
"""Policy-frontend pipeline tests (Cedar + Dogwood).

These run the REAL policy pipeline (parse policy -> build ProtocolIR ->
validate -> ModelFinder reachability -> Verdict -> report) and assert:
  * the dispatcher routes by file extension (`.cedar` / `.json` / `.dw`)
  * ``build_ir`` validates and pins the correct property for each family
  * Dogwood safety is PROVEN on a conforming agent-step model
  * Cedar realizability is SAT (witness exists) on the sample policy
  * a buggy agent-step model VIOLATES the Dogwood safety property
  * the spend-cap ``.dw`` fixture: correct is PROVEN, buggy VIOLATES (the
    pinned property must be the real cap predicate, not ``Const(True)``)
  * the ``pipeline.py --policy`` CLI branch works end-to-end

Pure stdlib, Python 3.6 compatible.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pipeline  # noqa: E402
import rot.modelfind as modelfind  # noqa: E402
import rot.frontends.policy as policy_frontends  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_POL = os.path.join(_ROOT, "samples", "policy.json")
_TOOLS = os.path.join(_ROOT, "samples", "tools.json")
_CEDAR = os.path.join(_ROOT, "samples", "agent.cedar")
# The fetched AWS Dogwood spend-cap fixture (the one-word correct/buggy diff
# that exercises the parallel-fire race).
_DW_DIR = os.path.join(_ROOT, "tests", "fixtures", "aws_dogwood",
                       "spendcap", "policies")
_DW_CORRECT = os.path.join(_DW_DIR, "spendcap-correct.dw")
_DW_BUGGY = os.path.join(_DW_DIR, "spendcap-buggy.dw")
# The taint-egress fixture (the "never contact outsiders after touching
# confidential data" shape -- temporal + data-dependent).
_DW_TEGRESS_CORRECT = os.path.join(_DW_DIR, "taint-egress-correct.dw")
_DW_TEGRESS_BUGGY = os.path.join(_DW_DIR, "taint-egress-buggy.dw")


class DispatcherTests(unittest.TestCase):
    def test_routes_cedar(self):
        ir = policy_frontends.build_ir(_CEDAR, None, 1)
        meta = ir.metadata
        self.assertEqual(meta["family"], "CEDAR_POLICY")
        self.assertEqual(meta["property_kind"], "realizability")
        self.assertEqual(meta["property_name"], "policy_permits_request")

    def test_routes_dogwood(self):
        ir = policy_frontends.build_ir(_POL, _TOOLS, 1)
        meta = ir.metadata
        self.assertEqual(meta["family"], "AGENT_STEP")
        self.assertEqual(meta["frontend"], "dogwood")
        self.assertEqual(meta["property_kind"], "safety")
        self.assertEqual(meta["property_name"], "policy_conformance")

    def test_routes_dw_spendcap(self):
        # The .dw fixture routes to the spend-cap family (a Dogwood-derived
        # safety invariant), distinct from the JSON policy conformance model.
        # The front-end (rot.frontends.policy.dw) stamps family/frontend and
        # pins spendcap_within_cap; rot.spendcap supplies the protocol.
        ir = policy_frontends.build_ir(_DW_CORRECT, None, 1)
        meta = ir.metadata
        self.assertEqual(meta["family"], "SPENDCAP")
        self.assertEqual(meta["frontend"], "dw")
        self.assertEqual(meta["property_kind"], "safety")
        self.assertEqual(meta["property_name"], "spendcap_within_cap")
        self.assertEqual(meta.get("protocol"), "SPENDCAP")
        self.assertFalse(meta.get("buggy"))
        # Provenance back to the parsed .dw policy (via rot.dw.to_ir).
        self.assertEqual(meta.get("dw_event_kind"), "request")

    def test_dw_buggy_flag(self):
        ir = policy_frontends.build_ir(_DW_BUGGY, None, 1)
        self.assertTrue(ir.metadata.get("buggy"))
        # Same property, same state space; only the guard rule differs.
        self.assertEqual(ir.metadata["property_name"], "spendcap_within_cap")

    def test_dw_missing_file_raises(self):
        with self.assertRaises(policy_frontends.PolicyFrontendError):
            policy_frontends.build_ir(
                os.path.join(_DW_DIR, "no_such.dw"), None, 1)

    def test_unknown_extension_raises(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            with self.assertRaises(policy_frontends.PolicyFrontendError):
                policy_frontends.build_ir(path, None, 1)
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with self.assertRaises(policy_frontends.PolicyFrontendError):
            policy_frontends.build_ir(os.path.join(_ROOT, "no_such.cedar"), None, 1)

    def test_missing_tools_raises(self):
        with self.assertRaises(policy_frontends.PolicyFrontendError):
            policy_frontends.build_ir(_POL, os.path.join(_ROOT, "no_such_tools.json"), 1)


class BuildIrValidationTests(unittest.TestCase):
    def test_dogwood_ir_validates(self):
        ir = policy_frontends.build_ir(_POL, _TOOLS, 1)
        errors = ir.validate()
        self.assertEqual(errors, [], "validation errors: %r" % errors)
        self.assertIsNotNone(ir.pinned_property)

    def test_cedar_ir_validates(self):
        ir = policy_frontends.build_ir(_CEDAR, None, 1)
        errors = ir.validate()
        self.assertEqual(errors, [], "validation errors: %r" % errors)
        self.assertIsNotNone(ir.pinned_property)

    def test_dogwood_pinned_property_shape(self):
        ir = policy_frontends.build_ir(_POL, _TOOLS, 1)
        # States are plain mappings over the 'decision' state variable.
        # Idle: the agent has not taken a denied action -> property holds.
        self.assertTrue(ir.pinned_property.eval({"decision": "idle"}),
                        "idle must satisfy the conformance property")
        # The policy denies 'exfiltrate_secret' (samples/policy.json).
        self.assertFalse(
            ir.pinned_property.eval({"decision": "exfiltrate_secret"}),
            "a denied action must violate the conformance property")

    def test_dw_ir_validates(self):
        import rot.ir as irmod
        for path in (_DW_CORRECT, _DW_BUGGY):
            ir = policy_frontends.build_ir(path, None, 1)
            errors = ir.validate()
            self.assertEqual(errors, [], "validation errors: %r" % errors)
            # The pinned property must be the real cap predicate, not the
            # ProtocolIR default of Const(True) -- otherwise the soundness
            # core would vacuously "prove" even the buggy model.
            self.assertIsNotNone(ir.pinned_property)
            self.assertNotIsInstance(ir.pinned_property, irmod.Const)

    def test_dw_pinned_property_shape(self):
        import rot.spendcap as spendcap
        ir = policy_frontends.build_ir(_DW_CORRECT, None, 1)
        prop = ir.pinned_property
        amt, cap = spendcap.AMOUNT, spendcap.CAP
        # One request in flight (no settled amount) is within the cap.
        self.assertTrue(prop.eval({"completed": 0, "inflight": 1}),
                        "a single in-flight request must be within the cap")
        # Settled + in-flight exactly at the cap is still within it.
        self.assertTrue(prop.eval({"completed": cap - amt, "inflight": 1}))
        # A burst past the cap (in-flight not yet settled) violates it: this
        # is exactly the state the buggy model can reach and the correct one
        # cannot -- and it is what the soundness core must now catch.
        self.assertFalse(
            prop.eval({"completed": 0, "inflight": cap // amt + 1}),
            "settled + in-flight past the cap must violate the property")


class SemanticsTests(unittest.TestCase):
    def test_dogwood_conformance_proven(self):
        # The Dogwood frontend already carries the conforming agent-step
        # model: denied transitions are never-enabled, so conformance holds.
        ir = policy_frontends.build_ir(_POL, _TOOLS, 1)
        finder = modelfind.ModelFinder.from_ir(ir)
        ok, witness = finder.forall_reachable(lambda s: ir.pinned_property.eval(s))
        self.assertTrue(ok, "conforming agent-step model must be proven safe")
        self.assertIsNone(witness)

    def test_buggy_model_violates(self):
        import rot.agent_step as agent_step

        # Same policy as samples/policy.json, but the adversarial agent:
        # the denied action stays enabled, so a violating state is reachable.
        ir = agent_step.build_ir(n=1, buggy=True)
        finder = modelfind.ModelFinder.from_ir(ir)
        ok, counterexample = finder.forall_reachable(lambda s: ir.pinned_property.eval(s))
        self.assertFalse(ok, "buggy model must violate policy")
        self.assertIsNotNone(counterexample)

    def test_cedar_realizability_sat(self):
        ir = policy_frontends.build_ir(_CEDAR, None, 1)
        finder = modelfind.ModelFinder.from_ir(ir)
        sat, witness = finder.exists_reachable(lambda s: ir.pinned_property.eval(s))
        self.assertTrue(sat, "sample Cedar policy must be realizable")
        self.assertIsNotNone(witness)

    def test_dw_correct_proven(self):
        # The correct spend-cap model charges in-flight requests against the
        # cap, so settled + in-flight never exceeds it -- the safety invariant
        # holds over every reachable state.
        import rot.spendcap as spendcap
        ir = policy_frontends.build_ir(_DW_CORRECT, None, 1)
        finder = modelfind.ModelFinder.from_ir(ir)
        ok, witness = finder.forall_reachable(
            lambda s: ir.pinned_property.eval(s))
        self.assertTrue(ok, "correct spend-cap model must be proven within cap")
        self.assertIsNone(witness)

    def test_dw_buggy_violates(self):
        # The buggy spend-cap model charges settled responses only, so a
        # parallel burst of ``spend_ok`` (before any ``respond``) grows the
        # in-flight amount past the cap -- the soundness core must return a
        # counterexample, not vacuously prove it.
        import rot.spendcap as spendcap
        ir = policy_frontends.build_ir(_DW_BUGGY, None, 1)
        finder = modelfind.ModelFinder.from_ir(ir)
        ok, counterexample = finder.forall_reachable(
            lambda s: ir.pinned_property.eval(s))
        self.assertFalse(ok, "buggy spend-cap model must violate the cap")
        self.assertIsNotNone(counterexample)
        # The witness really is over the cap: settled + in-flight > CAP.
        amt, cap = spendcap.AMOUNT, spendcap.CAP
        settled = counterexample["completed"]
        inflight = counterexample["inflight"]
        self.assertGreater(settled + inflight * amt, cap,
                           "witness %r should exceed cap %d" % (counterexample, cap))
        # And it is not the vacuous default: the property is False there.
        self.assertFalse(ir.pinned_property.eval(counterexample))

    def test_taint_egress_correct_proven(self):
        # The correct taint-egress policy (request-trigger) admits the egress
        # only when the agent is NOT holding private data, so private data
        # never reaches an unapproved channel -- NoExfiltration holds over
        # every reachable state.
        ir = policy_frontends.build_ir(_DW_TEGRESS_CORRECT, None, 1)
        finder = modelfind.ModelFinder.from_ir(ir)
        ok, witness = finder.forall_reachable(
            lambda s: ir.pinned_property.eval(s))
        self.assertTrue(ok, "correct taint-egress model must be proven")
        self.assertIsNone(witness)
        # The pinned property is the real NoExfiltration predicate, not True.
        self.assertFalse(ir.pinned_property.eval(
            {"holding_private": True, "exfiltrated": True}))

    def test_taint_egress_buggy_violates(self):
        # The buggy taint-egress policy (response-trigger) admits the egress
        # unconditionally, so an agent that has touched confidential data can
        # contact an outsider while still holding it -- the model checker must
        # return the exfiltration state as a counterexample.
        ir = policy_frontends.build_ir(_DW_TEGRESS_BUGGY, None, 1)
        finder = modelfind.ModelFinder.from_ir(ir)
        ok, counterexample = finder.forall_reachable(
            lambda s: ir.pinned_property.eval(s))
        self.assertFalse(ok, "buggy taint-egress model must violate")
        self.assertIsNotNone(counterexample)
        # The witness really is an exfiltration: private data held AND sent.
        self.assertTrue(counterexample.get("holding_private"),
                        "witness %r should be holding private data"
                        % (counterexample,))
        self.assertTrue(counterexample.get("exfiltrated"),
                        "witness %r should have exfiltrated"
                        % (counterexample,))
        # And it is not the vacuous default: the property is False there.
        self.assertFalse(ir.pinned_property.eval(counterexample))


class CliTests(unittest.TestCase):
    def test_pipeline_dogwood_proven(self):
        tmp = tempfile.mkdtemp(prefix="rotn_policy_cli_")
        rc = pipeline.main(["--policy", _POL, "--tools", _TOOLS,
                            "--n-steps", "1", "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)

    def test_pipeline_cedar_proven(self):
        tmp = tempfile.mkdtemp(prefix="rotn_policy_cli_")
        rc = pipeline.main(["--policy", _CEDAR, "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)

    def test_pipeline_missing_policy_errors(self):
        tmp = tempfile.mkdtemp(prefix="rotn_policy_cli_")
        rc = pipeline.main(["--policy", os.path.join(_ROOT, "no_such.cedar"),
                            "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_ERROR)

    def test_report_written(self):
        tmp = tempfile.mkdtemp(prefix="rotn_policy_cli_")
        rc = pipeline.main(["--policy", _CEDAR, "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)
        names = [n for n in os.listdir(tmp) if n.endswith(".json")]
        self.assertTrue(names, "expected a JSON report in %s" % tmp)

    def test_pipeline_dw_correct_proven(self):
        tmp = tempfile.mkdtemp(prefix="rotn_policy_cli_")
        rc = pipeline.main(["--policy", _DW_CORRECT, "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN,
                         "the correct spend-cap model must be proven")

    def test_pipeline_dw_buggy_violated(self):
        tmp = tempfile.mkdtemp(prefix="rotn_policy_cli_")
        rc = pipeline.main(["--policy", _DW_BUGGY, "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_VIOLATED,
                         "the buggy spend-cap model must be reported violated")

    def test_pipeline_dw_missing_errors(self):
        tmp = tempfile.mkdtemp(prefix="rotn_policy_cli_")
        rc = pipeline.main(
            ["--policy", os.path.join(_DW_DIR, "no_such.dw"),
             "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()

