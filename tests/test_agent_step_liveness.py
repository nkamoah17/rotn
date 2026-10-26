# -*- coding: utf-8 -*-
"""Tests for the agent-step bounded-liveness front-end (``agent_step_liveness``).

Covers:
  * the front-end produces a valid ``ProtocolIR`` with the liveness property
    pinned (``property_kind == "liveness"``, goal ``decision != idle``);
  * the existing bounded-liveness machinery returns ``proven`` for a model
    where the agent can act (a policy with >= 1 allowed action);
  * and ``violated`` for a model where the agent is stuck (a policy with no
    allowed action).

Run: python tests/test_agent_step_liveness.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pipeline  # noqa: E402  (imported after the path fix, like the rot.*)

import rot.ir as ir
import rot.invariants as invariants
import rot.cegar as cegar
import rot.symbolic as symbolic
from rot.config import Config
from rot.frontends.policy import agent_step_liveness
from rot.linearization import linearize

_SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
_POLICY = os.path.join(_SAMPLES, "policy.json")
_TOOLS = os.path.join(_SAMPLES, "tools.json")


def _run_liveness(model):
    """Run the existing bounded-liveness machinery on ``model`` and return the
    verdict (``proven`` / ``violated`` / ``unknown``).

    The model is a ``ProtocolIR``; the symbolic engine operates on the
    *linearized* view (``rot.linearization.linearize``), exactly as the
    pipeline does before dispatching a liveness property to
    ``SymbolicEngine.reach_within``.
    """
    prop = invariants.get("bounded_eventually", 1)
    cfg = Config(liveness_horizon=12, max_states=1000)
    linear_model = linearize(model)
    res = (symbolic.SymbolicEngine(linear_model, max_states=cfg.max_states)
           .reach_within(prop.expression, cfg.liveness_horizon,
                         max_states=cfg.max_states))
    return cegar.cegar_liveness(res, prop, cfg, "symbolic").status


class AgentStepLivenessFrontendTests(unittest.TestCase):
    def test_malformed_policy_raises_frontend_error(self):
        # Regression: a bad policy must surface as this front-end's own
        # PolicyFrontendError (the dogwood DogwoodFrontendError is wrapped,
        # never leaked -- and the except-clause must reference a name that
        # actually exists on the dogwood module, else the original error is
        # masked by an AttributeError).
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            fh.write("{not valid json")
        try:
            self.assertRaises(
                agent_step_liveness.PolicyFrontendError,
                agent_step_liveness.build_ir, path, _TOOLS)
        finally:
            os.remove(path)

    def test_produces_a_valid_liveness_ir(self):
        model = agent_step_liveness.build_ir(_POLICY, _TOOLS)
        self.assertIsInstance(model, ir.ProtocolIR)
        self.assertEqual(model.metadata["property_kind"], "liveness")
        self.assertEqual(model.metadata["property_name"], "bounded_eventually")
        self.assertEqual(model.metadata["frontend"], "agent_step_liveness")
        # The pinned property is the bounded-liveness goal: decision != idle
        # (NOT the safety policy-conformance property).
        pp = model.pinned_property
        self.assertIsInstance(pp, ir.BinOp)
        self.assertEqual(pp.op, "!=")
        self.assertEqual(pp.left.name, "decision")
        self.assertEqual(pp.right.value, "idle")
        self.assertEqual(model.validate(), [])

    def test_liveness_proven_when_the_agent_can_act(self):
        # The sample policy allows "open" and "close"; the agent can reach a
        # state where `decision != idle` -> bounded liveness holds.
        model = agent_step_liveness.build_ir(_POLICY, _TOOLS)
        self.assertEqual(_run_liveness(model), "proven")

    def test_liveness_violated_when_the_agent_is_stuck(self):
        # A policy with NO allowed action: the agent is stuck at idle, so
        # `decision != idle` is never reached -> bounded liveness is violated.
        stuck_policy = {"name": "stuck", "description": "no actions",
                        "allowed": [], "denied": ["do"]}
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(stuck_policy, fh)
            model = agent_step_liveness.build_ir(path, _TOOLS)
            self.assertEqual(_run_liveness(model), "violated")
        finally:
            os.remove(path)


class CliLivenessTests(unittest.TestCase):
    """End-to-end: ``pipeline.py --kind liveness`` dispatches the
    bounded-liveness machinery (linearize -> reach_within -> cegar_liveness)
    and maps the verdict onto the process exit code.
    """

    def _stuck_policy(self):
        stuck = {"name": "stuck", "description": "an agent with no actions",
                 "allowed": [], "denied": ["do"]}
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(stuck, fh)
        return path

    def test_cli_liveness_proven(self):
        tmp = tempfile.mkdtemp(prefix="rotn_liveness_cli_")
        rc = pipeline.main(["--policy", _POLICY, "--tools", _TOOLS,
                            "--kind", "liveness", "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)

    def test_cli_liveness_violated_when_the_agent_is_stuck(self):
        tmp = tempfile.mkdtemp(prefix="rotn_liveness_cli_")
        stuck = self._stuck_policy()
        try:
            rc = pipeline.main(["--policy", stuck, "--tools", _TOOLS,
                                "--kind", "liveness", "--out", tmp, "--quiet"])
            self.assertEqual(rc, pipeline.EXIT_VIOLATED)
        finally:
            os.remove(stuck)

    def test_cli_liveness_respects_an_explicit_horizon(self):
        # The agent commits after exactly one step, so horizon 1 still
        # proves the goal while horizon 0 (only the init state) violates it.
        tmp = tempfile.mkdtemp(prefix="rotn_liveness_cli_")
        rc = pipeline.main(["--policy", _POLICY, "--tools", _TOOLS,
                            "--kind", "liveness",
                            "--liveness-horizon", "1", "--out", tmp,
                            "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)
        tmp0 = tempfile.mkdtemp(prefix="rotn_liveness_cli_")
        rc0 = pipeline.main(["--policy", _POLICY, "--tools", _TOOLS,
                             "--kind", "liveness",
                             "--liveness-horizon", "0", "--out", tmp0,
                             "--quiet"])
        self.assertEqual(rc0, pipeline.EXIT_VIOLATED)

    def test_cli_liveness_report_records_kind_and_horizon(self):
        tmp = tempfile.mkdtemp(prefix="rotn_liveness_cli_")
        rc = pipeline.main(["--policy", _POLICY, "--tools", _TOOLS,
                            "--kind", "liveness",
                            "--liveness-horizon", "5", "--out", tmp,
                            "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)
        names = [n for n in os.listdir(tmp) if n.endswith(".json")]
        self.assertTrue(names, "expected a JSON report in %s" % tmp)
        with open(os.path.join(tmp, names[0])) as fh:
            report = json.load(fh)
        self.assertEqual(report["property_kind"], "liveness")
        self.assertEqual(report["verdict"], "proven")
        self.assertEqual(report["liveness_horizon"], 5)
        self.assertIn("note", report)

    def test_cli_kind_forces_liveness_over_extension(self):
        # --kind overrides the extension-based auto-routing: a Dogwood policy
        # is normally pinned as a safety property, but forcing 'liveness'
        # must take the bounded-liveness path instead.
        tmp = tempfile.mkdtemp(prefix="rotn_liveness_cli_")
        rc = pipeline.main(["--policy", _POLICY, "--tools", _TOOLS,
                            "--kind", "liveness", "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)
        names = [n for n in os.listdir(tmp) if n.endswith(".json")]
        with open(os.path.join(tmp, names[0])) as fh:
            report = json.load(fh)
        self.assertEqual(report["property_kind"], "liveness")
        self.assertEqual(report["property_name"], "bounded_eventually")


if __name__ == "__main__":
    unittest.main(verbosity=2)
