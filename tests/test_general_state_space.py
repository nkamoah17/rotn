# -*- coding: utf-8 -*-
"""General state space gate (Phase 2, GSSM lift).

This is the gate for **Phase 2** (section 2.6) of the Joern-primary rework
(``docs/joern-primary-ab-plan.md``) -- the *general state space* lift that
comes **after** the Phase 1 FSM-extraction lift.  It verifies that the four
pieces the plan calls for are in place and *measurable* on the 2PC fixture:

  * **the 3-factor decomposition** (GSSM III) -- ``rot.factor`` is a *pure
    lens* over ``rot.ir``: prior = the init action, between = the transitions,
    measurement = the pinned property.  Zero behaviour change: it reads the IR,
    it never mutates it.
  * **the multi-connected + distributed view** (GSSM IV-3a/3b) --
    ``rot.factor_graph`` recovers the 2PC protocol as *two or more* components
    (coordinator | participants) joined by channel factors, rather than the
    ``LinearModel`` chain; ``rot.env.distributed_view`` builds the product of
    the local factor graphs.  The chain remains the sound special case.
  * **constant-node reduction** (GSSM IV-3c) -- the 2PC fixture's state space,
    with its never-written variables marked constant nodes, is *smaller* than
    the naive linearized chain (``reduced < chain``).
  * **the named factor-graph quotient soundness** -- ``rot.cegar`` names the
    "hiding never under-approximates" theorem (the soundness of the
    factor-graph quotient) and records that the backward pass runs *before*
    marginalization.

The 2PC fixture is the committed ``tests/fixtures/cpg/twopc.cpg.json`` (the
Phase 1 artifact) for the constant-node half, and the hand-authored oracle
``rot.twopc.build_ir(n=3)`` for the coordinator | participants half.  Pure
stdlib, Python 3.6 compatible.

Run: python -m pytest tests/test_general_state_space.py -v
"""

import json
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import rot.factor as factor
import rot.factor_graph as factor_graph
import rot.linearization as linearization
import rot.twopc as twopc
import rot.env as env
import rot.cegar as cegar
from rot.frontends.cpg_model import CpgModel
import rot.fsmextract as fe

FIX_2PC = os.path.join(_ROOT, "tests", "fixtures", "cpg", "twopc.cpg.json")


def _fsm_twopc_ir():
    """The Phase 1 artifact: the FSM-extracted 2PC IR from the committed CPG."""
    with open(FIX_2PC) as fh:
        model = CpgModel.from_dict(json.load(fh))
    res = fe.extract_fsm(model)
    assert res.ir is not None, "the 2PC fixture must extract to an IR"
    return res.ir


class ThreeFactorDecompositionTests(unittest.TestCase):
    """GSSM III: the 3-factor decomposition is a pure lens over rot.ir."""

    def test_prior_between_measurement_on_twopc(self):
        ir = twopc.build_ir(n=3)
        d = factor.decompose(ir)

        self.assertEqual(d.ir.name, ir.name)
        # prior = the initial action
        self.assertIsNotNone(d.prior.action)
        init_actions = [a for a in ir.actions if a.is_initial]
        self.assertEqual(len(init_actions), 1)
        self.assertEqual(d.prior.action.name, init_actions[0].name)
        # between = the transitions (the non-init actions), in order
        transitions = [a for a in ir.actions if not a.is_initial]
        self.assertEqual(len(d.between.actions()), len(transitions))
        self.assertEqual(
            [a.name for a in d.between.actions()], [a.name for a in transitions])
        # measurement = the pinned property (the query)
        self.assertIsNotNone(d.measurement.expression())
        self.assertIs(d.measurement.expression(), ir.pinned_property)
        self.assertEqual(d.measurement.kind, factor.MEASUREMENT)

    def test_lens_is_pure(self):
        """decompose / build_factor_graph read the IR; they never mutate it."""
        ir = twopc.build_ir(n=3)
        vars_before = [v.name for v in ir.variables]
        actions_before = [a.name for a in ir.actions]
        factor.decompose(ir)
        factor_graph.build_factor_graph(ir)
        self.assertEqual([v.name for v in ir.variables], vars_before)
        self.assertEqual([a.name for a in ir.actions], actions_before)

    def test_serialization_round_trip(self):
        ir = twopc.build_ir(n=3)
        d = factor.decompose(ir)
        dd = d.to_dict()
        self.assertEqual(dd["prior"]["action"], d.prior.action.name)
        self.assertEqual(dd["between"]["n_actions"], len(d.between.actions()))
        self.assertEqual(dd["measurement"]["kind"], factor.MEASUREMENT)
        self.assertIn("free_vars", dd["measurement"])


class MultiProcessViewTests(unittest.TestCase):
    """GSSM IV-3a/3b: the 2PC protocol is a multi-connected graph, not a chain."""

    def test_coordinator_parallel_participants(self):
        ir = twopc.build_ir(n=3)
        g = factor_graph.build_factor_graph(ir)

        # more than one component (not the single LinearModel chain)
        self.assertGreaterEqual(len(g.components), 2)
        self.assertFalse(g.is_chain)

        owners = [c.owner for c in g.components]
        self.assertIn("coordinator", owners, owners)
        self.assertTrue(
            any(o.startswith("participant") for o in owners),
            "expected at least one participant component; got %s" % owners)

        # the components are joined by channel (connection) factors
        self.assertGreaterEqual(len(g.channels), 1)
        for ch in g.channels:
            self.assertIn(ch.from_component, owners)
            self.assertIn(ch.to_component, owners)
            self.assertGreaterEqual(len(ch.variables), 1)

    def test_component_names_are_stable(self):
        ir = twopc.build_ir(n=3)
        g1 = factor_graph.build_factor_graph(ir)
        g2 = factor_graph.build_factor_graph(ir)
        self.assertEqual(g1.component_names(), g2.component_names())
        self.assertEqual(g1.channel_names(), g2.channel_names())

    def test_distributed_view_product(self):
        """rot.env.distributed_view: the product of local factor graphs."""
        frags = [env.at_least_once_queue(), env.tcp_channel()]
        n_vars_before = [len(f.variables) for f in frags]
        dv = env.distributed_view(frags)
        self.assertEqual(len(dv.components), 2)
        self.assertFalse(dv.is_chain)
        # the product does not mutate the fragments
        self.assertEqual([len(f.variables) for f in frags], n_vars_before)

    def test_single_fragment_is_the_chain(self):
        """The LinearModel chain is the sound special case (one fragment)."""
        dv = env.distributed_view([env.at_least_once_queue()])
        self.assertEqual(len(dv.components), 1)
        self.assertTrue(dv.is_chain)


class ConstantNodeReductionTests(unittest.TestCase):
    """GSSM IV-3c: the 2PC fixture's state space shrinks under constant nodes."""

    def test_state_space_smaller_than_chain(self):
        ir = _fsm_twopc_ir()
        model = linearization.linearize(ir)
        ss = model.state_space()

        # the 2PC fixture has never-written variables (the participant votes)
        self.assertGreaterEqual(len(ss["constant_nodes"]), 1)
        # the reduced state space is strictly smaller than the naive chain
        self.assertIsNotNone(ss["chain"])
        self.assertIsNotNone(ss["reduced"])
        self.assertLess(ss["reduced"], ss["chain"])

    def test_constant_nodes_are_exactly_the_init_only_vars(self):
        ir = _fsm_twopc_ir()
        model = linearization.linearize(ir)
        # a constant node is precisely a variable no transition action writes
        self.assertEqual(
            set(model.constant_nodes),
            set(model.state_space()["constant_nodes"]))
        # and it is disjoint from the varying variables
        self.assertFalse(
            set(model.constant_nodes) & set(model.varying_var_names()))

    def test_domain_sizes_are_finite(self):
        ir = _fsm_twopc_ir()
        model = linearization.linearize(ir)
        for v in ir.variables:
            self.assertIsNotNone(model.domain_size(v.name), v.name)
            self.assertGreater(model.domain_size(v.name), 0)


class CegarSoundnessNamingTests(unittest.TestCase):
    """The factor-graph quotient soundness is named; backward pass before hiding."""

    def test_soundness_is_named_and_exported(self):
        s = cegar.FACTOR_GRAPH_QUOTIENT_SOUNDNESS
        self.assertIsInstance(s, str)
        self.assertTrue(len(s) > 40)
        self.assertIn("FACTOR_GRAPH_QUOTIENT_SOUNDNESS", cegar.__all__)
        # the theorem it names (hiding = marginalization never under-approximates)
        self.assertIn("under-approxim", s)
        self.assertIn("backward pass", s)
        self.assertIn("before", s)


if __name__ == "__main__":
    unittest.main(verbosity=2)

