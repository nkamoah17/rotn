# -*- coding: utf-8 -*-
"""Unit tests for ``rot.modelfind.ModelFinder.path_to`` -- the BFS
witness-path reconstruction used by ``rot.smtz3.SMTBackend`` to build
``Verdict.trace`` on VIOLATED safety verdicts.

Fixture: the spendcap (AWS Dogwood) slice, buggy variant.  From the initial
state ``{completed: 0, inflight: 0}`` the first violating state is
``{completed: 0, inflight: 3}`` (three back-to-back ``spend_ok`` fires),
reached by exactly three ``spend_ok`` steps.

Run: python tests/test_modelfind.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.modelfind import ModelFinder, ProductTooLarge
from rot.spendcap import build_ir


INIT = {"completed": 0, "inflight": 0}
TARGET = {"completed": 0, "inflight": 3}


def _finder(max_states=None):
    if max_states is None:
        return ModelFinder.from_ir(build_ir(buggy=True))
    return ModelFinder.from_ir(build_ir(buggy=True), max_states=max_states)


class PathToTest(unittest.TestCase):
    def test_reachable_target_returns_step_list(self):
        steps = _finder().path_to(TARGET)
        self.assertEqual(len(steps), 3)
        for step in steps:
            self.assertEqual(len(step), 3)
            state_before, action, delta = step
            self.assertEqual(action.name, "spend_ok")
            # The guard must be enabled in the state the step is applied to.
            self.assertIs(True, action.guard.eval(state_before))

    def test_reachable_target_states_and_deltas(self):
        steps = _finder().path_to(TARGET)
        states = [s for (s, a, d) in steps]
        deltas = [d for (s, a, d) in steps]
        self.assertEqual(states, [
            {"completed": 0, "inflight": 0},
            {"completed": 0, "inflight": 1},
            {"completed": 0, "inflight": 2},
        ])
        self.assertEqual(deltas, [
            {"inflight": 1},
            {"inflight": 2},
            {"inflight": 3},
        ])

    def test_replay_reaches_target(self):
        """Replaying ``state_before | delta`` walks the path to the target."""
        steps = _finder().path_to(TARGET)
        for i, (state_before, action, delta) in enumerate(steps):
            post = dict(state_before)
            post.update(delta)
            if i + 1 < len(steps):
                self.assertEqual(post, steps[i + 1][0])
            else:
                self.assertEqual(post, TARGET)

    def test_initial_state_target_is_empty(self):
        self.assertEqual(_finder().path_to(dict(INIT)), [])

    def test_unreachable_target_is_empty(self):
        # ``completed`` only changes by whole AMOUNT (100) increments, so a
        # state with completed = 1 is unreachable from Init.
        self.assertEqual(_finder().path_to({"completed": 1, "inflight": 0}), [])

    def test_budget_exceeded_raises(self):
        finder = _finder(max_states=1)
        self.assertRaises(ProductTooLarge, finder.path_to, TARGET)

    def test_path_is_deterministic(self):
        a = _finder().path_to(TARGET)
        b = _finder().path_to(TARGET)
        self.assertEqual(
            [(s, act.name, d) for (s, act, d) in a],
            [(s, act.name, d) for (s, act, d) in b])


if __name__ == "__main__":
    unittest.main()