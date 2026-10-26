# -*- coding: utf-8 -*-
"""Unit tests for rot.sat (DPLL solver + 3-valued eval), cross-checked by brute force."""
import os
import sys
import random
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rot import sat  # noqa: E402


class TestSatSolver(unittest.TestCase):
    def test_trivial(self):
        self.assertEqual(sat.solve(sat.TRUE)[0], sat.SAT)
        self.assertEqual(sat.solve(sat.FALSE)[0], sat.UNSAT)

    def test_literal(self):
        self.assertEqual(sat.solve(sat.Lit(0))[0], sat.SAT)
        self.assertEqual(sat.solve(sat.Lit(0, True))[0], sat.SAT)
        self.assertEqual(sat.solve(sat.AndOf(sat.Lit(0), sat.Lit(0, True)))[0], sat.UNSAT)

    def test_parentheses(self):
        # a<->b  ==  (a|~b) & (~a|b)   (SAT, satisfied by a = b)
        f = sat.AndOf(
            sat.OrOf(sat.Lit(0), sat.Lit(1, True)),
            sat.OrOf(sat.Lit(0, True), sat.Lit(1)),
        )
        status, model = sat.solve(f)
        self.assertEqual(status, sat.SAT)
        self.assertTrue(sat.eval2(f, model))
        # make it contradictory: a<->b & c & ~c  -> UNSAT
        g = sat.AndOf(f, sat.Lit(2), sat.Lit(2, True))
        self.assertEqual(sat.solve(g)[0], sat.UNSAT)

    def test_implies(self):
        # (a => b) & (b => a) & a & ~b  -> UNSAT
        f = sat.AndOf(sat.Imp(sat.Lit(0), sat.Lit(1)),
                      sat.Imp(sat.Lit(1), sat.Lit(0)),
                      sat.Lit(0), sat.Lit(1, True))
        self.assertEqual(sat.solve(f)[0], sat.UNSAT)

    def test_model_consistency(self):
        f = sat.AndOf(sat.Lit(0), sat.OrOf(sat.Lit(1), sat.Lit(2)))
        status, model = sat.solve(f)
        self.assertEqual(status, sat.SAT)
        self.assertTrue(sat.eval2(f, model))

    def test_random_cross_check(self):
        rng = random.Random(1234)
        for _ in range(300):
            nvars = rng.randint(1, 6)
            f = self._rand_formula(rng, nvars)
            s1, _ = sat.solve(f)
            s2, _ = sat.brute_force(f, list(range(nvars)))
            self.assertEqual(s1, s2, "mismatch on formula %r" % (f,))

    def _rand_formula(self, rng, nvars):
        depth = rng.randint(0, 3)
        return self._rand(rng, nvars, depth)

    def _rand(self, rng, nvars, depth):
        if depth == 0 or rng.random() < 0.3:
            v = rng.randint(0, nvars - 1)
            return sat.Lit(v, rng.random() < 0.5)
        kind = rng.choice(["and", "or", "not"])
        if kind == "not":
            return sat.NotOf(self._rand(rng, nvars, depth - 1))
        k = rng.randint(2, 3)
        kids = [self._rand(rng, nvars, depth - 1) for _ in range(k)]
        return (sat.AndOf(*kids) if kind == "and" else sat.OrOf(*kids))


class TestEval3(unittest.TestCase):
    def test_unknown_propagation_and(self):
        # (True & UNKNOWN) == UNKNOWN ; (False & UNKNOWN) == False
        a = sat.Lit(0)
        b = sat.Lit(1)
        self.assertEqual(sat.eval3(sat.AndOf(a, b), {0: True, 1: True}, set()), True)
        self.assertEqual(sat.eval3(sat.AndOf(a, b), {0: True}, {1}), sat.UNKNOWN)
        self.assertEqual(sat.eval3(sat.AndOf(a, b), {0: False}, {1}), False)

    def test_unknown_propagation_or(self):
        a = sat.Lit(0)
        b = sat.Lit(1)
        self.assertEqual(sat.eval3(sat.OrOf(a, b), {0: False}, {1}), sat.UNKNOWN)
        self.assertEqual(sat.eval3(sat.OrOf(a, b), {0: True}, {1}), True)
        self.assertEqual(sat.eval3(sat.OrOf(a, b), {0: False, 1: False}, set()), False)

    def test_unknown_not(self):
        self.assertEqual(sat.eval3(sat.NotOf(sat.Lit(0)), {}, {0}), sat.UNKNOWN)
        self.assertEqual(sat.eval3(sat.NotOf(sat.Lit(0)), {0: True}, set()), False)


if __name__ == "__main__":
    unittest.main(verbosity=2)