# -*- coding: utf-8 -*-
"""Tests for the Phase 1 constraint-vs-property TLA+ emission path
(``rot.emitter.Emitter.emit_spec`` / ``cfg_spec`` / ``write_spec``).

The keystone: a **state constraint** (well-formedness / ``TypeInvariant``) is
emitted as a *constraint* -- a named operator baked into ``Init`` and ``Next``
so ill-formed states are *dropped*, and listed as ``INVARIANT`` in the ``.cfg``
-- **never** as a ``PROPERTY``. A **temporal property** (e.g. ``no_deadlock``)
is a named operator listed as ``PROPERTY`` in the ``.cfg``. The totalising
``busy`` self-loop (terminal != deadlock) is preserved.

Run: python tests/test_emitter_spec.py
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.approval as approval
import rot.invariants as invariants
from rot.linearization import linearize
from rot.emitter import Emitter


def _operator_body(src, name):
    """Return the text of the ``<name> ==`` operator block in ``src``.

    Captures from ``<name> ==`` up to the next top-level definition
    (``<ident> ==``) or the end of the module.
    """
    m = re.search(r"^%s ==\n(.*?)(?=^[A-Za-z_][A-Za-z0-9_]* ==\n|----|\Z)"
                  % re.escape(name), src, re.M | re.S)
    if not m:
        return None
    return m.group(1)


class EmitterSpecConstraintVsPropertyTests(unittest.TestCase):

    def setUp(self):
        self.ir = approval.orchestration_build_ir(buggy=False)
        self.model = linearize(self.ir)
        self.em = Emitter(self.model, module_name="Orchestration")
        self.src, self.cops, self.pops = self.em.emit_spec(
            constraints=[("type_invariant",
                          invariants.type_invariant(self.ir).expression)],
            properties=[("no_deadlock",
                         invariants.get("no_deadlock", 1).expression)])
        self.cfg = self.em.cfg_spec(self.cops, self.pops)

    def test_operators_split_by_kind(self):
        # the constraint and the property are sanitised operator names
        self.assertEqual(self.cops, ["TypeInvariant"])
        self.assertEqual(self.pops, ["NoDeadlock"])

    def test_constraint_is_invariant_not_property(self):
        # TypeInvariant is a state constraint: listed as INVARIANT, and
        # explicitly NOT as a PROPERTY.
        self.assertIn("INVARIANT TypeInvariant", self.cfg)
        self.assertNotIn("PROPERTY TypeInvariant", self.cfg)

    def test_property_is_property(self):
        # no_deadlock is a temporal property: listed as PROPERTY.
        self.assertIn("PROPERTY NoDeadlock", self.cfg)
        self.assertNotIn("INVARIANT NoDeadlock", self.cfg)

    def test_both_are_named_operators(self):
        self.assertIn("TypeInvariant ==", self.src)
        self.assertIn("NoDeadlock ==", self.src)

    def test_constraint_baked_into_init(self):
        # Init is restricted to well-formed states (drops ill-formed initial
        # states).
        body = _operator_body(self.src, "Init")
        self.assertIsNotNone(body, "Init operator not found")
        self.assertIn("/\\ TypeInvariant", body)

    def test_constraint_baked_into_next(self):
        # Next is restricted to well-formed successors (drops ill-formed
        # states from the reachable set).
        body = _operator_body(self.src, "Next")
        self.assertIsNotNone(body, "Next operator not found")
        self.assertIn("/\\ TypeInvariant", body)
        # the action disjunction is parenthesised so the conjunction applies
        # to the whole disjunction.
        self.assertIn("(", body)

    def test_busy_self_loop_preserved(self):
        # the totalising busy self-loop keeps terminal != deadlock
        self.assertTrue(("busy ==" in self.src) or ("_busy ==" in self.src),
                        "busy self-loop operator not found")
        # and it is part of the transition relation (a disjunct of Next)
        next_body = _operator_body(self.src, "Next") or ""
        self.assertTrue(("busy" in next_body) or ("_busy" in next_body),
                        "busy not referenced in Next")

    def test_write_spec_roundtrip(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp(prefix="rot_emitspec_")
        try:
            tla_path, cfg_path, cops, pops = self.em.write_spec(
                d,
                constraints=[("type_invariant",
                              invariants.type_invariant(self.ir).expression)],
                properties=[("no_deadlock",
                             invariants.get("no_deadlock", 1).expression)])
            self.assertTrue(os.path.isfile(tla_path))
            self.assertTrue(os.path.isfile(cfg_path))
            with open(cfg_path) as f:
                cfg_text = f.read()
            self.assertIn("INVARIANT TypeInvariant", cfg_text)
            self.assertNotIn("PROPERTY TypeInvariant", cfg_text)
            self.assertIn("PROPERTY NoDeadlock", cfg_text)
            self.assertEqual(cops, ["TypeInvariant"])
            self.assertEqual(pops, ["NoDeadlock"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_int_range_model_emits_integers(self):
        # an IntRange model (with a well-formedness constraint) must extend
        # Integers and emit the constraint + a property.
        import rot.ir as ir
        m = ir.ProtocolIR(
            name="counter",
            variables=[ir.StateVar("counter", ir.IntRange(0, 2))],
            init={"counter": 0})
        em = Emitter(linearize(m), module_name="Counter")
        # a property valid for this model (counter stays within its cap)
        bounded = ir.BinOp("<=", ir.V("counter"), ir.C(2))
        src, cops, pops = em.emit_spec(
            constraints=[("type_invariant",
                          invariants.type_invariant(m).expression)],
            properties=[("bounded", bounded)])
        self.assertIn("EXTENDS Integers", src)
        self.assertEqual(cops, ["TypeInvariant"])
        self.assertEqual(pops, ["Bounded"])
        init_body = _operator_body(src, "Init")
        self.assertIn("/\\ TypeInvariant", init_body)
        self.assertIn("PROPERTY Bounded", em.cfg_spec(cops, pops))


if __name__ == "__main__":
    unittest.main(verbosity=2)