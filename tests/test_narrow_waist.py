# -*- coding: utf-8 -*-
"""Narrow-waist guardrail (WP1).

The IR is the *sole* contract between the code and the verification engines
(the "narrow waist" of the architecture). Frontends (``rot/frontends/**``) may
therefore depend only on the IR (``rot.ir``), their own package
(``rot.frontends``) and stdlib -- never on a downstream engine module
(``rot.emitter``, ``rot.tlc``, ``rot.symbolic``, ``rot.cegar``,
``rot.abstraction``, ...).

This test enforces that contract *statically* (by parsing the ``import`` /
``from`` statements of every frontend module with ``ast``) so a future
frontend cannot quietly reach past the waist. It also self-tests the scanner
on synthetic good/bad modules so it cannot pass vacuously.

Run: python tests/test_narrow_waist.py
"""

import ast
import glob
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_FRONTENDS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rot", "frontends")


def _import_targets(source):
    """Yield ``(line, target, level)`` for every import statement in ``source``.

    ``target`` is the full dotted module (e.g. ``rot.ir`` or ``rot.tlc``);
    ``level`` is the relative-import level (0 = absolute). Relative imports
    (level > 0) resolve within the frontend package and are always permitted.
    """
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name, 0
        elif isinstance(node, ast.ImportFrom):
            level = node.level or 0
            yield node.lineno, (node.module or ""), level


def _is_allowed_rot(target):
    """The only ``rot.*`` modules a frontend may import: the IR and its own
    package. ``rot.emitter`` / ``rot.tlc`` / ``rot.symbolic`` / ... are all
    downstream of the waist and forbidden here."""
    if target in ("rot", "rot.ir"):
        return True
    if target.startswith("rot.ir."):
        return True
    if target == "rot.frontends" or target.startswith("rot.frontends."):
        return True
    return False


def _is_forbidden(target, level):
    """True iff the import crosses the narrow waist (a frontend reaching a
    non-IR ``rot.*`` module)."""
    if level > 0:                      # relative import: stays in the package
        return False
    if not target:
        return False
    if target.split(".")[0] != "rot":  # stdlib / third-party: not internal coupling
        return False
    return not _is_allowed_rot(target)


def scan_source(source):
    """Return a list of ``(line, target)`` violations in ``source``."""
    return [(line, target) for (line, target, level) in _import_targets(source)
            if _is_forbidden(target, level)]


class NarrowWaistTests(unittest.TestCase):
    def test_scanner_flags_violations_and_passes_the_waist(self):
        # Self-test: the scanner must actually discriminate (so it can't pass
        # vacuously even if the real frontends happen to be clean).
        bad = "from rot.tlc import run_tlc\nimport rot.emitter\n"
        good = ("import json\nfrom rot.ir import ProtocolIR\n"
                "from rot.frontends import cpg_model\n")
        self.assertTrue(scan_source(bad), "scanner failed to flag rot.tlc/rot.emitter")
        self.assertIn((1, "rot.tlc"), scan_source(bad))
        self.assertEqual(scan_source(good), [], "scanner flagged a legitimate waist import")

    def test_frontends_import_only_the_ir_and_stdlib(self):
        files = sorted(glob.glob(os.path.join(_FRONTENDS_DIR, "*.py")))
        self.assertTrue(files, "no frontend modules found under %s" % _FRONTENDS_DIR)
        violations = []
        for path in files:
            with open(path, "r") as fh:
                source = fh.read()
            for (line, target) in scan_source(source):
                violations.append("%s:%d imports %r" % (os.path.basename(path), line, target))
        self.assertEqual(
            violations, [],
            "frontends must depend only on rot.ir (plus stdlib / their own "
            "package); found: %s" % ", ".join(violations))

    def test_no_frontend_reaches_a_known_engine_module(self):
        # A second, explicit guard: name the engine modules that must never
        # leak into the frontend layer, so the intent is self-documenting.
        engines = ("rot.emitter", "rot.emitter_tlc", "rot.emitter_quint",
                   "rot.tlc", "rot.symbolic", "rot.cegar", "rot.abstraction",
                   "rot.linearization", "rot.invariants", "rot.mr_gate",
                   "rot.llm_baseline", "rot.itf", "rot.refine")
        for path in sorted(glob.glob(os.path.join(_FRONTENDS_DIR, "*.py"))):
            with open(path, "r") as fh:
                source = fh.read()
            for (line, target, _level) in _import_targets(source):
                if target in engines or any(target.startswith(e + ".") for e in engines):
                    self.fail("%s:%d imports engine module %r (narrow-waist violation)"
                              % (os.path.basename(path), line, target))


if __name__ == "__main__":
    unittest.main(verbosity=2)
