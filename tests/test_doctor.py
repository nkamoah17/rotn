# -*- coding: utf-8 -*-
"""Tests for ``rot doctor`` (the installation diagnostic, Phase J).

``cmd_doctor`` runs read-only checks (Python, package, core-module imports,
and an optional ``--deep`` end-to-end self-test) and reports PASS/FAIL. We
assert:
  * the shallow run passes and returns EXIT_PROVEN (0);
  * the report carries a PASS line for every core check (and no FAIL);
  * the ``--deep`` run passes (the real spend-cap self-test proves clean);
  * ``--quiet`` suppresses the human report entirely.

Run: python tests/test_doctor.py
"""

import io
import sys
import unittest
from contextlib import redirect_stdout

import rot.__main__ as cli


class DoctorTests(unittest.TestCase):

    def _run(self, deep, quiet=False):
        args = cli.argparse.Namespace(deep=deep, quiet=quiet)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.cmd_doctor(args)
        return code, buf.getvalue()

    def test_shallow_passes(self):
        code, out = self._run(deep=False)
        self.assertEqual(code, cli.EXIT_PROVEN)
        self.assertIn("ROTN doctor", out)
        for needle in ("python >= 3.6", "rot package",
                       "import rot.trace", "import rot.sitegen",
                       "import rot.ir", "import rot.tlc",
                       "import rot.smtz3", "import rot.policy_smt",
                       "import rot.cegar"):
            self.assertIn(needle, out)
        self.assertNotIn("FAIL", out)

    def test_deep_passes(self):
        code, out = self._run(deep=True)
        self.assertEqual(code, cli.EXIT_PROVEN)
        self.assertIn("engine self-test", out)
        self.assertIn("verdict=proven", out)
        self.assertNotIn("FAIL", out)

    def test_quiet_suppresses_report(self):
        code, out = self._run(deep=False, quiet=True)
        self.assertEqual(code, cli.EXIT_PROVEN)
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
