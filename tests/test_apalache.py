# -*- coding: utf-8 -*-
"""Tests for ``rot.apalache`` -- the Apalache engine (bounded TLA+ + apalache.jar).

These tests drive the REAL ``ApalacheEngine.check()`` code path -- command
build, subprocess launch, output parsing, witness recovery, timeout handling --
without a real Apalache jar or a Java 21 runtime, by substituting a *fake*
``java`` executable (a ``.bat`` that runs a small Python script).  The fake's
behaviour is selected by the ``FAKE_APALACHE_MODE`` environment variable:

* ``proven``             -> prints ``The outcome is: NoError``, exit 0
* ``violated``           -> prints ``The outcome is: Error``, exit 12, and
                            copies an ITF witness into ``--out-dir``
* ``java-version-error`` -> prints an ``UnsupportedClassVersionError`` line, exit 1
* ``error``              -> prints a hard error, exit 1
* ``timeout``            -> sleeps past the configured timeout

The ``missing jar`` case is tested by forcing ``Config.apalache_jar_path()``
to return ``None`` (the early-return branch; no subprocess is launched).

The command-build tests exercise the locked 0.62.x command form directly (a
pure function, no subprocess).

Run: python tests/test_apalache.py
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot import apalache
from rot.apalache import ApalacheEngine, _module_name
from rot.config import Config
from rot.linearization import linearize
from rot import targets

PROVEN = "proven"
VIOLATED = "violated"
UNKNOWN = "unknown"
ERROR = "error"

# A real ITF trace the fake binary can copy into --out-dir for the
# "violated + witness" case (parseable by rot.itf; state 6 refutes the
# "agreement" invariant, so _find_witness recovers a concrete witness).
ITF_FIXTURE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tests", "fixtures", "violation.itf.json")


# The fake ``java`` implementation.  Driven by FAKE_APALACHE_MODE.
_FAKEJAVA_IMPL = r'''
import os, sys, shutil, time

mode = os.environ.get("FAKE_APALACHE_MODE", "proven")
out_dir = None
for a in sys.argv[1:]:
    if a.startswith("--out-dir="):
        out_dir = a.split("=", 1)[1]

if mode == "timeout":
    time.sleep(2)
    sys.exit(0)

if mode == "proven":
    sys.stdout.write("The outcome is: NoError\n")
    sys.stdout.flush()
    sys.exit(0)

if mode == "violated":
    sys.stdout.write("The outcome is: Error\n")
    sys.stdout.flush()
    witness = os.environ.get("FAKE_APALACHE_WITNESS")
    if out_dir and witness and os.path.exists(witness):
        sub = os.path.join(out_dir, "M.tla", "ts1")
        os.makedirs(sub)
        shutil.copyfile(witness, os.path.join(sub, "violation.itf.json"))
    sys.exit(12)

if mode == "java-version-error":
    sys.stderr.write(
        "java.lang.UnsupportedClassVersionError: class file version 65.0\n")
    sys.stderr.flush()
    sys.exit(1)

sys.stderr.write("Some hard error\n")
sys.stderr.flush()
sys.exit(1)
'''


class _FakeJava(object):
    """Creates a fake ``java`` executable (``.bat`` -> python) + a dummy jar."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="rotn_fakejava_")
        self.impl = os.path.join(self.tmp, "fakejava_impl.py")
        with open(self.impl, "w") as f:
            f.write(_FAKEJAVA_IMPL)
        self.bat = os.path.join(self.tmp, "fakejava.bat")
        with open(self.bat, "w") as f:
            f.write('@echo off\r\n"%s" "%s" %%*\r\n'
                    % (sys.executable, self.impl))
        # A dummy jar so Config.apalache_jar_path() resolves to a real file.
        self.jar = os.path.join(self.tmp, "apalache.jar")
        with open(self.jar, "w") as f:
            f.write("fake apalache jar\n")

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def _build_model_and_prop():
    """A real ``LinearModel`` + ``Invariant`` so ``Emitter`` can write a .tla."""
    ir = targets.build("correct", 3)
    model = linearize(ir)
    prop = targets.get_property("correct", "agreement", 3)
    return model, prop


class CommandBuildTest(unittest.TestCase):
    """The locked 0.62.x command form (a pure function, no subprocess)."""

    def test_command_form(self):
        cfg = Config(apalache_length=5)
        engine = ApalacheEngine(cfg)
        cmd = engine._command("java", "apalache.jar", "M.tla",
                              "Agreement", "out/apalache")
        self.assertEqual(cmd, [
            "java", "-jar", "apalache.jar", "check",
            "--out-dir=out/apalache",
            "--init=Init",
            "--next=Next",
            "--inv=Agreement",
            "--length=5",
            "M.tla",
        ])

    def test_command_defaults_length_to_10(self):
        # Apalache's own default bound is 10; a None length falls back to it.
        engine = ApalacheEngine(Config(apalache_length=None))
        cmd = engine._command("java", "jar", "M.tla", "Op", "out")
        self.assertIn("--length=10", cmd)

    def test_module_name_sanitization(self):
        self.assertEqual(_module_name("correct", "agreement"),
                         "correct_agreement")
        self.assertEqual(_module_name("spendcap-buggy", "spendcap_within_cap"),
                         "spendcap_buggy_spendcap_within_cap")
        # A leading digit is prefixed so the TLA+ module name is a valid id.
        self.assertTrue(_module_name("2pc", "x").startswith(("2pc", "M_")))


class FakeBinaryTest(unittest.TestCase):
    """Drive the real ``check()`` code path with a fake ``java`` executable."""

    def setUp(self):
        self.fake = _FakeJava()
        self.model, self.prop = _build_model_and_prop()
        self.work_dir = tempfile.mkdtemp(prefix="rotn_apalache_work_")
        self._saved_env = {}

    def tearDown(self):
        self._restore_env()
        self.fake.cleanup()
        shutil.rmtree(self.work_dir, ignore_errors=True)

    # -- env-var plumbing (the fake java reads FAKE_APALACHE_MODE) ----------
    def _set_mode(self, mode, witness=None):
        self._saved_env["FAKE_APALACHE_MODE"] = os.environ.get(
            "FAKE_APALACHE_MODE")
        os.environ["FAKE_APALACHE_MODE"] = mode
        if witness is not None:
            self._saved_env["FAKE_APALACHE_WITNESS"] = os.environ.get(
                "FAKE_APALACHE_WITNESS")
            os.environ["FAKE_APALACHE_WITNESS"] = witness
        else:
            os.environ.pop("FAKE_APALACHE_WITNESS", None)

    def _restore_env(self):
        for key, val in self._saved_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        self._saved_env = {}

    def _cfg(self, **overrides):
        base = dict(
            apalache_enabled=True,
            apalache_jar=self.fake.jar,
            apalache_java=self.fake.bat,
            apalache_timeout=30,
            apalache_length=5,
            work_dir=self.work_dir,
        )
        base.update(overrides)
        return Config(**base)

    def _check(self, mode, witness=None, **cfg_overrides):
        self._set_mode(mode, witness=witness)
        return ApalacheEngine(self._cfg(**cfg_overrides)).check(
            self.model, self.prop)

    # -- the six required cases ---------------------------------------------
    def test_proven(self):
        result = self._check("proven")
        self.assertEqual(result.status, PROVEN)
        self.assertTrue(result.complete)
        self.assertIn("NoError", result.note)

    def test_violated_with_witness(self):
        result = self._check("violated", witness=ITF_FIXTURE)
        self.assertEqual(result.status, VIOLATED)
        self.assertIsNotNone(result.witness)
        self.assertIsInstance(result.witness, dict)
        self.assertIn("counterexample", result.note)

    def test_missing_jar(self):
        # Force the early-return branch (jar is None); no subprocess is run.
        from unittest import mock
        with mock.patch.object(Config, "apalache_jar_path",
                              return_value=None):
            result = ApalacheEngine(self._cfg()).check(self.model, self.prop)
        self.assertEqual(result.status, ERROR)
        self.assertIn("apalache.jar not found", result.note)

    def test_timeout(self):
        # The fake java sleeps 2s; with a 1s budget check() must report a
        # bounded (unknown) result, not a decision.
        result = self._check("timeout", apalache_timeout=1)
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("timed out", result.note)

    def test_java_version_error(self):
        result = self._check("java-version-error")
        self.assertEqual(result.status, ERROR)
        self.assertIn("Java 21", result.note)

    def test_hard_error(self):
        # A non-counterexample failure (exit 1, no Error marker) is an error.
        result = self._check("error")
        self.assertEqual(result.status, ERROR)
        self.assertIn("errored", result.note)


if __name__ == "__main__":
    unittest.main()

