# -*- coding: utf-8 -*-
"""apalache.py -- the Apalache engine: emit bounded TLA+ and run ``apalache.jar``.

This is the third engine alongside :mod:`rot.symbolic` and :mod:`rot.tlc`. It
takes the SAME :class:`rot.linearization.LinearModel` + invariant, emits a
bounded TLA+ module (via :class:`rot.emitter.Emitter`), and drives the Apalache
model checker with the locked 0.62.x command form::

    java -jar apalache.jar check --out-dir=<dir> --init=Init --next=Next \\
        --inv=<op> --length=<n> <file.tla>

(Equals-form options, ``.tla`` file last, ``--out-dir`` a *command* option after
``check`` -- the space form is rejected by this build as a positional.)

Apalache is an SMT-based *bounded* model checker, so its verdicts are bounded:
* ``NoError`` (exit 0)  -> the invariant held within the bound -> ``proven``;
* ``Error``   (exit 12) -> a concrete counterexample was found. Apalache
  persists it as an ITF trace (``violation.itf.json``) under
  ``<out-dir>/<module>.tla/<timestamp>/``; we parse it with :mod:`rot.itf` and
  recover the offending state as the witness -> ``violated``.

The engine returns a :class:`rot.symbolic.EngineResult` so all three engines
are interchangeable downstream (``cegar``, ``verdicts``).

Apalache is fully isolated here: if the jar or a Java 21 runtime is missing,
the launch fails, the check times out, or the check errors, the engine returns
an ``error`` / ``unknown`` ``EngineResult`` (it never raises into the pipeline).
That lets ``Config``'s ``auto`` policy fall back to the other engines in a bare
Python environment.

Pure stdlib, Python 3.6 compatible (no f-strings, no ``capture_output``).
"""

import os
import re
import subprocess

from . import symbolic


def _decode(b):
    """Best-effort bytes -> str (tolerates a missing stream)."""
    if b is None:
        return ""
    if isinstance(b, bytes):
        return b.decode("utf-8", "replace")
    return b


def _module_name(target, prop):
    """A safe, unique TLA+ module name for one (target, property) pair."""
    base = "%s_%s" % (target, prop)
    base = re.sub(r"[^A-Za-z0-9_]", "_", base)
    if not base or (not base[0].isalpha() and base[0] != "_"):
        base = "M_" + base
    return base


class ApalacheEngine(object):
    """Run Apalache over a LinearModel + invariant; return an ``EngineResult``."""

    name = "apalache"

    def __init__(self, cfg):
        self.cfg = cfg

    # -- jar / java / bound --------------------------------------------------
    def _jar(self):
        return self.cfg.apalache_jar_path()

    def _java(self):
        return self.cfg.apalache_java_cmd()

    def _length(self):
        """The bounded horizon N for ``--length`` (Apalache's own default is 10)."""
        n = self.cfg.apalache_length
        if n is None:
            return 10
        return int(n)

    def _command(self, java, jar, tla_path, op, out_dir):
        """The locked 0.62.x command: equals-form options, ``.tla`` file last."""
        return [java, "-jar", jar, "check",
                "--out-dir=%s" % out_dir,
                "--init=Init",
                "--next=Next",
                "--inv=%s" % op,
                "--length=%d" % self._length(),
                tla_path]

    # -- public entry point --------------------------------------------------
    def check(self, model, prop, target="model"):
        """Decide ``prop`` (an Invariant) over ``model`` with Apalache.

        ``target`` only names the emitted module so artifacts for different
        (target, property) pairs do not collide. Returns an ``EngineResult``.
        Never raises.
        """
        jar = self._jar()
        if jar is None:
            return symbolic.EngineResult(
                "error", note="apalache.jar not found; set $APALACHE_JAR or "
                              "pass apalache_jar=... (Apalache engine unavailable)")
        java = self._java()
        if java is None:
            return symbolic.EngineResult(
                "error", note="no Java 21 runtime found; set $APALACHE_JAVA or "
                              "pass apalache_java=... (Apalache 0.62.x needs JDK 21)")

        from .emitter import Emitter
        work_dir = self.cfg.work_dir or os.path.join("out", "work")
        work_dir = os.path.abspath(work_dir)
        if not os.path.isdir(work_dir):
            os.makedirs(work_dir)
        module = _module_name(target, prop.name)
        e = Emitter(model, module_name=module)
        tla_path, cfg_path, op = e.write(work_dir, prop.name,
                                         prop.expression, base=module)

        # Apalache writes artifacts under <out-dir>/<module>.tla/<timestamp>/.
        out_dir = os.path.join(work_dir, "apalache")
        cmd = self._command(java, jar, tla_path, op, out_dir)

        # -- launch Apalache -------------------------------------------------
        try:
            proc = subprocess.Popen(cmd, cwd=work_dir,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        except OSError as exc:
            return symbolic.EngineResult(
                "error", note="failed to launch Apalache: %s" % exc)

        timed_out = False
        exit_code = None
        try:
            out_b, err_b = proc.communicate(timeout=self.cfg.apalache_timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out_b, err_b = proc.communicate()

        out = _decode(out_b) + "\n" + _decode(err_b)

        if timed_out:
            return symbolic.EngineResult(
                "unknown",
                note="Apalache timed out after %ss; bounded result, not proven"
                     % self.cfg.apalache_timeout)

        # Java 21 runtime mismatch (Apalache 0.62.x is compiled for Java 21).
        if ("LinkageError" in out
                or "UnsupportedClassVersionError" in out
                or "class file version" in out):
            return symbolic.EngineResult(
                "error",
                note="Apalache failed to load: this build needs Java 21 "
                     "(class-file/Linkage error). Point $APALACHE_JAVA at a "
                     "JDK 21 `java`. Output:\n" + _tail(out))

        if exit_code == 0:
            return symbolic.EngineResult(
                "proven", complete=True,
                note="Apalache: invariant holds within the bound "
                     "(length=%d); outcome NoError" % self._length())

        # Non-zero exit: a counterexample (Apalache exit 12) or a hard error.
        if exit_code == 12 or _looks_violated(out):
            witness = self._find_witness(out_dir, prop)
            return symbolic.EngineResult(
                "violated", witness=witness, complete=True,
                note="Apalache found a counterexample%s"
                     % ("" if witness else " (witness not captured)"))

        return symbolic.EngineResult(
            "error", note="Apalache errored (exit %s):\n%s"
                         % (exit_code, _tail(out)))


    # -- counterexample ------------------------------------------------------
    def _find_witness(self, out_dir, prop):
        """Locate and parse Apalache's ITF witness; return the offending state.

        Globs ``*.itf.json`` under ``out_dir`` (Apalache writes
        ``violation.itf.json`` under ``<module>.tla/<timestamp>/``), parses the
        most recent one with :func:`rot.itf.parse_itf`, and returns the first
        state where ``prop`` is a definite False (falling back to the last
        state). Returns ``None`` if no witness can be recovered. Never raises.
        """
        import glob
        try:
            hits = glob.glob(os.path.join(out_dir, "**", "*.itf.json"),
                             recursive=True)
        except Exception:
            hits = []
        if not hits:
            return None
        # Prefer the most recently written witness (each run makes a new
        # <module>.tla/<timestamp>/ dir, so the newest is this run's).
        try:
            hits.sort(key=os.path.getmtime, reverse=True)
        except Exception:
            pass
        from .itf import parse_itf, ItfError
        for path in hits:
            try:
                trace = parse_itf(path)
            except ItfError:
                continue
            except Exception:
                continue
            states = trace.states
            if not states:
                continue
            for st in states:
                if _refutes(prop, st):
                    return dict(st)
            return dict(states[-1])
        return None


def _refutes(prop, state):
    """True iff ``prop`` evaluates to a definite False in ``state``."""
    try:
        r = prop.expression.eval(state)
    except Exception:
        return False
    return r is False


def _looks_violated(out):
    """True iff Apalache's output carries a counterexample marker.

    Deliberately specific: ``The outcome is: Error`` must not match the success
    line ``The outcome is: NoError``, and we do NOT use the generic
    ``EXITCODE: ERROR`` (that also appears for hard errors such as a missing
    file, which is not a counterexample).
    """
    needles = ("The outcome is: Error", "Checker has found an error")
    return any(n in out for n in needles)


def _tail(text, n=1500):
    text = text.strip()
    if len(text) <= n:
        return text
    return "..." + text[-n:]


__all__ = ["ApalacheEngine", "_module_name"]
