# -*- coding: utf-8 -*-
"""tlc.py -- the real-TLC engine: emit bounded TLA+ and run ``tla2tools.jar``.

This is the second engine alongside :mod:`rot.symbolic`. It takes the SAME
:class:`rot.linearization.LinearModel` + invariant, emits a bounded TLA+ module
and ``.cfg`` (via :class:`rot.emitter.Emitter`), and drives the real TLC model
checker with ``java -cp <tla2tools.jar> tlc2.TLC -nowarning -config <M> <M>``.

Because the emitted model is fully concrete (finite domains, total actions),
TLC's exhaustive model check is a genuine proof or a genuine counterexample --
the gold standard the symbolic engine approximates.

The engine returns a :class:`rot.symbolic.EngineResult` so the two engines are
interchangeable downstream (``cegar``, ``verdicts``).

TLC is fully isolated here: if the jar is missing, java fails to launch, or the
model check errors, the engine returns an ``error`` / ``unknown``
``EngineResult`` (it never raises into the pipeline). That lets ``Config``'s
``auto`` policy fall back to the symbolic engine in a bare Python environment.

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


class TlcOutcome(object):
    """Structured result of one TLC invocation (before ``EngineResult``)."""

    def __init__(self, status, note="", witness=None, n_states=0,
                 tla_path="", cfg_path="", command=None, model_path=""):
        self.status = status          # proven / violated / unknown / error
        self.note = note
        self.witness = witness        # dict state (when violated)
        self.n_states = int(n_states)
        self.tla_path = tla_path
        self.cfg_path = cfg_path
        self.command = list(command or [])
        self.model_path = model_path


class TlcEngine(object):
    """Run real TLC over a LinearModel + invariant; return an ``EngineResult``."""

    def __init__(self, cfg):
        self.cfg = cfg

    # -- jar / command -------------------------------------------------------
    def _jar(self):
        return self.cfg.tlc_jar_path()

    def _command(self, jar, base):
        cmd = [self.cfg.java_cmd, "-cp", jar, "tlc2.TLC"]
        if self.cfg.tlc_seed is not None:
            cmd += ["-workers", "1", "-seed", str(self.cfg.tlc_seed)]
        if self.cfg.tlc_depth:
            cmd += ["-depth", str(self.cfg.tlc_depth)]
        cmd += ["-nowarning", "-config", base, base]
        return cmd

    # -- public entry point --------------------------------------------------
    def check(self, model, prop, target="model"):
        """Decide ``prop`` (an Invariant) over ``model`` with TLC.

        ``target`` only names the emitted module so artifacts for different
        (target, property) pairs do not collide. Returns an ``EngineResult``.
        """
        jar = self._jar()
        if jar is None:
            return symbolic.EngineResult(
                "error", note="tla2tools.jar not found; set $TLA2TOOLS_JAR or "
                              "pass tlc_jar=... (TLC engine unavailable)")

        from .emitter import Emitter
        work_dir = self.cfg.work_dir or os.path.join("out", "work")
        if not os.path.isdir(work_dir):
            os.makedirs(work_dir)
        module = _module_name(target, prop.name)
        e = Emitter(model, module_name=module)
        tla_path, cfg_path, op = e.write(work_dir, prop.name,
                                         prop.expression, base=module)
        base = os.path.splitext(os.path.basename(tla_path))[0]
        cmd = self._command(jar, base)

        # -- launch TLC ------------------------------------------------------
        try:
            proc = subprocess.Popen(cmd, cwd=work_dir,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        except OSError as exc:
            return symbolic.EngineResult(
                "error", note="failed to launch TLC: %s" % exc)

        timed_out = False
        try:
            out_b, err_b = proc.communicate(timeout=self.cfg.tlc_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out_b, err_b = proc.communicate()

        out = _decode(out_b) + "\n" + _decode(err_b)
        n_states = _count_states(out)

        if timed_out:
            return symbolic.EngineResult(
                "unknown", n_states=n_states,
                note="TLC timed out after %ss; bounded result, not proven"
                     % self.cfg.tlc_timeout)

        if "No error has been found" in out:
            return symbolic.EngineResult(
                "proven", n_states=n_states, complete=True,
                note="TLC: invariant holds in all %d reachable states"
                     % n_states)

        if "is violated" in out:
            witness, src = self._counterexample(work_dir, base, prop, out)
            return symbolic.EngineResult(
                "violated", witness=witness, n_states=n_states, complete=True,
                note="TLC found a counterexample%s"
                     % ("" if witness else " (witness not captured)"))

        return symbolic.EngineResult(
            "error" if _looks_like_error(out) else "unknown",
            n_states=n_states, note="TLC inconclusive/errored:\n" + _tail(out))

    # -- counterexample ------------------------------------------------------
    def _counterexample(self, work_dir, base, prop, stdout=""):
        """Pick a state that refutes ``prop`` from TLC's output.

        Tries the ``.model`` file first (when TLC wrote one), then falls back to
        parsing the ``The behavior up to this point is:`` trace in stdout -- this
        TLC build prints the counterexample to stdout and does not always persist
        a ``.model`` file. Returns ``(witness_or_None, source_label)``.
        """
        model_path = os.path.join(work_dir, base + ".model")
        if os.path.isfile(model_path):
            try:
                with open(model_path, "r") as f:
                    text = f.read()
            except Exception:
                text = ""
            states = _parse_states(text)
            if states:
                for st in states:
                    if _refutes(prop, st):
                        return st, model_path
                return states[-1], model_path
        states = _parse_trace(stdout)
        if states:
            for st in states:
                if _refutes(prop, st):
                    return st, "stdout"
            return states[-1], "stdout"
        return None, ""


# ---------------------------------------------------------------------------
# .model parsing helpers (module-private)
# ---------------------------------------------------------------------------
def _refutes(prop, state):
    """True iff ``prop`` evaluates to a definite False in ``state``."""
    try:
        r = prop.expression.eval(state)
    except Exception:
        return False
    return r is False


def _parse_states(text):
    """Split a TLC ``.model`` file into a list of ``{var: value}`` states."""
    parts = re.split(r"^State \d+:\s*$", text, flags=re.MULTILINE)
    out = []
    for p in parts:
        if not p.strip():
            continue
        st = {}
        for line in p.splitlines():
            line = line.strip()
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip()
            if not k or not v:
                continue
            st[k] = _coerce(v)
        if st:
            out.append(st)
    return out


def _coerce(v):
    """Turn a TLA+ literal back into a Python value (best effort)."""
    if v == "TRUE":
        return True
    if v == "FALSE":
        return False
    if re.match(r"^-?\d+$", v):
        return int(v)
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _parse_trace(stdout):
    """Parse the ``The behavior up to this point is:`` trace from TLC stdout.

    Per-state format:
        State <n>: <action label>
        /\\ var1 = value1
        /\\ var2 = value2

    Returns a list of ``{var: value}`` dicts in trace order (last element is the
    violating state).
    """
    states = []
    cur = None
    for line in stdout.splitlines():
        s = line.strip()
        if re.match(r"^State \d+:", s):
            if cur is not None:
                states.append(cur)
            cur = {}
            continue
        if cur is None:
            continue
        t = s
        if t.startswith("/\\"):
            t = t[2:].strip()
        if "=" not in t:
            continue
        k, _, v = t.partition("=")
        k = k.strip()
        v = v.strip()
        if k and v:
            cur[k] = _coerce(v)
    if cur is not None:
        states.append(cur)
    return states


def _count_states(out):
    m = re.search(r"(\d+) distinct states found", out)
    if m:
        return int(m.group(1))
    m = re.search(r"distinct states generated was (\d+)", out)
    if m:
        return int(m.group(1))
    return 0


def _looks_like_error(out):
    needles = ("does not match the name", "Syntax", "expecting",
               "is not completely specified", "Error:")
    return any(n in out for n in needles)


def _tail(text, n=1500):
    text = text.strip()
    if len(text) <= n:
        return text
    return "..." + text[-n:]


__all__ = ["TlcEngine", "TlcOutcome", "_module_name"]
