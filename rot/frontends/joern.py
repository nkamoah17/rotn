# -*- coding: utf-8 -*-
"""joern.py -- Python driver for the Joern CLI (front-end plumbing).

This module owns the *brittle* part of the pipeline: locating the Java +
Joern toolchain, running a Scala scrape script, and parsing the JSON it
writes.  Everything downstream of that (``cpg_model`` / ``cone`` / the
``java`` front-end) is pure Python and never touches this file.

Strategy (proven on this machine):
  * Joern lives as a classpath jar bundle (``joern-cli/lib/*``), not a
    ``joern`` binary on PATH.  We drive the Ammonite bridge directly:

        type scrape.sc | java -cp "JOERN_LIB/*" \
            io.shiftleft.joern.console.AmmoniteBridge

    which runs the script exactly like ``joern console`` does, without the
    shell-quoting problems of the ``joern`` launcher script.
  * Paths are passed to the script via environment variables
    (``ROTN_CPG_SOURCE`` / ``ROTN_CPG_OUT``), so the same ``scrape.sc`` works
    for any source directory and any output location.
  * The scrape writes a JSON CPG model (see ``cpg_model.CpgModel``); we
    validate the output and surface a useful error (with a log tail) on
    failure instead of crashing silently.

Toolchain discovery order (first hit wins):
  1. ``ROTN_JOERN_HOME`` + ``ROTN_JAVA`` env vars (explicit override).
  2. ``JOERN_HOME`` + ``JAVA_HOME``/PATH (generic).
  3. This machine's known locations (Android Studio JBR + ``wrought/joern``).

Pure stdlib, Python 3.6 compatible.
"""

import json
import os
import subprocess
import tempfile
import time

from rot.frontends.cpg_model import CpgModel

# The Ammonite bridge main class that runs a Scala script on stdin.
JOERN_BRIDGE_MAIN = "io.shiftleft.joern.console.AmmoniteBridge"

# Marker the scrape script prints on success; lets us distinguish "Joern
# started and finished the script" from "Joern crashed mid-import".
SCRAPE_OK_MARKER = "ROTN-SCRAPE-OK"

DEFAULT_TIMEOUT = 900  # seconds; a fresh Java import of a small protocol is <60s


class JoernError(Exception):
    """Raised when the Joern toolchain is missing or a scrape fails."""


class JoernToolchain(object):
    """A located, usable Joern + Java toolchain."""

    def __init__(self, java, lib_dir, home=None, source="auto"):
        self.java = java
        self.lib_dir = lib_dir
        self.home = home or os.path.dirname(os.path.dirname(lib_dir))
        self.source = source

    def classpath(self):
        return os.path.join(self.lib_dir, "*")

    def describe(self):
        return "java=%s lib=%s (source=%s)" % (self.java, self.lib_dir, self.source)

    def check(self):
        """Return the list of problems (empty list == usable)."""
        problems = []
        if not (self.java and os.path.isfile(self.java)):
            problems.append("java executable not found: %s" % self.java)
        if not (self.lib_dir and os.path.isdir(self.lib_dir)):
            problems.append("joern lib dir not found: %s" % self.lib_dir)
        else:
            jars = [f for f in os.listdir(self.lib_dir) if f.endswith(".jar")]
            if not any("joern" in f.lower() for f in jars):
                problems.append("no joern jars in %s" % self.lib_dir)
        return problems


def _candidate_lib_dirs():
    """Joern lib dirs to try, in order (best first)."""
    cands = []
    env_home = os.environ.get("ROTN_JOERN_HOME") or os.environ.get("JOERN_HOME")
    if env_home:
        cands.append((os.path.join(env_home, "lib"), "env"))
    # Known local install on this machine.
    cands.append((r"C:\Users\jeren\Documents\wrought\joern\joern-cli\lib", "known"))
    # Generic locations.
    home = os.path.expanduser("~")
    cands.append((os.path.join(home, ".cache", "joern", "lib"), "generic"))
    cands.append((os.path.join(home, "joern", "joern-cli", "lib"), "generic"))
    return cands


def _candidate_javas():
    javas = []
    env_java = os.environ.get("ROTN_JAVA")
    if env_java:
        javas.append(env_java)
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        javas.append(os.path.join(java_home, "bin", "java.exe"))
        javas.append(os.path.join(java_home, "bin", "java"))
    javas.append("java")  # rely on PATH last
    # Known JBR on this machine (Android Studio).
    javas.append(r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe")
    return javas


def find_toolchain():
    """Locate a usable Joern + Java toolchain, or raise JoernError."""
    lib_ok = None
    for lib_dir, source in _candidate_lib_dirs():
        if os.path.isdir(lib_dir) and any(
                f.endswith(".jar") for f in os.listdir(lib_dir)):
            lib_ok = (lib_dir, source)
            break
    if lib_ok is None:
        raise JoernError(
            "No Joern lib dir found. Set ROTN_JOERN_HOME to a joern-cli "
            "directory (one containing lib/*.jar) or JOERN_HOME.")

    lib_dir, source = lib_ok
    for java in _candidate_javas():
        if os.path.isfile(java) or java == "java":
            tc = JoernToolchain(java=java, lib_dir=lib_dir, source=source)
            problems = tc.check()
            # A bare "java" on PATH may not exist; keep looking.
            if not problems:
                return tc
    raise JoernError(
        "Found Joern lib at %s but no usable java executable. "
        "Set ROTN_JAVA or JAVA_HOME." % lib_dir)


def run_joern_script(tc, script_path, env_extra=None, cwd=None,
                     timeout=DEFAULT_TIMEOUT, log_path=None):
    """Run a Scala script through the Joern Ammonite bridge in *script mode*.

    The bridge MUST be launched as ``AmmoniteBridge --script <path>``:
    that makes it compile and execute the whole file as a single program
    and then exit.  Feeding the script on stdin instead drops the bridge
    into the interactive REPL, which treats the scrape's top-level
    ``{ ... }`` block as one incomplete statement, buffers it, and drops
    it at EOF -- only *echoing* the input, which makes the success
    marker look present when the script never actually ran.

    Returns ``(returncode, output_text)``.  ``log_path`` (optional)
    also receives the full output for offline inspection.
    """
    if not os.path.isfile(script_path):
        raise JoernError("scrape script not found: %s" % script_path)
    problems = tc.check()
    if problems:
        raise JoernError("toolchain not usable: %s" % "; ".join(problems))

    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)

    cmd = [tc.java, "-Xmx4G", "-cp", tc.classpath(), JOERN_BRIDGE_MAIN,
           "--script", script_path]

    def _run():
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, cwd=cwd, env=env)
        try:
            stdout, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
            raise JoernError("Joern scrape timed out after %ss" % timeout)
        return proc.returncode, (stdout.decode("utf-8", "replace")
                                 if stdout is not None else "")

    rc, text = _run()
    if log_path:
        with open(log_path, "w") as logf:
            logf.write("# cmd: " + " ".join(cmd) + "\n")
            logf.write("# rc: %d\n" % rc)
            logf.write(text)
    return rc, text


def _to_posix(path):
    """Normalize a path to forward-slash form (safe for the JVM on Windows)."""
    return path.replace("\\", "/")


def _tail(text, n=40):
    lines = text.splitlines()
    return "\n".join(lines[-n:])


def scrape_model(source_dir, out_path=None, tc=None, timeout=DEFAULT_TIMEOUT,
                 log_path=None, keep_workdir=False, scrape_script=None):
    """Import ``source_dir`` with Joern, scrape it, return a ``CpgModel``.

    ``out_path``      where the JSON CPG model is written (default: tempdir).
    ``tc``            a ``JoernToolchain`` (default: ``find_toolchain()``).
    ``timeout``       seconds to allow the whole scrape.
    ``log_path``      where the full Joern output is saved (default: tempdir).
    ``keep_workdir``  keep the temp workdir (debugging).
    ``scrape_script`` path to scrape.sc
                      (default: rot/frontends/java/scrape.sc).

    Raises ``JoernError`` with a log tail on any failure.
    """
    if not os.path.isdir(source_dir):
        raise JoernError("source_dir not found: %s" % source_dir)

    tc = tc or find_toolchain()
    if scrape_script is None:
        scrape_script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "frontends", "java", "scrape.sc")
    if not os.path.isfile(scrape_script):
        raise JoernError("scrape script not found: %s" % scrape_script)

    workdir = tempfile.mkdtemp(prefix="rotn_joern_")
    out_path = out_path or os.path.join(workdir, "cpg_model.json")
    log_path = log_path or os.path.join(workdir, "scrape.log")

    env_extra = {
        "ROTN_CPG_SOURCE": _to_posix(source_dir),
        "ROTN_CPG_OUT": _to_posix(out_path),
        "ROTN_CPG_WORK": _to_posix(workdir),
    }

    # NB: the workdir (which by default holds the JSON output and the log)
    # must survive every check below -- cleanup happens only on success.
    t0 = time.time()
    rc, text = run_joern_script(
        tc, scrape_script, env_extra=env_extra, cwd=workdir,
        timeout=timeout, log_path=log_path)

    dt = time.time() - t0
    if rc != 0:
        raise JoernError(
            "Joern exited %d (in %.1fs). Log: %s\n--- tail ---\n%s"
            % (rc, dt, log_path, _tail(text)))
    # The marker must stand on its OWN line: a bare substring match would
    # be satisfied by the REPL *echoing* the script source (false positive).
    if SCRAPE_OK_MARKER not in {ln.strip() for ln in text.splitlines()}:
        raise JoernError(
            "Joern ran but the scrape did not report OK (%s). Log: %s\n"
            "--- tail ---\n%s" % (SCRAPE_OK_MARKER, log_path, _tail(text)))
    if not os.path.isfile(out_path):
        raise JoernError(
            "scrape reported OK but no JSON at %s. Log: %s"
            % (out_path, log_path))
    try:
        with open(out_path, "r") as f:
            json.load(f)  # must be valid JSON before we trust it
    except ValueError as e:
        raise JoernError(
            "scrape wrote invalid JSON (%s) at %s. Log: %s"
            % (e, out_path, log_path))

    model = CpgModel.from_file(out_path)
    model.meta.setdefault("source", _to_posix(source_dir))
    model.meta.setdefault("scrape_seconds", round(dt, 2))
    errors = model.validate()
    if errors:
        raise JoernError(
            "scrape produced an invalid CpgModel: %s. Log: %s"
            % ("; ".join(errors), log_path))

    # Everything verified: only now may the scratch workdir be removed.
    # On failure paths above it is kept, so the log can be inspected.
    if not keep_workdir and not os.environ.get("ROTN_KEEP_WORKDIR"):
        _rmtree(workdir)
    return model


def _rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


__all__ = [
    "JoernError",
    "JoernToolchain",
    "find_toolchain",
    "run_joern_script",
    "scrape_model",
]
