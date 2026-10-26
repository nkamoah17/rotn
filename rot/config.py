# -*- coding: utf-8 -*-
"""config.py -- central runtime configuration for the ROTN verification pipeline.

Everything the downstream stages need to know about *how* to run lives here, so
that the individual modules (emitter, tlc, cegar, ...) stay pure and testable.
Two concerns are central:

  * ENGINE SELECTION. The invariant check can be discharged by one of four
    independent engines:
        - ``tlc``      : the real TLC model checker (java tla2tools.jar). This is
                         the gold standard, but it needs a JVM + the jar.
        - ``symbolic`` : our own SAT-based engine (rot.symbolic + rot.sat). Pure
                         Python, fully offline, deterministic.
        - ``apalache`` : the ITF trace engine (rot.itf): evaluates the pinned
                          invariant over a concrete Apalache counterexample
                          trace (``Config.itf_trace``). It can refute,
                          never prove.
        - ``apalache-mc``: the real Apalache runner (rot.apalache): emits bounded
                           TLA+ and drives ``apalache.jar`` (needs a jar + Java 21).
                           It can prove (bounded NoError) and refute (counterexample
                           + witness). Gated by ``apalache_enabled`` +
                           ``apalache_available()``.
      ``Config.select_engine()`` resolves the ``"auto"`` policy: use TLC when a
      jar is present and reachable, otherwise fall back to the symbolic engine.
      This keeps the whole pipeline runnable in a bare Python environment.

  * BUDGETS / BOUNDS. State-space budgets (``max_states``), CEGAR iteration cap
    (``cegar_max_iter``), the bounded-liveness horizon (``liveness_horizon``,
    max steps for ``bounded_eventually`` reach_within checks), and the
    property-directed bounds (``participant_bound`` / ``env_bound``) that
    become recorded assumptions.

Pure stdlib, Python 3.6 compatible.
"""

import os

# Engine identifiers.
ENGINE_AUTO = "auto"
ENGINE_TLC = "tlc"
ENGINE_SYMBOLIC = "symbolic"
ENGINE_APALACHE = "apalache"
# The real Apalache *runner* (rot.apalache): emits bounded TLA+ and drives
# apalache.jar. Distinct from ENGINE_APALACHE (the ITF *trace* engine, rot.itf),
# which only evaluates a pre-existing counterexample trace and can never prove.
ENGINE_APALACHE_MC = "apalache-mc"
ENGINE_CROSSCHECK = "crosscheck"


def _find_java21():
    """Best-effort discovery of a Java 21 ``java.exe`` on this box.

    Apalache 0.62.x requires JDK 21. We probe the well-known per-user install
    dir first, then the standard vendor dirs, and return the newest matching
    ``java.exe`` (or ``None``). Pure stdlib (``glob``).
    """
    import glob
    patterns = [
        r"C:\java\jdk-21*\bin\java.exe",
        r"C:\Program Files\Java\jdk-21*\bin\java.exe",
        r"C:\Program Files\Eclipse Adoptium\jdk-21*\bin\java.exe",
        r"C:\Program Files\Microsoft\jdk-21*\bin\java.exe",
    ]
    for pat in patterns:
        hits = sorted(glob.glob(pat), reverse=True)
        for hit in hits:
            if os.path.isfile(hit):
                return hit
    return None


class Config(object):
    """Runtime configuration for one verification run.

    All fields have safe defaults so ``Config()`` is always usable. Override any
    field with ``Config(..., tlc_jar=..., engine="symbolic", ...)``.
    """

    def __init__(self,
                 engine=ENGINE_AUTO,
                 tlc_jar=None,
                 java_cmd="java",
                 tlc_timeout=120,
                 tlc_depth=None,
                 tlc_workers=1,
                 tlc_seed=None,
                 max_states=200000,
                 cegar_max_iter=6,
                 liveness_horizon=12,
                 participant_bound=None,
                 env_bound=None,
                 out_dir="out",
                 work_dir="out/work",
                 verbose=False,
                 llm_enabled=False,
                 llm_base_url=None,
                 llm_api_key_env="OPENAI_API_KEY",
                 llm_model=None,
                 llm_timeout=120,
                 llm_max_turns=8,
                 itf_trace=None,
                 apalache_enabled=False,
                 apalache_jar=None,
                 apalache_java=None,
                 apalache_timeout=120,
                 apalache_length=None):
        self.engine = engine
        self.tlc_jar = tlc_jar
        self.java_cmd = java_cmd
        self.tlc_timeout = int(tlc_timeout)
        self.tlc_depth = int(tlc_depth) if tlc_depth else None
        self.tlc_workers = int(tlc_workers)
        self.tlc_seed = tlc_seed
        self.max_states = int(max_states)
        self.cegar_max_iter = int(cegar_max_iter)
        # Phase 4: bounded-liveness horizon (max steps) for ``bounded_eventually``
        # invariants, used by the CEGAR loop's ``SymbolicEngine.reach_within``.
        self.liveness_horizon = int(liveness_horizon)
        self.participant_bound = participant_bound
        self.env_bound = env_bound
        self.out_dir = out_dir
        self.work_dir = work_dir
        self.verbose = verbose
        # LLM baseline (optional, opt-in; never affects the formal verdict).
        self.llm_enabled = bool(llm_enabled)
        self.llm_base_url = llm_base_url
        self.llm_api_key_env = llm_api_key_env
        self.llm_model = llm_model
        self.llm_timeout = int(llm_timeout)
        self.llm_max_turns = int(llm_max_turns)
        # Apalache ITF trace engine (rot.itf): path to a .itf.json
        # counterexample trace, evaluated when engine == ENGINE_APALACHE.
        self.itf_trace = itf_trace
        # Apalache native engine (rot.apalache): drives the real Apalache jar.
        # ``apalache_enabled`` gates the engine; the jar/java paths and the
        # bounded-check length/timeout are resolved lazily (see apalache_*()).
        self.apalache_enabled = bool(apalache_enabled)
        self.apalache_jar = apalache_jar
        self.apalache_java = apalache_java
        self.apalache_timeout = int(apalache_timeout)
        self.apalache_length = int(apalache_length) if apalache_length else None

    # -- engine selection ----------------------------------------------------
    def tlc_jar_path(self):
        """Resolve the tla2tools.jar location, or ``None`` if not configured.

        Resolution order: explicit ``self.tlc_jar`` -> ``$TLA2TOOLS_JAR`` ->
        ``$TLC_JAR`` -> a well-known local Toolbox install.
        """
        candidates = [self.tlc_jar,
                      os.environ.get("TLA2TOOLS_JAR"),
                      os.environ.get("TLC_JAR")]
        local = os.path.join(
            os.path.expanduser("~"), "Downloads",
            "TLAToolbox-1.7.1-win32.win32.x86_64", "toolbox", "tla2tools.jar")
        candidates.append(local)
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return None

    def tlc_available(self):
        """True iff a usable ``java`` + ``tla2tools.jar`` pair is present."""
        if self.tlc_jar_path() is None:
            return False
        java = self.java_cmd
        # A bare command name means "on PATH"; a path means "file must exist".
        if os.path.sep in java or "/" in java:
            return os.path.isfile(java)
        # Treat a bare name as available if it resolves (best-effort, no shell).
        try:
            import shutil
            return shutil.which(java) is not None
        except Exception:
            return True

    def apalache_jar_path(self):
        """Resolve the Apalache jar location, or ``None`` if not configured.

        Resolution order: explicit ``self.apalache_jar`` -> ``$APALACHE_JAR``
        -> the well-known local install (``C:\\apalache_install\\...``).
        """
        candidates = [self.apalache_jar,
                      os.environ.get("APALACHE_JAR"),
                      r"C:\apalache_install\apalache-0.62.3\lib\apalache.jar"]
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return None

    def apalache_java_cmd(self):
        """Resolve the ``java`` executable to run Apalache with.

        Resolution order: explicit ``self.apalache_java`` -> ``$APALACHE_JAVA``
        -> a discovered JDK 21 (``_find_java21``) -> ``shutil.which("java")``
        -> the bare name ``"java"`` (last resort, resolved on the PATH).
        """
        if self.apalache_java:
            return self.apalache_java
        env = os.environ.get("APALACHE_JAVA")
        if env:
            return env
        found = _find_java21()
        if found:
            return found
        try:
            import shutil
            which = shutil.which("java")
            if which:
                return which
        except Exception:
            pass
        return "java"

    def apalache_available(self):
        """True iff a usable ``java`` + Apalache jar pair is present."""
        if self.apalache_jar_path() is None:
            return False
        java = self.apalache_java_cmd()
        # A bare command name means "on PATH"; a path means "file must exist".
        if os.path.sep in java or "/" in java:
            return os.path.isfile(java)
        try:
            import shutil
            return shutil.which(java) is not None
        except Exception:
            return True

    def select_engine(self):
        """Resolve ``self.engine`` (possibly ``"auto"``) to a concrete engine."""
        if self.engine == ENGINE_AUTO:
            return ENGINE_TLC if self.tlc_available() else ENGINE_SYMBOLIC
        if self.engine in (ENGINE_TLC, ENGINE_SYMBOLIC, ENGINE_APALACHE,
                           ENGINE_APALACHE_MC, ENGINE_CROSSCHECK):
            return self.engine
        raise ValueError("unknown engine %r" % (self.engine,))

    # -- helpers -------------------------------------------------------------
    def ensure_dirs(self):
        for d in (self.out_dir, self.work_dir):
            if d and not os.path.isdir(d):
                os.makedirs(d)

    def to_dict(self):
        return {
            "engine": self.engine,
            "resolved_engine": self.select_engine(),
            "tlc_jar": self.tlc_jar_path(),
            "tlc_available": self.tlc_available(),
            "tlc_timeout": self.tlc_timeout,
            "tlc_depth": self.tlc_depth,
            "tlc_workers": self.tlc_workers,
            "max_states": self.max_states,
            "cegar_max_iter": self.cegar_max_iter,
            "liveness_horizon": self.liveness_horizon,
            "participant_bound": self.participant_bound,
            "env_bound": self.env_bound,
            "itf_trace": self.itf_trace,
            "apalache_enabled": self.apalache_enabled,
            "apalache_jar": self.apalache_jar_path(),
            "apalache_java": self.apalache_java_cmd(),
            "apalache_available": self.apalache_available(),
            "apalache_timeout": self.apalache_timeout,
            "apalache_length": self.apalache_length,
            "out_dir": self.out_dir,
            "work_dir": self.work_dir,
            "llm_enabled": self.llm_enabled,
            "llm_base_url": self.llm_base_url,
            "llm_api_key_env": self.llm_api_key_env,
            "llm_model": self.llm_model,
            "llm_timeout": self.llm_timeout,
            "llm_max_turns": self.llm_max_turns,
        }

    @classmethod
    def from_dict(cls, d):
        keys = ("engine", "tlc_jar", "java_cmd", "tlc_timeout", "tlc_depth",
                "tlc_workers", "tlc_seed", "max_states", "cegar_max_iter",
                "liveness_horizon",
                "participant_bound", "env_bound", "itf_trace", "out_dir",
                "work_dir", "verbose", "llm_enabled", "llm_base_url",
                "llm_api_key_env", "llm_model", "llm_timeout", "llm_max_turns",
                "apalache_enabled", "apalache_jar", "apalache_java",
                "apalache_timeout", "apalache_length")
        return cls(**{k: d[k] for k in keys if k in d})


__all__ = ["Config", "ENGINE_AUTO", "ENGINE_TLC", "ENGINE_SYMBOLIC",
           "ENGINE_APALACHE", "ENGINE_CROSSCHECK"]
