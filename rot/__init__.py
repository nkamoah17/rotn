# -*- coding: utf-8 -*-
"""ROTN -- the nkamoah17/rotn temporal policy verification engine.

ROTN ingests an AI agent's tool policy (Dogwood *or* an MCP manifest)
and verifies it with a built-in, pure-stdlib default engine (a bounded
state-space model finder), with optional Z3 / TLC / Apalache cross-checks
that degrade to a skip or an honest ``UNKNOWN`` when absent, and a bounded
re-check loop (bounded re-checking -- not counterexample-guided
refinement).  Every verdict is engine-labeled, so you always know which
engine(s) produced it.  It maps findings to SOC 2 / AIUC controls and
emits a deterministic, hashed trace that replays as an interactive proof
on GitHub Pages.

Pipeline: front-end -> ProtocolIR (the narrow waist) -> linearization
-> engine (built-in pure-stdlib default | optional Z3/TLC/Apalache
cross-checks) + bounded re-check -> engine-labeled verdict
-> deterministic manifest (the RTF trace).

This package is pure-stdlib (Python 3.8+) so it runs fully
offline.  See ``docs/architecture.md`` for the single source of truth.
"""

__version__ = "0.2.0"

__all__ = [
    "sat",
    "ir",
    "linearization",
    "abstraction",
    "emitter",
    "tlc",
    "itf",
    "invariants",
    "verdicts",
    "cegar",
    "config",
    "mcp_adapter",
    "policy_verify",
]
