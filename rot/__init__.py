# -*- coding: utf-8 -*-
"""ROTN -- the caravel/rot-verify temporal policy verification engine.

ROTN ingests an AI agent's tool policy (Dogwood *or* an MCP manifest),
verifies it with three independent engines and a bounded CEGAR loop,
maps findings to SOC 2 / AIUC controls, and emits a deterministic,
hashed trace that replays as an interactive proof on GitHub Pages.

Pipeline: front-end -> ProtocolIR (the narrow waist) -> linearization
-> engine (symbolic | SMT | policy-direct) + bounded CEGAR -> verdict
-> deterministic manifest (the RTF trace).

This package is pure-stdlib (Python 3.6 compatible) so it runs fully
offline.  See ``docs/architecture.md`` for the single source of truth.
"""

__version__ = "0.1.0"

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
    "cpg_reader",
    "mcp_adapter",
]
