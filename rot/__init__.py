# -*- coding: utf-8 -*-
"""ROTN Phase 1 -- sound spec core.

Pipeline: CPG -> property-directed abstraction -> symbolic translation
-> deterministic TLA+ emitter -> TLC invariant pipeline -> bounded CEGAR.

This package is pure-stdlib (Python 3.6 compatible) so it runs fully offline.
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
]
