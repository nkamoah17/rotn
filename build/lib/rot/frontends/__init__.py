# -*- coding: utf-8 -*-
"""rot.frontends -- the front-end half of the narrow waist.

A front-end's ONLY job is to turn source code (or any other artifact) into a
``rot.ir.ProtocolIR``.  The contract every front-end must satisfy:

    build_ir(source_dir, protocol, n, buggy) -> ProtocolIR

Architectural rule (enforced by ``tests/test_narrow_waist.py``): a front-end
module must NEVER import from the downstream engines -- ``rot.emitter``,
``rot.tlc``, or ``rot.cegar``.  Verification engines consume the IR; they are
never part of a front-end.

Sub-packages / modules:
  * ``rot.frontends.joern``   -- Joern CLI driver (import + scrape).
  * ``rot.frontends.java``    -- the Java front-end (public ``build_ir``).
  * ``rot.frontends.cpg_model`` -- language-agnostic CPG data model.
  * ``rot.frontends.cone``      -- cone-of-influence over a CPG.
  * ``rot.frontends.cedar``     -- Cedar policy front-end (``parse_cedar``).

Pure stdlib, Python 3.6 compatible.
"""

from .cedar import CedarError, parse_cedar, parse_cedar_file

__all__ = ["CedarError", "parse_cedar", "parse_cedar_file"]
