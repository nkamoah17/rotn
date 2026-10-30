# -*- coding: utf-8 -*-
"""rot.frontends.cpg -- CPG -> Candidate extraction (spec §7, D3; CPG-2).

A narrow-waist Ingest front-end, the **second code-grounded producer** of
the P1 pattern class: it reads a language-agnostic ``CpgModel`` scrape (the
output of e.g. a Joern CPG, via ``rot.frontends.cpg_reader``) and recognizes
the P1 shapes from *CPG structure* -- dataflow edges, call edges, field
read/write sets, declared types -- not from source-text name heuristics.

Public entry point (narrow-waist contract, see ``rot/frontends/__init__.py``)::

    extract_cpg(model, shape=None, method=None) -> Candidate

It emits the same :class:`Candidate` contract as ``rot.frontends.code``
(one class, imported -- not duplicated), so both producers feed the same
``lower_candidate`` -> Verify pipeline.  The A/B gate
(``tests/test_cpg_extraction.py``) checks that for the same control both
producers lower to a ``to_dict()``-identical ``ProtocolIR``.  See
``extractor.py`` for the structural recognition rules and the E1/E2/E4
honesty rules.
"""

from .extractor import extract_cpg

__all__ = [
    "extract_cpg",
]
