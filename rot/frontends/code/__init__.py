# -*- coding: utf-8 -*-
"""rot.frontends.code -- Code-to-TLA+ extraction (spec §7, D3).

A narrow-waist Ingest front-end: it reads legacy source and produces
``ProtocolIR`` *candidates* -- one pinned property per extracted control -- so
the Verify plane can PROVE each or hand back the exact bypass witness.

Public entry point (narrow-waist contract, see ``rot/frontends/__init__.py``)::

    extract(source, filename="") -> Candidate

The candidate is then materialized into a full ``ProtocolIR`` by
:func:`rot.lower.lower_candidate` and discharged by the Verify plane
(:func:`rot.cegar.verify_extraction`).  See ``extractor.py`` for the P1
pattern class (budget + label/flow) and the E1/E2/E4 honesty rules.
"""

from .extractor import (CANDIDATE_TAG, Candidate, PATTERN_BUDGET,
                        PATTERN_CLASS, PATTERN_LABEL_FLOW, extract, extract_file)

__all__ = [
    "PATTERN_CLASS",
    "PATTERN_BUDGET",
    "PATTERN_LABEL_FLOW",
    "CANDIDATE_TAG",
    "Candidate",
    "extract",
    "extract_file",
]