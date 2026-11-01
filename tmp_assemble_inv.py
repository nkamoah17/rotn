# -*- coding: utf-8 -*-
"""Assemble rotn-research/rotn_research/invariants.py from the extracted
research-invariant block + imports + registration."""
import io

block = io.open("tmp_research_invariants_block.py", encoding="utf-8").read()

HEADER = '''# -*- coding: utf-8 -*-
"""Research invariant kinds (ZAB / PBFT / payment / approval / liveness).

These are the invariant *kinds* that the research plane pins.  They were
previously defined in ``rot.invariants``; after the product/research split
they live here and are re-registered into the shared ``rot.invariants``
registry via ``register`` so that research targets resolve exactly as before.

The product never imports this module; only the research plane (and its
tests) do.  Importing ``rotn_research`` triggers the registration at the
bottom of this file.
"""
from rot import ir                                    # product (shared IR)
import rot.invariants as _inv                         # product (registry)
from rot.invariants import (                          # product (data model)
    Invariant,
    LABEL_BOUNDED, LABEL_EVENTUALLY,
    KIND_SAFETY, KIND_LIVENESS,
    RUNG_LOCAL,
)
import rotn_research.zab as zab                       # research
import rotn_research.payment as payment               # research
import rotn_research.approval as approval             # research (CAP + props)

'''

RESEARCH_NAMES = [
    "zab_no_premature_apply", "zab_apply_persisted", "pbft_quorum",
    "pbft_prepare_before_commit", "no_double_charge", "charge_requires_order",
    "settle_requires_charge", "no_unapproved_irreversible",
    "no_privilege_escalation", "no_deadlock", "task_ends_or_escalates",
    "no_runaway_budget",
]

REG = "\n\n# --- register into the shared product registry ---------------------\n"
for n in RESEARCH_NAMES:
    REG += '_inv.register("%s", %s)\n' % (n, n)
REG += ("__all__ = %r\n" % RESEARCH_NAMES)

out = HEADER + block + REG
io.open("rotn-research/rotn_research/invariants.py", "w", encoding="utf-8",
        newline="\n").write(out)
print("wrote rotn-research/rotn_research/invariants.py (%d lines)"
      % len(out.splitlines()))
