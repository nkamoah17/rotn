# -*- coding: utf-8 -*-
"""Verify the research package imports + registers into the product registries."""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "rotn-research"))
sys.path.insert(0, ROOT)

import rot.invariants as P_inv          # product
import rot.targets as P_tgts            # product

print("BEFORE research import:")
print("  invariants:", P_inv.names())
print("  targets:   ", P_tgts.names())

import rotn_research                    # research (triggers registration)
import rotn_research.invariants as R_inv
import rotn_research.targets as R_tgts

print("\nAFTER research import:")
print("  invariants:", P_inv.names())
print("  targets:   ", P_tgts.names())

# Verify a research invariant resolves
inv = P_inv.get("zab_no_premature_apply", 3)
print("\nzab_no_premature_apply ->", inv.name, "| label:", inv.label)

# Verify a research target resolves and builds
spec = P_tgts.get("zab-buggy")
ir = P_tgts.build("zab-buggy", 3)
print("zab-buggy build ->", type(ir).__name__,
      "| states:", len(ir.states) if hasattr(ir, "states") else "?")

# Verify a payment target
ir2 = P_tgts.build("payment-buggy", 1)
print("payment-buggy build ->", type(ir2).__name__)

# Verify 2PC target
ir3 = P_tgts.build("buggy", 3)
print("buggy(2PC) build ->", type(ir3).__name__)

print("\nOK -- research package registers + builds")
