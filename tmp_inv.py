# -*- coding: utf-8 -*-
"""Locate definitions + registry references of the research invariants."""
import io
import os
import re

NAMES = [
    "zab_no_premature_apply", "zab_apply_persisted", "pbft_quorum",
    "pbft_prepare_before_commit", "no_double_charge", "charge_requires_order",
    "settle_requires_charge", "no_unapproved_irreversible",
    "no_privilege_escalation", "no_deadlock", "task_ends_or_escalates",
    "no_runaway_budget",
]

files = []
for base in ("rot", "tests", "rot/frontends"):
    if not os.path.isdir(base):
        continue
    for f in os.listdir(base):
        if f.endswith(".py"):
            files.append(os.path.join(base, f))
files.append("pipeline.py")

for n in NAMES:
    defs, uses = [], []
    for p in files:
        if not os.path.exists(p):
            continue
        text = io.open(p, encoding="utf-8", errors="replace").read()
        if re.search(r"\bdef %s\b" % n, text):
            defs.append(p)
        elif re.search(r"['\"]%s['\"]" % n, text):
            uses.append(p)
    print("%-26s defs=%s uses=%s" % (n, defs or "-", uses or "-"))
