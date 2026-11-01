# -*- coding: utf-8 -*-
"""Find 2PC invariant / research target references in product modules + phase0."""
import io
import os
import re

RX = re.compile(r"\bagreement\b|\bvalidity\b|no_spurious_abort|"
               r"['\"](correct|buggy)['\"]")

print("=== rot/*.py (product modules) ===")
for f in sorted(os.listdir("rot")):
    if not f.endswith(".py"):
        continue
    p = "rot/" + f
    text = io.open(p, encoding="utf-8", errors="replace").read()
    hits = sorted(set(RX.findall(text)))
    if hits:
        # show the matching lines for context
        print("--- %s  %s" % (p, hits))
        for ln, line in enumerate(text.splitlines(), 1):
            if RX.search(line):
                print("    L%-4d %s" % (ln, line.strip()[:105]))

t = io.open("tests/test_phase0_ir_contract.py", encoding="utf-8").read()
print()
print("=== test_phase0_ir_contract.py refs ===")
print(sorted(set(RX.findall(t))))
