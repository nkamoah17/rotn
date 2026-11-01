# -*- coding: utf-8 -*-
"""Find product code (rot/*.py, excluding research modules) that imports
research modules."""
import io
import os
import re

RESEARCH = ['twopc', 'zab', 'pbft', 'payment', 'order_service', 'env',
            'composition', 'zk_bugs', 'ladder', 'approval', 'ab',
            'empirical', 'llm_baseline', 'cpg_reader', 'classify']
alts = "|".join(RESEARCH)
pats = [
    re.compile(r"\bimport\s+rot\.(" + alts + r")\b"),
    re.compile(r"\bfrom\s+rot\.(" + alts + r")\b"),
    re.compile(r"\bfrom\s+rot\s+import\s+[^#\n]*\b(" + alts + r")\b"),
    re.compile(r"\bfrom\s+\.\s+import\s+[^#\n]*\b(" + alts + r")\b"),
    re.compile(r"\bfrom\s+\.(" + alts + r")\s+import\b"),
]


def hit(line):
    return any(p.search(line) for p in pats)


for root, dirs, files in os.walk("rot"):
    if "__pycache__" in root:
        continue
    for f in sorted(files):
        if not f.endswith(".py"):
            continue
        base = f[:-3]
        if base in RESEARCH:
            continue
        p = os.path.join(root, f)
        t = io.open(p, encoding="utf-8", errors="replace").read()
        hits = [l.strip() for l in t.splitlines() if hit(l)]
        if hits:
            print("== %s" % p)
            for h in hits:
                print("    %s" % h[:90])
