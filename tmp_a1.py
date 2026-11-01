# -*- coding: utf-8 -*-
"""Comprehensive A1 boundary check: does any STAYING product code reference
any research module (all import forms)?"""
import io
import os
import re

RESEARCH = {
    "twopc", "zab", "pbft", "payment", "order_service", "env",
    "composition", "zk_bugs", "ladder", "approval", "ab", "empirical",
    "llm_baseline", "cpg_reader", "classify",
}

# patterns that reference a research module as an import target
RX_IMPORT = re.compile(r"^\s*import\s+rot\.([a-z_0-9]+)\b")
RX_FROMMOD = re.compile(r"^\s*from\s+rot\.([a-z_0-9]+)\s+import\b")
RX_FROMPKG = re.compile(r"^\s*from\s+rot\s+import\s+(.+)$")

def staying_product_files():
    files = []
    for base in ("rot", "rot/frontends", "rot/frontends/code",
                 "rot/frontends/cpg", "rot/frontends/java",
                 "rot/frontends/policy"):
        if not os.path.isdir(base):
            continue
        for f in os.listdir(base):
            if f.endswith(".py") and f != "__init__.py":
                files.append(os.path.join(base, f))
    files.append("rot/__init__.py")
    files.append("rot/__main__.py")
    return files

print("=== STAYING product code referencing RESEARCH modules ===")
any_hit = False
for p in staying_product_files():
    if not os.path.exists(p):
        continue
    # skip the research modules themselves (they are moving)
    modname = os.path.splitext(os.path.basename(p))[0]
    if modname in RESEARCH:
        continue
    lines = io.open(p, encoding="utf-8", errors="replace").read().splitlines()
    for i, line in enumerate(lines, 1):
        m = RX_IMPORT.match(line)
        if m and m.group(1) in RESEARCH:
            print("%s L%-4d import rot.%s   [%s]" % (p, i, m.group(1), line.strip()[:70]))
            any_hit = True
            continue
        m = RX_FROMMOD.match(line)
        if m and m.group(1) in RESEARCH:
            print("%s L%-4d from rot.%s import ...   [%s]" % (p, i, m.group(1), line.strip()[:70]))
            any_hit = True
            continue
        m = RX_FROMPKG.match(line)
        if m:
            names = [x.strip().split(" as ")[0] for x in m.group(1).split(",")]
            hits = [n for n in names if n in RESEARCH]
            if hits:
                print("%s L%-4d from rot import %s   [%s]" % (p, i, hits, line.strip()[:70]))
                any_hit = True

if not any_hit:
    print("  (none -- boundary is clean for the staying product code)")
