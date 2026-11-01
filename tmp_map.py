# -*- coding: utf-8 -*-
"""Map imports across the 15 research modules + find tests referencing them."""
import io
import os
import re

RESEARCH = ["twopc", "zab", "pbft", "payment", "order_service", "env",
            "composition", "zk_bugs", "ladder", "approval", "ab",
            "empirical", "llm_baseline", "cpg_reader", "classify"]

RX = re.compile(r"(?:^|\s)(from|import)\s+(rot\.[a-z_0-9]+|rotn_research\.[a-z_0-9]+)")

print("=== research module import map ===")
for m in RESEARCH:
    p = "rot/%s.py" % m
    if not os.path.exists(p):
        print("MISSING: %s" % p)
        continue
    text = io.open(p, encoding="utf-8", errors="replace").read()
    deps = sorted(set(RX.findall(text) and [a for a, _ in RX.findall(text)]))
    # findall with groups returns the group; redo properly:
    deps = sorted(set(mm[1] for mm in RX.findall(text)))
    prod = [d for d in deps if d[4:] not in RESEARCH and d != "rot"]
    res = [d for d in deps if d[4:] in RESEARCH]
    print("%-14s prod=%-60s research=%s" % (m, ",".join(x[4:] for x in prod), ",".join(x[4:] for x in res)))

print()
print("=== test files referencing research modules (incl. strings) ===")
for f in sorted(os.listdir("tests")):
    if not (f.startswith("test") and f.endswith(".py")):
        continue
    text = io.open("tests/" + f, encoding="utf-8", errors="replace").read()
    hits = [m for m in RESEARCH if re.search(r"\b%s\b" % re.escape(m), text)]
    if hits:
        print("%-32s %s" % (f, ",".join(hits)))
