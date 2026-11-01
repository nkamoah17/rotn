# -*- coding: utf-8 -*-
"""Inspect the Phase 2 tests: imports + research target/invariant usage."""
import io
import re

for p in ["rot/tests/test_phase2_w2.py", "rot/tests/test_phase2_w3.py",
          "rot/tests/test_phase2_w4.py", "rot/tests/test_phase2_w7.py"]:
    t = io.open(p, encoding="utf-8", errors="replace").read()
    lines = t.splitlines()
    print("== %s (%d lines)" % (p, len(lines)))
    for l in lines:
        s = l.strip()
        if s.startswith(("import ", "from ")):
            print("    ", l)
    # research target/invariant names used
    names = set(re.findall(r"""build\(\s*['"]([a-z][a-z0-9-]+)['"]""", t))
    names |= set(re.findall(r"""get\(\s*['"]([a-z][a-z0-9_]+)['"]""", t))
    print("     uses-names:", sorted(names))
    print()
