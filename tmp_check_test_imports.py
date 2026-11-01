# -*- coding: utf-8 -*-
"""Check which tests import research modules (rot.<research>)."""
import io
import os
import re

RESEARCH = ['twopc', 'zab', 'pbft', 'payment', 'order_service', 'env',
            'composition', 'zk_bugs', 'ladder', 'approval', 'ab',
            'empirical', 'llm_baseline', 'cpg_reader', 'classify',
            'cpg_bridge']
alts = "|".join(RESEARCH)
pat = re.compile(r"\brot\.(" + alts + r")\b")

tests = [
    "tests/test_ab_frontends.py", "tests/test_approval.py",
    "tests/test_ladder.py", "tests/test_pbft_target.py",
    "tests/test_twopc.py", "tests/test_zab_target.py",
    "tests/test_cpg_extraction.py", "tests/test_cpg_model.py",
    "tests/test_cpg4.py", "tests/test_cpg_crosscheck.py",
    "rot/tests/test_phase2_w2.py", "rot/tests/test_phase2_w3.py",
    "rot/tests/test_phase2_w4.py", "rot/tests/test_phase2_w4_empirical.py",
    "rot/tests/test_phase2_w7.py",
]
for p in tests:
    if not os.path.exists(p):
        continue
    t = io.open(p, encoding="utf-8", errors="replace").read()
    mods = sorted(set(pat.findall(t)))
    print("%-42s research-imports: %s" % (p, mods or "NONE"))
