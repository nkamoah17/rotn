# -*- coding: utf-8 -*-
"""Move the 7 research tests (that import rot.<research>) into the research
repo, rewriting their imports from rot.<research> to rotn_research.<research>.
The product (rot.*) registry imports stay unchanged."""
import io
import os
import re
import shutil

RESEARCH = ['twopc', 'zab', 'pbft', 'payment', 'order_service', 'env',
            'composition', 'zk_bugs', 'ladder', 'approval', 'ab',
            'empirical', 'llm_baseline', 'cpg_reader', 'classify']

TESTS = [
    "tests/test_ab_frontends.py",
    "tests/test_approval.py",
    "tests/test_ladder.py",
    "tests/test_pbft_target.py",
    "tests/test_twopc.py",
    "tests/test_zab_target.py",
    "rot/tests/test_phase2_w4_empirical.py",
]

DEST_DIR = "rotn-research/tests"
os.makedirs(DEST_DIR, exist_ok=True)


def rewrite(text):
    """Replace rot.<research> with rotn_research.<research>, but only for the
    research module names (never rot.invariants, rot.targets, etc.)."""
    # Word-boundary replace of 'rot.NAME' -> 'rotn_research.NAME'
    for name in RESEARCH:
        # Avoid double-replacing rotn_research.NAME
        text = re.sub(r"\brot\.(" + name + r")\b",
                      "rotn_research." + name, text)
    # 'from rot import NAME' -> 'from rotn_research import NAME'
    for name in RESEARCH:
        text = re.sub(r"\bfrom\s+rot\s+import\s+(" + name + r")\b",
                      "from rotn_research import " + name, text)
    return text


for src in TESTS:
    if not os.path.exists(src):
        print("SKIP (missing):", src)
        continue
    with io.open(src, "r", encoding="utf-8", newline="") as f:
        content = f.read()
    new = rewrite(content)
    base = os.path.basename(src)
    dest = os.path.join(DEST_DIR, base)
    with io.open(dest, "w", encoding="utf-8", newline="") as f:
        f.write(new)
    # syntax check
    import py_compile
    try:
        py_compile.compile(dest, doraise=True)
        ok = "syntax OK"
    except py_compile.PyCompileError as e:
        ok = "SYNTAX ERROR: %s" % e
    print("moved %s -> %s  (%s)" % (src, dest, ok))

print("\nDone.")
