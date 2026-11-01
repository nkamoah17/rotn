# -*- coding: utf-8 -*-
"""Helper: show 2PC-specific usage lines in product test files (Phase A triage)."""
import io
import re

RX = re.compile(
    r"build\(\"(correct|buggy|twopc|zab|pbft|payment|approval|delegation|"
    r"orchestration|budget|livelock|deadlock)|"
    r"vote_|apply_|decide|prepare|commit|quorum|double_charge|"
    r"no_deadlock|unapproved|escalat|targets\.|invariants\.(get|no_|zab|pbft)")

for m in ["test_apalache.py", "test_falseblock.py", "test_targeted_test.py",
          "test_itf.py", "test_design_view.py", "test_gateimpact.py",
          "test_refine.py", "test_pipeline.py"]:
    lines = io.open("tests/" + m, encoding="utf-8").readlines()
    hits = [l.strip() for l in lines if RX.search(l)]
    print("=== %s (%d lines, %d hits)" % (m, len(lines), len(hits)))
    for h in hits[:12]:
        print("   ", h[:110])
