# -*- coding: utf-8 -*-
"""Show exact lines matching research-module words in specific test files."""
import io
import re

FILES = ["test_apalache.py", "test_compliance.py", "test_classify.py",
         "test_cpg_extraction.py", "test_cpg_model.py", "test_design_view.py",
         "test_fsm_extraction.py", "test_license.py", "test_manifest.py",
         "test_narrow_waist.py", "test_phase0_ir_contract.py",
         "test_phase5_lossiness.py", "test_runtime_plane.py",
         "test_source_pipeline.py", "test_invariant_discipline.py"]

for f in FILES:
    rx = re.compile(r"\b(twopc|zab|pbft|payment|order_service|env|composition|"
                    r"zk_bugs|ladder|approval|\bab\b|empirical|llm_baseline|"
                    r"cpg_reader|classify)\b")
    print("=== %s" % f)
    for ln, line in enumerate(io.open("tests/" + f, encoding="utf-8",
                                      errors="replace").read().splitlines(), 1):
        m = rx.search(line)
        if m:
            print("   L%-4d %s" % (ln, line.strip()[:110]))
