#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""End-to-end tests for the Java *source* pipeline (``--source`` mode).

These drive the exact same public entry points a user would:
``pipeline.run(source_dir=...)`` and ``pipeline.main([...])`` -- with the
Java front-end (``rot.frontends.java``) building the IR from real ``.java``
sources (``examples/twopc`` for the correct protocol, and a minimal buggy
participant that re-derives its applied value from its own vote), then the
lineariser + sound symbolic engine deciding agreement / validity.

They also pin down the CPG-degradation contract:
  * ``--cpg <path>`` (explicit) on a missing/invalid artifact -> hard error;
  * an auto-detected invalid ``*.cpg.json`` under the source dir -> warn and
    continue with the source-only front-end.

Run:
    python tests/test_source_pipeline.py
"""
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pipeline
import rot.frontends.java as java_fe
from rot import twopc  # canonical IR ground truth the source IR must match
from rot.frontends.cpg_reader import CpgReadError
from rot.symbolic import PROVEN, VIOLATED

EXAMPLES = os.path.join(_ROOT, "examples", "twopc")
N = 2  # linearisation bound the fixtures were validated at


# --- fixtures -----------------------------------------------------------------
BUGGY_PARTICIPANT = """\
// Minimal 2PC participant with the seeded bug: apply() re-derives the
// applied value from the participant's OWN vote instead of applying the
// shared coordinator decision (``applied = decision`` would be correct).
public class Participant {
    enum Phase { PREPARE, DECIDED }
    enum Vote { NONE, YES, NO }
    enum Decision { NONE, COMMIT, ABORT }

    String vote = Vote.NONE.name();
    String applied = Decision.NONE.name();

    void prepare() {
        vote = Vote.YES.name();
    }

    // BUG: self-decides from its own vote; the coordinator's decision ignored.
    void apply() {
        String self = vote.equals(Vote.YES.name()) ? Decision.COMMIT.name()
                                                   : Decision.ABORT.name();
        applied = self;
    }
}
"""


def _buggy_fixture(base):
    d = os.path.join(base, "buggy-src")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "Participant.java"), "w", encoding="utf-8") as fh:
        fh.write(BUGGY_PARTICIPANT)
    return d


def _cpg_fixture(base):
    """A source dir containing one (correct) participant + an INVALID cpg."""
    d = os.path.join(base, "src-with-cpg")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "Participant.java"), "w", encoding="utf-8") as fh:
        fh.write("public class Participant {\n"
                 "    void apply(Decision d) { applied = d; }\n"
                 "}\n")
    path = os.path.join(d, "x.cpg.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{ this is not valid json")
    return d, path


# --- source front-end: detection + IR fidelity ---------------------------------
def test_examples_sources_present():
    for f in ("Coordinator.java", "Participant.java"):
        assert os.path.isfile(os.path.join(EXAMPLES, f)), f


def test_apply_mode_autodetection():
    assert java_fe.detect_apply_mode(EXAMPLES) == "correct"
    with tempfile.TemporaryDirectory() as tmp:
        fix = _buggy_fixture(tmp)
        assert java_fe.detect_apply_mode(fix) == "buggy"
        # auto-detection == explicit flag on the buggy fixture
        auto = java_fe.build_ir(fix, n=N, buggy=None).to_dict()
        explicit = java_fe.build_ir(fix, n=N, buggy=True).to_dict()
        assert auto["actions"] == explicit["actions"]
        # ...and the correct vs buggy action sets actually differ
        correct = java_fe.build_ir(EXAMPLES, n=N, buggy=False).to_dict()
        assert correct["actions"] != explicit["actions"]


def test_source_ir_matches_canonical_ground_truth():
    for buggy in (False, True):
        src = java_fe.build_ir(EXAMPLES, n=N, buggy=buggy).to_dict()
        gt = twopc.build_ir(n=N, buggy=buggy).to_dict()
        assert src["variables"] == gt["variables"]
        assert src["actions"] == gt["actions"]
        assert src["pinned_property"] == gt["pinned_property"]


# --- pipeline.run(source_dir=...) ----------------------------------------------
def test_source_pipeline_proven_agreement():
    with tempfile.TemporaryDirectory() as tmp:
        v = pipeline.run(target_name="correct", source_dir=EXAMPLES, n=N,
                         engine="symbolic", quiet=True, out_dir=tmp)
        assert v.status == PROVEN
        reps = [f for f in os.listdir(tmp) if f.endswith("_agreement.json")]
        assert reps, "no agreement report written to %s" % tmp


def test_source_pipeline_buggy_violates_agreement():
    with tempfile.TemporaryDirectory() as tmp:
        fix = _buggy_fixture(tmp)
        v = pipeline.run(target_name="buggy", source_dir=fix, n=N,
                         engine="symbolic", quiet=True, out_dir=tmp)
        assert v.status == VIOLATED
        assert v.counterexample, "buggy verdict must carry a counterexample"
        # non-vacuity: validity (apply only on a decided value) still holds
        v2 = pipeline.run(target_name="buggy", source_dir=fix, n=N,
                          property_name="validity", engine="symbolic",
                          quiet=True, out_dir=tmp)
        assert v2.status == PROVEN


# --- CPG degradation contract ---------------------------------------------------
def test_cpg_explicit_missing_is_hard_error():
    try:
        pipeline._load_cpg_model(os.path.join(_ROOT, "no_such.cpg.json"), None)
    except CpgReadError:
        return
    raise AssertionError("missing explicit --cpg artifact must raise CpgReadError")


def test_cpg_explicit_malformed_is_hard_error():
    with tempfile.TemporaryDirectory() as tmp:
        _d, path = _cpg_fixture(tmp)
        try:
            pipeline._load_cpg_model(path, None)
        except CpgReadError:
            return
        raise AssertionError("malformed explicit --cpg artifact must raise")


def test_cpg_auto_malformed_degrades_to_source_only():
    with tempfile.TemporaryDirectory() as tmp:
        d, _path = _cpg_fixture(tmp)
        assert pipeline._load_cpg_model(None, d, quiet=True) is None


# --- CLI: pipeline.main([...]) ---------------------------------------------------
def test_cli_source_correct_exits_proven():
    with tempfile.TemporaryDirectory() as tmp:
        rc = pipeline.main(["--source", EXAMPLES, "--engine", "symbolic",
                            "--n", str(N), "--quiet", "--out", tmp])
        assert rc == 0, "exit code %r (want 0/PROVEN)" % rc


def test_cli_source_buggy_exits_violated():
    with tempfile.TemporaryDirectory() as tmp:
        fix = _buggy_fixture(tmp)
        rc = pipeline.main(["--source", fix, "--engine", "symbolic",
                            "--n", str(N), "--quiet", "--out", tmp])
        assert rc == 1, "exit code %r (want 1/VIOLATED)" % rc


def test_cli_source_and_target_are_mutually_exclusive():
    try:
        pipeline.main(["correct", "--source", EXAMPLES, "--quiet"])
    except SystemExit as ex:
        assert ex.code == 2, "argparse error code %r (want 2)" % ex.code
        return
    raise AssertionError("positional target + --source must be rejected")


def test_cli_missing_source_dir_is_error():
    with tempfile.TemporaryDirectory() as tmp:
        rc = pipeline.main(["--source", os.path.join(_ROOT, "no_such_src"),
                            "--quiet", "--out", tmp])
        assert rc == 3, "exit code %r (want 3/ERROR)" % rc


# --- runner ---------------------------------------------------------------------
def main():
    tests = [
        test_examples_sources_present,
        test_apply_mode_autodetection,
        test_source_ir_matches_canonical_ground_truth,
        test_source_pipeline_proven_agreement,
        test_source_pipeline_buggy_violates_agreement,
        test_cpg_explicit_missing_is_hard_error,
        test_cpg_explicit_malformed_is_hard_error,
        test_cpg_auto_malformed_degrades_to_source_only,
        test_cli_source_correct_exits_proven,
        test_cli_source_buggy_exits_violated,
        test_cli_source_and_target_are_mutually_exclusive,
        test_cli_missing_source_dir_is_error,
    ]
    width = max(len(t.__name__) for t in tests)
    passed = failed = skipped = 0
    for t in tests:
        name = t.__name__
        try:
            t()
        except unittest.SkipTest as ex:
            skipped += 1
            print("[%s] %s -> SKIPPED (%s)" % ("SKIP", name.ljust(width), ex))
        except AssertionError as ex:
            failed += 1
            print("[%s] %s -> FAIL: %s" % ("FAIL", name.ljust(width), ex))
        except Exception as ex:
            failed += 1
            print("[%s] %s -> ERROR: %r" % ("ERR", name.ljust(width), ex))
        else:
            passed += 1
            print("[%s] %s" % ("PASS", name.ljust(width)))
    print("-" * (width + 14))
    print("passed=%d failed=%d skipped=%d" % (passed, failed, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
