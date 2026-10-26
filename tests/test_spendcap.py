# -*- coding: utf-8 -*-
"""End-to-end checks on the spendcap (AWS Dogwood) vertical-slice target: IR
sanity, the guard seed difference, and within-cap hold/violate via the
bounded-exhaustive symbolic engine.

The two variants share the same state, actions, and pinned property; they
differ only in the decision rule -- ``spend_ok`` admits on it, ``spend_deny``
is its negation:

  * correct -- charges in-flight requests against the cap
    (``completed + inflight * AMOUNT + AMOUNT <= CAP``);
  * buggy   -- charges settled responses only
    (``completed + AMOUNT <= CAP``), so a burst of parallel fires
    (``spend_ok`` back-to-back, before any ``respond``) grows the in-flight
    amount past the cap -- the parallel fire race.

Run: python tests/test_spendcap.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.spendcap import (AMOUNT, CAP, MAX_INFLIGHT, build_ir,
                          spend_ok_guard_buggy, spend_ok_guard_correct,
                          within_cap_property)
from rot.linearization import linearize
from rot.symbolic import SymbolicEngine, PROVEN, VIOLATED
from rot.ir import Expr

try:
    import z3  # noqa: F401
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False


def _check(prop, ir):
    """Decide ``prop`` over every reachable state of ``ir``.

    Returns the ``EngineResult``. The slice is small (completed is a
    multiple of AMOUNT up to CAP; inflight <= MAX_INFLIGHT), so a complete
    search must be returned -- an UNKNOWN verdict is a test failure, not an
    answer.
    """
    model = linearize(ir)
    res = SymbolicEngine(model, max_states=100000).check(prop)
    if res.is_unknown():
        raise AssertionError(
            "engine returned UNKNOWN; state space too large for slice: %s"
            % res.note)
    return res


def _spend_ok_action(ir):
    for a in ir.actions:
        if a.name == "spend_ok":
            return a
    raise AssertionError("no spend_ok action in %s" % ir.name)


def _burst_admissions(ir, state):
    """How many consecutive ``spend_ok`` fires are admitted from ``state``.

    Mirrors the parallel-fire scenario: the client fires requests one after
    another before any response settles.
    """
    action = _spend_ok_action(ir)
    admitted = 0
    s = dict(state)
    while True:
        g = action.guard.eval(s)
        if g is Expr.UNDEF or not g:
            break
        s["inflight"] += 1
        admitted += 1
    return admitted


class SpendcapTests(unittest.TestCase):
    def test_ir_is_well_formed(self):
        for buggy in (False, True):
            ir = build_ir(buggy=buggy)
            # ProtocolIR.validate() returns the list of well-formedness
            # errors; an empty list (falsy) means the IR is well-formed.
            self.assertFalse(ir.validate(), msg=str(ir.validate()))
            self.assertTrue(any(a.is_initial for a in ir.actions))
            self.assertEqual(sorted(a.name for a in ir.actions),
                             ["init", "respond", "spend_deny", "spend_ok"])
            self.assertEqual(len(ir.variables), 2)
            self.assertEqual(sorted(v.name for v in ir.variables),
                             ["completed", "inflight"])
            # spend_deny is a no-op outcome action (no effects).
            deny = [a for a in ir.actions if a.name == "spend_deny"][0]
            self.assertEqual(deny.effects, [])

    def test_spend_deny_is_the_negated_decision(self):
        # spend_deny is enabled exactly where the seeded decision rejects the
        # request -- in both variants the decision branches partition the
        # request: admit (spend_ok) vs deny (spend_deny).
        for buggy in (False, True):
            ir = build_ir(buggy=buggy)
            ok = [a for a in ir.actions if a.name == "spend_ok"][0]
            deny = [a for a in ir.actions if a.name == "spend_deny"][0]
            # At the initial state the rule admits (completed=0), so deny is
            # disabled in both variants.
            s0 = {"completed": 0, "inflight": 0}
            self.assertEqual(ok.guard.eval(s0), True)
            self.assertEqual(deny.guard.eval(s0), False)
            # With two in-flight requests the rule diverges: the buggy rule
            # still admits (deny disabled), the correct rule rejects (deny
            # enabled) -- the deny branch is the negation of the decision.
            s = {"completed": 0, "inflight": 2}
            if buggy:
                self.assertEqual(deny.guard.eval(s), False,
                                 "buggy deny should be disabled at %s" % s)
            else:
                self.assertEqual(deny.guard.eval(s), True,
                                 "correct deny should be enabled at %s" % s)
                self.assertEqual(ok.guard.eval(s), False,
                                 "spend_ok/deny must partition at %s" % s)

    def test_correct_holds_within_cap_in_all_reachable_states(self):
        ir = build_ir(buggy=False)
        prop = within_cap_property()
        res = _check(prop, ir)
        self.assertEqual(res.status, PROVEN,
                         "correct spendcap should satisfy within_cap, "
                         "but got %s (witness=%s)" % (res.status, res.witness))
        self.assertTrue(res.complete)

    def test_buggy_violates_within_cap(self):
        ir = build_ir(buggy=True)
        prop = within_cap_property()
        res = _check(prop, ir)
        self.assertEqual(res.status, VIOLATED,
                         "buggy spendcap should violate within_cap, "
                         "but it held in all reachable states")
        w = res.witness
        self.assertTrue(w["completed"] + w["inflight"] * AMOUNT > CAP,
                        "witness %s does not exceed the cap" % w)
        # The violation is the *parallel fire race*: multiple approved-but-
        # unsettled requests outstanding at once.
        self.assertGreaterEqual(w["inflight"], 2,
                                "witness %s is not a parallel-fire "
                                "violation" % w)

    def test_burst_of_fires_admitted_buggy_denied_correct(self):
        # From the initial state, a parallel burst of spend_ok:
        #   * buggy admits the whole burst (only the structural pool bound
        #     stops it) -- so 3+ in-flight requests coexist, and 3 alone
        #     already exceed the cap (3 * AMOUNT > CAP);
        #   * correct admits only the first CAP // AMOUNT fires, then denies
        #     the rest (the 3rd fire is the first denied one).
        init_state = {"completed": 0, "inflight": 0}
        buggy = _burst_admissions(build_ir(buggy=True), init_state)
        correct = _burst_admissions(build_ir(buggy=False), init_state)
        self.assertEqual(correct, CAP // AMOUNT)
        self.assertEqual(buggy, MAX_INFLIGHT)  # structural bound only
        self.assertGreater(buggy, correct)
        self.assertGreater(CAP // AMOUNT, 1)  # the race is real: 2 fit, 3 does not

    def test_guard_difference_is_seeded_only_in_inflight(self):
        buggy_guard = spend_ok_guard_buggy()
        correct_guard = spend_ok_guard_correct()
        # With nothing in flight the two rules agree...
        for completed in (0, AMOUNT):
            s = {"completed": completed, "inflight": 0}
            self.assertEqual(buggy_guard.eval(s), correct_guard.eval(s),
                             "guards should agree at %s" % s)
        # ...and with in-flight requests outstanding they can diverge: the
        # buggy rule admits a fire that the correct rule denies.
        s = {"completed": 0, "inflight": 2}
        self.assertEqual(buggy_guard.eval(s), True,
                         "buggy guard should admit at %s" % s)
        self.assertEqual(correct_guard.eval(s), False,
                         "correct guard should deny at %s" % s)
        # Boundary: settled + in-flight exactly at the cap is still within it.
        s = {"completed": 0, "inflight": 1}
        self.assertEqual(correct_guard.eval(s), True,
                         "correct guard should admit at %s (boundary)" % s)

    def test_invariant_and_target_registered(self):
        import rot.invariants as invariants
        import rot.targets as targets
        inv = invariants.get("spendcap_within_cap")
        self.assertTrue(inv.pinned)
        self.assertEqual(inv.name, "spendcap_within_cap")
        # The registered invariant and the module's property-builder agree.
        self.assertEqual(inv.expression.to_dict(),
                         within_cap_property().to_dict())
        for name in ("spendcap-correct", "spendcap-buggy"):
            self.assertIn(name, targets.names())
            spec = targets.get(name)
            self.assertEqual(spec.default_property, "spendcap_within_cap")
            self.assertIn("spendcap_within_cap", targets.list_properties(name))
        # The buggy/correct distinction is seeded into the built IR's metadata.
        self.assertFalse(targets.get("spendcap-correct").build(1).metadata["buggy"])
        self.assertTrue(targets.get("spendcap-buggy").build(1).metadata["buggy"])

    def test_property_serializes(self):
        prop = within_cap_property()
        d = prop.to_dict()
        # Canonical IR serialization: the property is a binary "<=" node.
        self.assertEqual(d["tag"], "bin")
        self.assertEqual(d["op"], "<=")


    def test_fixture_fidelity_locks_one_word_diff(self):
        # The two .dw spec artifacts (in the fetched-fixture tree) lock the
        # one-word diff: buggy sums over Transfer::response (completed only),
        # correct sums over Transfer::request (issued incl. in-flight).
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "fixtures", "aws_dogwood", "spendcap", "policies")
        buggy_path = os.path.join(base, "spendcap-buggy.dw")
        correct_path = os.path.join(base, "spendcap-correct.dw")
        self.assertTrue(os.path.exists(buggy_path), "missing %s" % buggy_path)
        self.assertTrue(os.path.exists(correct_path), "missing %s" % correct_path)
        with open(buggy_path, encoding="utf-8") as f:
            buggy_src = f.read()
        with open(correct_path, encoding="utf-8") as f:
            correct_src = f.read()
        # Buggy references Transfer::response, NOT Transfer::request.
        self.assertIn('Transfer"::response', buggy_src)
        self.assertNotIn('Transfer"::request', buggy_src)
        # Correct references Transfer::request, NOT Transfer::response.
        self.assertIn('Transfer"::request', correct_src)
        self.assertNotIn('Transfer"::response', correct_src)


class E2eCliTests(unittest.TestCase):
    """E2E CLI contract: ``python pipeline.py <target>`` exit code + report.

    Locks the pipeline's exit-code contract (0 = proven, 1 = violated) and
    that the JSON/MD report carries the counterexample for the buggy variant
    and a clean verdict for the correct one.  Mirrors the "engine-level,
    matches pipeline path" requirement of Step 4 -- this is the exact command
    a user (or CI gate) would run.
    """

    @staticmethod
    def _pipeline_cmd(target, out_dir):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return [sys.executable, os.path.join(repo_root, "pipeline.py"),
                target, "--engine", "symbolic", "--out", out_dir, "--quiet"]

    def test_buggy_exits_1_with_counterexample_in_reports(self):
        """python pipeline.py spendcap-buggy -> exit 1; JSON+MD carry the
        counterexample (completed=0, inflight>=3 -- the parallel-fire race)."""
        out_dir = tempfile.mkdtemp(prefix="rotn_spendcap_buggy_")
        try:
            proc = subprocess.run(self._pipeline_cmd("spendcap-buggy", out_dir),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=180)
            self.assertEqual(proc.returncode, 1,
                             "buggy target must exit 1 (violated); "
                             "stderr=%s" % proc.stderr.decode("utf-8", "replace"))
            # JSON report: verdict violated + counterexample present.
            jpath = os.path.join(out_dir, "spendcap-buggy_spendcap_within_cap.json")
            self.assertTrue(os.path.exists(jpath), "missing JSON report %s" % jpath)
            with open(jpath, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["target"], "spendcap-buggy")
            self.assertEqual(data["verdict"]["status"], "violated")
            ce = data["verdict"]["counterexample"]
            self.assertIsNotNone(ce, "JSON report must carry a counterexample")
            self.assertEqual(ce.get("completed"), 0,
                             "witness has zero settled (no respond fired)")
            self.assertGreaterEqual(ce.get("inflight"), 3,
                                    "witness has >=3 in-flight parallel fires")
            # MD report: human-readable counterexample section.
            mpath = os.path.join(out_dir, "spendcap-buggy_spendcap_within_cap.md")
            self.assertTrue(os.path.exists(mpath), "missing MD report %s" % mpath)
            with open(mpath, encoding="utf-8") as f:
                md = f.read()
            self.assertIn("VIOLATED", md)
            self.assertIn("Counterexample", md)
            self.assertIn("inflight = 3", md)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

    def test_correct_exits_0_proven(self):
        """python pipeline.py spendcap-correct -> exit 0 (proven, complete)."""
        out_dir = tempfile.mkdtemp(prefix="rotn_spendcap_correct_")
        try:
            proc = subprocess.run(self._pipeline_cmd("spendcap-correct", out_dir),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=180)
            self.assertEqual(proc.returncode, 0,
                             "correct target must exit 0 (proven); "
                             "stderr=%s" % proc.stderr.decode("utf-8", "replace"))
            # JSON report: verdict proven, no counterexample.
            jpath = os.path.join(out_dir, "spendcap-correct_spendcap_within_cap.json")
            self.assertTrue(os.path.exists(jpath), "missing JSON report %s" % jpath)
            with open(jpath, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["target"], "spendcap-correct")
            self.assertEqual(data["verdict"]["status"], "proven")
            self.assertIsNone(data["verdict"]["counterexample"],
                              "proven verdict must carry no counterexample")
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class PolicyCrosscheckCliTests(unittest.TestCase):
    """D3 CLI contract: ``--policy <file> --engine crosscheck`` must route
    through the three-engine (SMT/Z3 + TLC + policy-direct) CrossChecker
    (not the concrete ModelFinder) and emit a report carrying ALL THREE
    engines' evidence (the D3 schema).

    Before the fix, the --policy path ignored --engine and hardcoded
    ModelFinder, so cross-check evidence was silently absent.  These tests
    lock the fix on the exact command a user would run against a .dw policy.
    """

    # The fetched AWS Dogwood spend-cap fixtures (the one-word correct/buggy
    # diff that exercises the parallel-fire race).
    _POLICIES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "fixtures", "aws_dogwood", "spendcap", "policies")

    @staticmethod
    def _cmd(policy, out_dir):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return [sys.executable, os.path.join(repo_root, "pipeline.py"),
                "--policy", policy, "--engine", "crosscheck",
                "--out", out_dir, "--quiet"]

    def _run_and_report(self, policy):
        """Run the crosscheck CLI on ``policy``; return (exit_code, report)."""
        out_dir = tempfile.mkdtemp(prefix="rotn_pol_crosscheck_")
        try:
            proc = subprocess.run(self._cmd(policy, out_dir),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=180)
            names = [n for n in os.listdir(out_dir) if n.endswith(".json")]
            self.assertEqual(len(names), 1,
                             "expected one JSON report in %s, got %r"
                             % (out_dir, names))
            with open(os.path.join(out_dir, names[0]), encoding="utf-8") as f:
                return proc.returncode, json.load(f)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

    def test_buggy_policy_crosscheck_exits_1_all_engines(self):
        """--policy spendcap-buggy.dw --engine crosscheck -> exit 1, and the
        report carries ALL THREE engines' evidence, agreeing on the
        violation."""
        rc, data = self._run_and_report(
            os.path.join(self._POLICIES_DIR, "spendcap-buggy.dw"))
        self.assertEqual(rc, 1,
                         "buggy spend-cap + crosscheck must be VIOLATED")
        self.assertEqual(data["engine"], "crosscheck")
        self.assertEqual(data["verdict"]["status"], "violated")
        cc = data["verdict"]["evidence"]["crosscheck"]
        # The D3 schema: per-engine SMT + TLC + policy_direct evidence and
        # the agreement join.
        self.assertIn("ALL THREE engines to agree", cc["policy"])
        self.assertEqual(cc["smt"]["status"], "violated")
        self.assertEqual(cc["tlc"]["status"], "violated")
        self.assertEqual(cc["policy_direct"]["status"], "violated")
        self.assertEqual(cc["joined"], "violated")
        self.assertIsNotNone(cc["smt"]["counterexample"],
                             "SMT evidence must carry a counterexample")
        self.assertIsNotNone(cc["tlc"]["witness"],
                             "TLC evidence must carry a witness")

    def test_correct_policy_crosscheck_exits_0(self):
        """--policy spendcap-correct.dw --engine crosscheck -> exit 0, all
        three engines agreeing the invariant holds."""
        rc, data = self._run_and_report(
            os.path.join(self._POLICIES_DIR, "spendcap-correct.dw"))
        self.assertEqual(rc, 0,
                         "correct spend-cap + crosscheck must be PROVEN")
        self.assertEqual(data["engine"], "crosscheck")
        self.assertEqual(data["verdict"]["status"], "proven")
        cc = data["verdict"]["evidence"]["crosscheck"]
        self.assertIn("ALL THREE engines to agree", cc["policy"])
        self.assertEqual(cc["smt"]["status"], "proven")
        self.assertEqual(cc["tlc"]["status"], "proven")
        self.assertEqual(cc["policy_direct"]["status"], "proven")
        self.assertEqual(cc["joined"], "proven")


class MaxInflightKTests(unittest.TestCase):
    """K (bounded concurrency pool) parameterization of the spend-cap slice.

    K is *structural*, not policy: it bounds how many in-flight requests the
    state space can express, and it is shared by the correct and buggy
    variants.  Verified K-sweep behavior (CAP=200, AMOUNT=50):

      * K=1  -- masked: the buggy policy is PROVEN (a single in-flight
                request cannot overshoot the cap);
      * K=2  -- VIOLATED, witness (completed=100, inflight=2) -- the second
                in-flight fire is admitted after one settlement;
      * K>=3 -- VIOLATED, witness (completed=0, inflight=3) -- the clean
                parallel-fire signature (no settlement at all).

    The correct policy is PROVEN for every K (the guard charges in-flight
    requests against the cap).
    """

    def test_k1_masks_the_bug(self):
        # With at most one in-flight request the parallel-fire race cannot be
        # expressed: the buggy policy is indistinguishable from the correct
        # one -- this corrects the audit's false "K=2 masked" claim.
        for buggy in (False, True):
            ir = build_ir(buggy=buggy, max_inflight=1)
            res = _check(within_cap_property(), ir)
            self.assertEqual(res.status, PROVEN,
                             "K=1 must be masked for buggy=%s (got %s, "
                             "witness=%s)" % (buggy, res.status, res.witness))

    def test_k2_violates_with_partial_settlement(self):
        ir = build_ir(buggy=True, max_inflight=2)
        res = _check(within_cap_property(), ir)
        self.assertEqual(res.status, VIOLATED,
                         "K=2 buggy must violate within_cap")
        self.assertEqual(res.witness, {"completed": 100, "inflight": 2},
                         "K=2 witness must be one settlement + 2 in-flight")
        # The correct policy still holds at K=2.
        res_ok = _check(within_cap_property(),
                        build_ir(buggy=False, max_inflight=2))
        self.assertEqual(res_ok.status, PROVEN)

    def test_k3_and_above_clean_parallel_fire_signature(self):
        for K in (3, 4, 5, 6):
            ir = build_ir(buggy=True, max_inflight=K)
            res = _check(within_cap_property(), ir)
            self.assertEqual(res.status, VIOLATED, "K=%d buggy" % K)
            self.assertEqual(res.witness, {"completed": 0, "inflight": 3},
                             "K=%d clean parallel-fire signature" % K)
            # The correct policy is PROVEN for every K.
            res_ok = _check(within_cap_property(),
                            build_ir(buggy=False, max_inflight=K))
            self.assertEqual(res_ok.status, PROVEN, "K=%d correct" % K)

    def test_metadata_and_domain_record_k(self):
        for K in (1, 2, 3):
            ir = build_ir(buggy=True, max_inflight=K)
            self.assertEqual(ir.metadata.get("max_inflight"), K)
            inflight = [v for v in ir.variables if v.name == "inflight"][0]
            self.assertEqual(inflight.domain.hi, K,
                             "inflight domain must be bounded by K=%d" % K)

    def test_default_k_is_module_constant(self):
        ir = build_ir(buggy=True)
        self.assertEqual(ir.metadata.get("max_inflight"), MAX_INFLIGHT)


class MaxInflightRouterTests(unittest.TestCase):
    """The router passes ``max_inflight`` through to the ``.dw`` spend-cap
    front-end only; Cedar has no in-flight request pool, so the flag is
    *ignored* there (the built IR must not record a ``max_inflight``)."""

    def test_cedar_ignores_max_inflight(self):
        import rot.frontends.policy as policy_fe
        cedar = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "samples", "agent.cedar")
        self.assertTrue(os.path.exists(cedar), "missing %s" % cedar)
        ir = policy_fe.build_ir(cedar, max_inflight=2)
        self.assertEqual(ir.metadata.get("max_inflight"), None,
                         "Cedar has no in-flight pool; K must be ignored")


class MaxInflightCliTests(unittest.TestCase):
    """The ``--max-inflight K`` CLI flag end-to-end on the buggy .dw policy:

      * K=1 -> exit 0 (masked: PROVEN)
      * K=2 -> exit 1 (VIOLATED, witness completed=100, inflight=2)
      * K=3 -> exit 1 (VIOLATED, witness completed=0, inflight=3)

    and the JSON report records ``max_inflight`` = K.
    """

    _POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "fixtures", "aws_dogwood", "spendcap", "policies",
                           "spendcap-buggy.dw")

    def _run(self, K):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out_dir = tempfile.mkdtemp(prefix="rotn_spendcap_k%d_" % K)
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(repo_root, "pipeline.py"),
                 "--policy", self._POLICY, "--max-inflight", str(K),
                 "--out", out_dir, "--quiet"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            jpath = os.path.join(
                out_dir, "policy-spendcap-buggy.dw_spendcap_within_cap.json")
            with open(jpath, encoding="utf-8") as f:
                return proc.returncode, json.load(f)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

    def test_k1_masked_exits_0(self):
        rc, data = self._run(1)
        self.assertEqual(rc, 0, "K=1 must be masked (PROVEN)")
        self.assertEqual(data["verdict"], "proven")
        self.assertEqual(data.get("max_inflight"), 1)

    def test_k2_exits_1_witness_100_2(self):
        rc, data = self._run(2)
        self.assertEqual(rc, 1, "K=2 must be VIOLATED")
        self.assertEqual(data["verdict"], "violated")
        self.assertEqual(data.get("max_inflight"), 2)
        self.assertEqual(data["witness"], {"completed": 100, "inflight": 2})

    def test_k3_exits_1_witness_0_3(self):
        rc, data = self._run(3)
        self.assertEqual(rc, 1, "K=3 must be VIOLATED")
        self.assertEqual(data["verdict"], "violated")
        self.assertEqual(data.get("max_inflight"), 3)
        self.assertEqual(data["witness"], {"completed": 0, "inflight": 3})


if __name__ == "__main__":
    unittest.main(verbosity=2)
