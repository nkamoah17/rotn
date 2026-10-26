#!/usr/bin/env bash
# ROTN spend-cap demo (AWS Dogwood .dw policies) -- 5 phases, exit-code aware.
#
#   Phase 1  PROVEN    --policy spendcap-correct.dw  -> exit 0 (safety holds)
#   Phase 2  VIOLATED  --policy spendcap-buggy.dw    -> exit 1 (witness emitted)
#   Phase 3  AUDIT     --trifecta --manifest         -> exit 0 (+ out/trifecta_manifest.json
#                                                      + out/trifecta_risk.json)
#   Phase 4  CROSSCHECK --engine crosscheck (SMT/Z3 + TLC + policy-direct), explicit K
#              4a: K=3 -> exit 1 (all three engines VIOLATED, SAME 3-parallel-fire witness)
#              4b: K=1 -> exit 0 (all three engines PROVEN -- the bug is masked for K<3)
#              + out/crosscheck_report.json (curated: agree + 3 CEs + witness_match + ITF)
#              [SKIP if TLC (java + tla2tools.jar) is absent -- graceful, not a failure]
#   Phase 5  K-SWEEP   --max-inflight K (symbolic)
#              K=1 -> exit 0 (masked/PROVEN), K=2 -> exit 1, K=3 -> exit 1 (clean fire)
#
# The one-word diff between the two policies (request vs response) is the
# entire seeded bug: summing over Transfer::request (issued transfers,
# in-flight included) is correct; summing over Transfer::response (settled
# only) lets a parallel-fire burst of in-flight requests overshoot the 200 cap.
#
# Each phase asserts the expected pipeline exit code; the script exits 0 only
# if all phases match (Phase 4 is skipped, not failed, when TLC is absent).
# Phases 1-3 are pure offline: the symbolic engine is used -- no Java and no
# TLC jar are required. Phase 4 runs all three engines in parallel, so it needs
# Java 8+ and tla2tools.jar (TLA Toolbox); without them it is skipped.
#
# Usage:
#   bash demo.sh                # symbolic engine (offline), out/ for the manifest
#   ENGINE=tlc bash demo.sh     # cross-check phases 1-2 with the real TLC
#   OUT=out-demo bash demo.sh   # custom output dir for phase 3
#   (Phase 4 runs automatically when Java + tla2tools.jar are present;
#    otherwise it is skipped gracefully.)
#
# See docs/spendcap-demo.md (walkthrough) and docs/spendcap-usage.md (CLI reference).

set -u
cd "$(dirname "$0")"

if [ -z "${PY:-}" ]; then
    if command -v python >/dev/null 2>&1; then
        PY=python
    elif command -v python3 >/dev/null 2>&1; then
        PY=python3
    elif command -v py >/dev/null 2>&1; then
        PY=py
    else
        echo "error: no Python interpreter found on PATH (set PY=... to override)" >&2
        exit 3
    fi
fi
ENGINE=${ENGINE:-symbolic}
OUT=${OUT:-out}
CORRECT=${CORRECT:-tests/fixtures/aws_dogwood/spendcap/policies/spendcap-correct.dw}
BUGGY=${BUGGY:-tests/fixtures/aws_dogwood/spendcap/policies/spendcap-buggy.dw}

BAR=$(printf -- '-%.0s' $(seq 1 66))
FAILURES=0

run_phase() {
    # $1 = phase number, $2 = title, $3 = expected exit code, rest = pipeline args
    local phase="$1" title="$2" expected="$3"
    shift 3
    echo
    echo "$BAR"
    echo "Phase ${phase} -- ${title}"
    echo "$BAR"
    "$PY" "$@"
    local code=$?
    if [ "$code" -eq "$expected" ]; then
        echo "  [PASS] exit ${code} as expected"
    else
        echo "  [FAIL] exit ${code}, expected ${expected}"
        FAILURES=$((FAILURES + 1))
    fi
}

# ---- Show the policy -> model abstraction BEFORE checking anything ----------
# So the audience sees exactly which policy maps to which model, and what the
# model assumes that the raw policy does not say. (Honest "discrimination"
# framing: we display the abstraction we check, not a general compilation.)
echo
echo "Abstraction: policy -> bounded model (what the engines will check)"
echo "  --- CORRECT variant ---"
"$PY" -m rot.spendcap_display "$CORRECT" --max-inflight 3
echo "  --- BUGGY variant ---"
"$PY" -m rot.spendcap_display "$BUGGY" --max-inflight 3

# ---- Phase 1: the CORRECT policy must be PROVEN ----------------------------
run_phase 1 "PROVEN -- spendcap-correct.dw (safety holds)" 0 \
    pipeline.py --policy "$CORRECT" --engine "$ENGINE"

# ---- Phase 2: the BUGGY policy must be VIOLATED (+ witness) ----------------
run_phase 2 "VIOLATED -- spendcap-buggy.dw (witness emitted)" 1 \
    pipeline.py --policy "$BUGGY" --engine "$ENGINE"

# ---- Phase 3: three-facet audit + deterministic manifest -------------------
run_phase 3 "AUDIT -- trifecta (safety + liveness + conformance) + manifest" 0 \
    pipeline.py --trifecta \
        --allowed read_log,update_balance \
        --denied exfiltrate_secret \
        --manifest --out "$OUT"

# Phase 3 artifact: the manifest must exist and pass the integrity check.
MANIFEST="${OUT%/}/trifecta_manifest.json"
if [ ! -f "$MANIFEST" ]; then
    echo "  [FAIL] expected manifest at ${MANIFEST}"
    FAILURES=$((FAILURES + 1))
else
    if "$PY" - "$MANIFEST" <<'EOF'
import json, sys
from rot import manifest
with open(sys.argv[1]) as f:
    d = json.load(f)
ok, cid, note = manifest.verify_manifest(d)
print("  manifest verify: %s  id=%s  %s" % (ok, cid[:16], note))
sys.exit(0 if ok else 1)
EOF
    then
        :
    else
        FAILURES=$((FAILURES + 1))
    fi
fi

# Phase 3 artifact: the D6 risk flag must exist and be CLEAR for this policy
# (it spans private-data-access + egress, but has no untrusted-content-intake
# facet, so the lethal combination is absent).
RISK="${OUT%/}/trifecta_risk.json"
if [ ! -f "$RISK" ]; then
    echo "  [FAIL] expected D6 risk flag at ${RISK}"
    FAILURES=$((FAILURES + 1))
else
    if "$PY" - "$RISK" <<'EOF'
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
ok = d.get("detected") is False and d.get("message") == "TRIFECTA: clear"
print("  risk flag     : %s  (detected=%s, missing=%s)"
      % (d.get("message"), d.get("detected"), ",".join(d.get("missing", []))))
sys.exit(0 if ok else 1)
EOF
    then
        :
    else
        echo "  [FAIL] D6 risk flag check failed (expected TRIFECTA: clear)"
        FAILURES=$((FAILURES + 1))
    fi
fi

# ---- Phase 4: three-engine crosscheck at EXPLICIT K (SMT/Z3 + TLC + policy-direct) -----------
# The credibility core: three INDEPENDENT model checkers (SMT/Z3 + TLC + policy-direct, zero
# shared code) run the REAL Dogwood policy file at an explicit concurrency
# bound and ALL THREE must find the SAME 3-parallel-fire attack state.  4a runs at
# K=3 (completed=0, inflight=3) and asserts witness_match -- the three engines'
# counterexamples are the identical state.  4b runs at K=1 (K < 3) and asserts
# ALL THREE engines agree the invariant HOLDS (PROVEN) -- the bug is masked below
# K=3.  K is stated in each run.  Gated on TLC availability: if java +
# tla2tools.jar are absent the phase is skipped gracefully (no failure) --
# phases 1-3 already cover the offline path.
PHASE4_SKIPPED=0
if "$PY" -c "import sys; from rot.config import Config; sys.exit(0 if Config(engine='crosscheck').tlc_available() else 1)" 2>/dev/null; then
    # Phase 4a: K=3 -- all three engines VIOLATED, and the counterexamples MUST MATCH.
    run_phase 4 "CROSSCHECK K=3 -- spendcap-buggy.dw (SMT/Z3 + TLC + policy-direct, same 3-parallel-fire witness)" 1 \
        pipeline.py --policy "$BUGGY" --engine crosscheck --max-inflight 3 --out "$OUT"

    # Curate the compact crosscheck report, attach the Apalache ITF witness,
    # and assert the three engines' counterexamples are the SAME attack state.
    XCC_REPORT="${OUT%/}/crosscheck_report.json"
    ITF=tests/fixtures/aws_dogwood/spendcap/apalache-buggy.itf.json
    REPORT="${OUT%/}/policy-$(basename "$BUGGY")_spendcap_within_cap.json"
    if [ ! -f "$REPORT" ]; then
        echo "  [FAIL] expected crosscheck report at ${REPORT}"
        FAILURES=$((FAILURES + 1))
    else
        if "$PY" -m rot.crosscheck "$REPORT" --witness "apalache-itf=${ITF}" --out "$XCC_REPORT" >/dev/null; then
            :
        else
            echo "  [FAIL] crosscheck report build failed"
            FAILURES=$((FAILURES + 1))
        fi
        if "$PY" - "$XCC_REPORT" <<'EOF'
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
a = d["agreement"]
agree = a["agree"] is True
c = d["counterexamples"]
wm = a.get("witness_match") is True
ce_eq = (c.get("smtz3") is not None and c.get("smtz3") == c.get("tlc")
         and c.get("smtz3") == c.get("policy_direct"))
verdict = d["verdict"] == "violated"
print("  K           : 3 (bounded concurrency pool, stated)")
print("  agreement   : %s  (smtz3=%s, tlc=%s, policy_direct=%s, joined=%s)"
      % ("AGREE" if agree else "DISAGREE", a["smtz3"], a["tlc"],
         a.get("policy_direct"), a["joined"]))
print("  witness     : smtz3=%s  tlc=%s  policy_direct=%s  -> %s"
      % (c.get("smtz3"), c.get("tlc"), c.get("policy_direct"),
         "MATCH (same 3-parallel-fire state)" if wm else "MISMATCH"))
print("  witness(es) : %s" % ", ".join(w.get("name", "?") for w in d.get("witnesses", [])))
sys.exit(0 if (agree and wm and ce_eq and verdict) else 1)
EOF
        then
            echo "  [PASS] crosscheck K=3: SMT/Z3 + TLC + policy-direct agree AND find the SAME counterexample"
        else
            echo "  [FAIL] crosscheck K=3: expected agree=true + matching counterexamples"
            FAILURES=$((FAILURES + 1))
        fi
    fi

    # Phase 4b: K=1 (K < 3) -- ALL THREE engines agree the invariant HOLDS (masked).
    # Runs to a separate out dir so it does not clobber the K=3 artifacts.
    run_phase 4 "CROSSCHECK K=1 (masked, K<3) -- spendcap-buggy.dw (SMT/Z3 + TLC + policy-direct all PROVEN)" 0 \
        pipeline.py --policy "$BUGGY" --engine crosscheck --max-inflight 1 --out "${OUT%/}/k1"
else
    PHASE4_SKIPPED=1
    echo
    echo "$BAR"
    echo "Phase 4 -- CROSSCHECK (SMT/Z3 + TLC + policy-direct)"
    echo "$BAR"
    echo "  [SKIP] TLC not available (no java + tla2tools.jar) -- crosscheck needs TLC."
    echo "         Install Java 8+ and set TLA2TOOLS_JAR (or run in WSL) to enable."
fi

# ---- Phase 5: K-sweep -- bug visibility vs the concurrency pool K ----------
# K is structural, not policy: it bounds how many in-flight requests the
# state space can express, shared by both variants.  Sweep the buggy policy:
#   K=1 -> exit 0 (masked: a single in-flight cannot overshoot the cap)
#   K=2 -> exit 1 (VIOLATED, witness completed=100, inflight=2)
#   K=3 -> exit 1 (VIOLATED, witness completed=0, inflight=3, clean fire)
run_phase 5 "K-SWEEP -- buggy policy K=1: masked (PROVEN)" 0 \
    pipeline.py --policy "$BUGGY" --max-inflight 1 --engine symbolic

run_phase 5 "K-SWEEP -- buggy policy K=2: VIOLATED (100, 2)" 1 \
    pipeline.py --policy "$BUGGY" --max-inflight 2 --engine symbolic

run_phase 5 "K-SWEEP -- buggy policy K=3: VIOLATED (0, 3) clean parallel fire" 1 \
    pipeline.py --policy "$BUGGY" --max-inflight 3 --engine symbolic

echo
echo "$BAR"
if [ "$FAILURES" -eq 0 ]; then
    if [ "$PHASE4_SKIPPED" = "1" ]; then
        echo "DEMO OK: 4 phases passed (Phase 4 crosscheck skipped -- TLC absent)."
    else
        echo "DEMO OK: all 5 phases passed (incl. three-engine crosscheck K=3 witness-match + K=1 masked + ITF witness + K-sweep)."
    fi
    exit 0
fi
echo "DEMO FAILED: ${FAILURES} check(s) deviated from the expected exit codes."
exit 1