#requires -Version 3.0
<#
.SYNOPSIS
    ROTN spend-cap demo (AWS Dogwood .dw policies) -- 5 phases, exit-code aware.

.DESCRIPTION
    Five phases, each asserting the expected pipeline exit code:

      Phase 1  PROVEN    --policy spendcap-correct.dw  -> exit 0 (safety holds)
      Phase 2  VIOLATED  --policy spendcap-buggy.dw    -> exit 1 (witness emitted)
      Phase 3  AUDIT     --trifecta --manifest         -> exit 0 (+ out/trifecta_manifest.json
                                                      + out/trifecta_risk.json)
      Phase 4  CROSSCHECK --engine crosscheck (SMT/Z3 + TLC + policy-direct), explicit K
                 4a: K=3 -> exit 1 (all three engines VIOLATED, SAME 3-parallel-fire witness)
                 4b: K=1 -> exit 0 (all three engines PROVEN -- the bug is masked for K<3)
                 + out/crosscheck_report.json (curated: agree + 3 CEs + witness_match + ITF)
                 [SKIP if TLC (java + tla2tools.jar) is absent -- graceful]
      Phase 5  K-SWEEP   --max-inflight K (symbolic)
                 K=1 -> exit 0 (masked/PROVEN), K=2 -> exit 1, K=3 -> exit 1 (clean fire)

    The one-word diff between the two policies (``request`` vs ``response``) is
    the entire seeded bug: summing over ``Transfer::request`` (issued
    transfers, in-flight included) is correct; summing over
    ``Transfer::response`` (settled only) lets a parallel-fire burst of
    in-flight requests overshoot the 200 cap.

    Phase 3 additionally runs the D6 "Lethal Trifecta" design-time risk flag
    (``rot.trifecta_risk``), writes the deterministic three-facet manifest
    (safety + liveness + conformance) and re-verifies its integrity
    (SHA-256 ``manifest_id``).

    The Phase 3 policy spans private-data-access (read_log / update_balance)
    and egress (exfiltrate_secret) but has no untrusted-content-intake facet,
    so the risk flag is expected to be CLEAR ("TRIFECTA: clear") -- a
    calibration check that the flag requires all three facets, not two.

    Phase 4 runs the buggy policy through THREE independent engines (SMT/Z3 +
    TLC + policy-direct, zero shared code) at an EXPLICIT concurrency bound and joins their
    verdicts.  4a runs at K=3 and asserts all three engines are VIOLATED AND their
    counterexamples are the SAME attack state (witness_match -- the clean
    3-parallel-fire ``completed=0, inflight=3``); 4b runs at K=1 (K < 3) and
    asserts all three engines are PROVEN, i.e. the bug is masked below K=3.  It
    curates a compact crosscheck_report.json with the Apalache ITF witness
    attached (evidence-only). It is gated on TLC availability
    (java + tla2tools.jar); without them it is skipped gracefully (not a
    failure).

    Phases 1-3 are pure offline: the symbolic engine is used -- no Java and
    no TLC jar are required.

    The script exits 0 only if all phases match their expected codes.

.PARAMETER Engine
    Engine for phases 1-2 (default: symbolic). auto/tlc/crosscheck are
    accepted where the tooling is present. Phase 3 (trifecta) is
    engine-agnostic.

.PARAMETER Out
    Output directory for the phase-3 manifest (default: out).

.PARAMETER CorrectPolicy
    Path to the correct spend-cap policy (default: the repo fixture).

.PARAMETER BuggyPolicy
    Path to the buggy spend-cap policy (default: the repo fixture).

.EXAMPLE
    .\demo.ps1

.EXAMPLE
    .\demo.ps1 -Engine auto -Out out-demo

.NOTES
    See docs/spendcap-demo.md (walkthrough) and docs/spendcap-usage.md (CLI
    reference).
#>
[CmdletBinding()]
param(
    [ValidateSet("auto", "tlc", "symbolic", "crosscheck")][string]$Engine = "symbolic",
    [string]$Out = "out",
    [string]$CorrectPolicy = "tests\fixtures\aws_dogwood\spendcap\policies\spendcap-correct.dw",
    [string]$BuggyPolicy   = "tests\fixtures\aws_dogwood\spendcap\policies\spendcap-buggy.dw"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

# Locate a Python interpreter (same lookup as run.ps1).
if (Get-Command "python" -ErrorAction SilentlyContinue) { $py = "python" }
elseif (Get-Command "py" -ErrorAction SilentlyContinue) { $py = "py" }
else { Write-Error "Python interpreter not found on PATH."; exit 3 }

$BAR = "-" * 66
$script:failures = 0

function Code-Name {
    param([int]$Code)
    if ($Code -eq 0) { return "PROVEN" }
    if ($Code -eq 1) { return "VIOLATED" }
    if ($Code -eq 2) { return "UNKNOWN" }
    return "ERROR"
}

function Run-Phase {
    param(
        [int]$Phase,
        [string]$Title,
        [int]$Expected,
        [string[]]$PipelineArgs
    )
    Write-Host ""
    Write-Host $BAR
    Write-Host ("Phase {0} -- {1}" -f $Phase, $Title)
    Write-Host $BAR
    & $py @PipelineArgs
    $code = $LASTEXITCODE
    if ($code -eq $Expected) {
        Write-Host ("  [PASS] exit {0} as expected ({1})" -f $code, (Code-Name $Expected))
    } else {
        Write-Host ("  [FAIL] exit {0}, expected {1} ({2})" -f $code, $Expected, (Code-Name $Expected))
        $script:failures += 1
    }
}

# ---- Show the policy -> model abstraction BEFORE checking anything ----------
# So the audience sees exactly which policy maps to which model, and what the
# model assumes that the raw policy does not say. (Honest "discrimination"
# framing: we display the abstraction we check, not a general compilation.)
Write-Host ""
Write-Host "Abstraction: policy -> bounded model (what the engines will check)"
Write-Host "  --- CORRECT variant ---"
& $py -m rot.spendcap_display $CorrectPolicy --max-inflight 3
Write-Host "  --- BUGGY variant ---"
& $py -m rot.spendcap_display $BuggyPolicy --max-inflight 3

# ---- Phase 1: the CORRECT policy must be PROVEN ----------------------------
Run-Phase -Phase 1 -Title "PROVEN -- spendcap-correct.dw (safety holds)" `
    -Expected 0 `
    -PipelineArgs @("pipeline.py", "--policy", $CorrectPolicy, "--engine", $Engine)

# ---- Phase 2: the BUGGY policy must be VIOLATED (+ witness) ----------------
Run-Phase -Phase 2 -Title "VIOLATED -- spendcap-buggy.dw (witness emitted)" `
    -Expected 1 `
    -PipelineArgs @("pipeline.py", "--policy", $BuggyPolicy, "--engine", $Engine)

# ---- Phase 3: three-facet audit + deterministic manifest -------------------
Run-Phase -Phase 3 -Title "AUDIT -- trifecta (safety + liveness + conformance) + manifest" `
    -Expected 0 `
    -PipelineArgs @(
        "pipeline.py", "--trifecta",
        "--allowed", "read_log,update_balance",
        "--denied", "exfiltrate_secret",
        "--manifest", "--out", $Out
    )

# Phase 3 artifact: the manifest must exist and pass the integrity check.
$manifestPath = Join-Path $here (Join-Path $Out "trifecta_manifest.json")
if (-not (Test-Path $manifestPath)) {
    Write-Host "  [FAIL] expected manifest at $manifestPath"
    $script:failures += 1
} else {
    & $py -c "import json, sys; from rot import manifest; d = json.load(open(sys.argv[1])); ok, cid, note = manifest.verify_manifest(d); print('  manifest verify: %s  id=%s  %s' % (ok, cid[:16], note)); sys.exit(0 if ok else 1)" $manifestPath
    if ($LASTEXITCODE -ne 0) { $script:failures += 1 }
}

# Phase 3 artifact: the D6 risk flag must exist and be CLEAR for this policy
# (it spans private-data-access + egress, but has no untrusted-content-intake
# facet, so the lethal combination is absent).
$riskPath = Join-Path $here (Join-Path $Out "trifecta_risk.json")
if (-not (Test-Path $riskPath)) {
    Write-Host "  [FAIL] expected D6 risk flag at $riskPath"
    $script:failures += 1
} else {
    & $py -c "import json, sys; d = json.load(open(sys.argv[1])); ok = (d.get('detected') is False and d.get('message') == 'TRIFECTA: clear'); print('  risk flag     : %s  (detected=%s, missing=%s)' % (d.get('message'), d.get('detected'), ','.join(d.get('missing', [])))); sys.exit(0 if ok else 1)" $riskPath
    if ($LASTEXITCODE -ne 0) { $script:failures += 1 }
}

# ---- Phase 4: three-engine crosscheck at EXPLICIT K (SMT/Z3 + TLC + policy-direct) -----------
# The credibility core: three INDEPENDENT model checkers (SMT/Z3 + TLC + policy-direct, zero
# shared code) run the REAL Dogwood policy file at an explicit concurrency
# bound and ALL THREE must find the SAME 3-parallel-fire attack state.  Phase 4a
# runs at K=3 (the clean fire: completed=0, inflight=3) and asserts
# witness_match -- the three engines' counterexamples are the identical state.
# Phase 4b runs at K=1 (K < 3) and asserts ALL THREE engines agree the invariant
# HOLDS (PROVEN) -- i.e. the bug is masked below K=3.  K is stated in each
# run.  Gated on TLC availability (java + tla2tools.jar): if absent the
# phase is skipped gracefully (no failure) -- phases 1-3 cover the offline path.
$phase4skipped = $false
& $py -c "import sys; from rot.config import Config; sys.exit(0 if Config(engine='crosscheck').tlc_available() else 1)"
if ($LASTEXITCODE -eq 0) {
    # Phase 4a: K=3 -- all three engines VIOLATED, and the counterexamples MUST MATCH.
    Run-Phase -Phase 4 -Title "CROSSCHECK K=3 -- spendcap-buggy.dw (SMT/Z3 + TLC + policy-direct, same 3-parallel-fire witness)" `
        -Expected 1 `
        -PipelineArgs @("pipeline.py", "--policy", $BuggyPolicy, "--engine", "crosscheck", "--max-inflight", "3", "--out", $Out)

    # Curate the compact crosscheck report, attach the Apalache ITF witness,
    # and assert the three engines' counterexamples are the SAME attack state.
    $xccReport  = Join-Path $here (Join-Path $Out "crosscheck_report.json")
    $itf        = "tests\fixtures\aws_dogwood\spendcap\apalache-buggy.itf.json"
    $reportPath = Join-Path $here (Join-Path $Out ("policy-" + (Split-Path $BuggyPolicy -Leaf) + "_spendcap_within_cap.json"))
    if (-not (Test-Path -LiteralPath $reportPath)) {
        Write-Host "  [FAIL] expected crosscheck report at $reportPath"
        $script:failures += 1
    } else {
        & $py -m rot.crosscheck $reportPath "--witness=apalache-itf=$itf" "--out=$xccReport"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [FAIL] crosscheck report build failed"
            $script:failures += 1
        }
        & $py -c "import json, sys; d = json.load(open(sys.argv[1])); a = d['agreement']; c = d['counterexamples']; ok = (a['agree'] is True and d['verdict'] == 'violated' and a.get('witness_match') is True and c.get('smtz3') is not None and c.get('smtz3') == c.get('tlc') and c.get('smtz3') == c.get('policy_direct')); print('  K           : 3 (bounded concurrency pool, stated)'); print('  agreement   : %s  (smtz3=%s, tlc=%s, policy_direct=%s, joined=%s)' % ('AGREE' if a['agree'] else 'DISAGREE', a['smtz3'], a['tlc'], a.get('policy_direct'), a['joined'])); print('  witness     : smtz3=%s  tlc=%s  policy_direct=%s  -> %s' % (c.get('smtz3'), c.get('tlc'), c.get('policy_direct'), 'MATCH (same 3-parallel-fire state)' if a.get('witness_match') else 'MISMATCH')); print('  witness(es) : %s' % ', '.join(w.get('name', '?') for w in d.get('witnesses', []))); sys.exit(0 if ok else 1)" $xccReport
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [PASS] crosscheck K=3: SMT/Z3 + TLC + policy-direct agree AND find the SAME counterexample"
        } else {
            Write-Host "  [FAIL] crosscheck K=3: expected agree=true + matching counterexamples"
            $script:failures += 1
        }
    }

    # Phase 4b: K=1 (K < 3) -- ALL THREE engines agree the invariant HOLDS (masked).
    # Runs to a separate out dir so it does not clobber the K=3 artifacts.
    Run-Phase -Phase 4 -Title "CROSSCHECK K=1 (masked, K<3) -- spendcap-buggy.dw (SMT/Z3 + TLC + policy-direct all PROVEN)" `
        -Expected 0 `
        -PipelineArgs @("pipeline.py", "--policy", $BuggyPolicy, "--engine", "crosscheck", "--max-inflight", "1", "--out", (Join-Path $Out "k1"))
} else {
    $phase4skipped = $true
    Write-Host ""
    Write-Host $BAR
    Write-Host "Phase 4 -- CROSSCHECK (SMT/Z3 + TLC + policy-direct)"
    Write-Host $BAR
    Write-Host "  [SKIP] TLC not available (no java + tla2tools.jar) -- crosscheck needs TLC."
    Write-Host "         Install Java 8+ and set TLA2TOOLS_JAR (or run in WSL) to enable."
}

# ---- Phase 5: K-sweep -- bug visibility vs the concurrency pool K ----------
# K is structural, not policy: it bounds how many in-flight requests the
# state space can express, shared by both variants.  Sweep the buggy policy:
#   K=1 -> exit 0 (masked: a single in-flight cannot overshoot the cap)
#   K=2 -> exit 1 (VIOLATED, witness completed=100, inflight=2)
#   K=3 -> exit 1 (VIOLATED, witness completed=0, inflight=3, clean fire)
Run-Phase -Phase 5 -Title "K-SWEEP -- buggy policy K=1: masked (PROVEN)" `
    -Expected 0 `
    -PipelineArgs @("pipeline.py", "--policy", $BuggyPolicy, "--max-inflight", "1", "--engine", "symbolic")

Run-Phase -Phase 5 -Title "K-SWEEP -- buggy policy K=2: VIOLATED (100, 2)" `
    -Expected 1 `
    -PipelineArgs @("pipeline.py", "--policy", $BuggyPolicy, "--max-inflight", "2", "--engine", "symbolic")

Run-Phase -Phase 5 -Title "K-SWEEP -- buggy policy K=3: VIOLATED (0, 3) clean parallel fire" `
    -Expected 1 `
    -PipelineArgs @("pipeline.py", "--policy", $BuggyPolicy, "--max-inflight", "3", "--engine", "symbolic")

Write-Host ""
Write-Host $BAR
if ($script:failures -eq 0) {
    if ($phase4skipped) {
        Write-Host "DEMO OK: 4 phases passed (Phase 4 crosscheck skipped -- TLC absent)."
    } else {
        Write-Host "DEMO OK: all 5 phases passed (incl. three-engine crosscheck K=3 witness-match + K=1 masked + ITF witness + K-sweep)."
    }
    exit 0
}
Write-Host ("DEMO FAILED: {0} check(s) deviated from the expected exit codes." -f $script:failures)
exit 1