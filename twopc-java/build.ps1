# build.ps1 -- plain javac build for the Phase 2 2PC vertical slice. No Maven/Gradle.
#
#   .\build.ps1              # compile everything + W1 demo + W0 smoke + W2 probe + W3 replay + W6 benchmark/determinism
#   .\build.ps1 -What demo   # compile + race demo only
#   .\build.ps1 -What smoke  # compile + agent smoke test only
#   .\build.ps1 -What probe  # compile + W2 trace emission + structural tracecheck
#   .\build.ps1 -What replay # compile + W3 gated replay + deterministic triple
#   .\build.ps1 -What w6     # compile + W6 probe-cost benchmark + 100x determinism gate
#   .\build.ps1 -What w7     # compile + W7 minimal logging policy + filtered replay
param(
    [ValidateSet("all", "demo", "smoke", "probe", "replay", "w6", "w7")]
    [string]$What = "all"
)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path          # ...\ROTN\twopc-java
$Repo = Split-Path -Parent $Root                                  # ...\ROTN
$Lib  = Join-Path $Repo "third_party"
$Out  = Join-Path $Root "build"
$Classes = Join-Path $Out "classes"
$SmokeClasses = Join-Path $Out "smoke-classes"
$ProbeClasses = Join-Path $Out "probe-classes"
$AgentJar = Join-Path $Out "smoke-agent.jar"
$ProbeAgentJar = Join-Path $Out "probe-agent.jar"

function Find-Jdk {
    $cmd = Get-Command javac -ErrorAction SilentlyContinue
    if ($cmd) { return (Split-Path (Split-Path $cmd.Source)) }
    foreach ($base in @("$env:ProgramFiles\Eclipse Adoptium",
                        "$env:ProgramFiles(x86)\Eclipse Adoptium",
                        "$env:LOCALAPPDATA\Programs\Eclipse Adoptium")) {
        if (Test-Path $base) {
            $j = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
                 ForEach-Object { Join-Path $_.FullName "bin\javac.exe" } |
                 Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($j) { return (Split-Path (Split-Path $j)) }
        }
    }
    throw "javac not found -- install Temurin JDK 11 first (winget install EclipseAdoptium.Temurin.11.JDK)"
}

function Find-Python {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cand = "C:\Program Files\Python36\python.exe"
    if (Test-Path $cand) { return $cand }
    throw "python not found"
}

$Jdk = Find-Jdk
$javac = Join-Path $Jdk "bin\javac.exe"
$java  = Join-Path $Jdk "bin\java.exe"
$jar   = Join-Path $Jdk "bin\jar.exe"
$py    = Find-Python
& $javac -version | Out-Host
& $py --version | Out-Host

$asm = Get-ChildItem $Lib -Filter "org.ow2.asm.asm-*.jar" | ForEach-Object { $_.FullName }
if ($asm.Count -eq 0) { throw "ASM jars missing in $Lib" }
$cpAsm = $asm -join ";"

New-Item -ItemType Directory -Force -Path $Classes | Out-Null
New-Item -ItemType Directory -Force -Path $SmokeClasses | Out-Null
New-Item -ItemType Directory -Force -Path $ProbeClasses | Out-Null

# ---- 1. 2PC target + probe sink + demo (no dependencies) -------------------------
$twopcSrc = @(
    (Join-Path $Root "src\com\rotn\twopc\*.java"),
    (Join-Path $Root "src\com\rotn\scheduler\*.java"),
    (Join-Path $Root "src\com\rotn\probe\*.java"),
    (Join-Path $Root "src\com\rotn\demo\*.java")
)
$files = @()
foreach ($g in $twopcSrc) { $files += (Get-ChildItem $g).FullName }
& $javac --release 8 -d $Classes $files
if ($LASTEXITCODE -ne 0) { throw "twopc compile failed" }

# ---- 2. W0 smoke agent (depends on ASM) ------------------------------------------
$smokeSrc = Get-ChildItem (Join-Path $Root "agent-smoke\src") -Recurse -Filter "*.java" | ForEach-Object { $_.FullName }
& $javac --release 8 -cp $cpAsm -d $SmokeClasses $smokeSrc
if ($LASTEXITCODE -ne 0) { throw "smoke compile failed" }

# bundle ASM inside the agent jar so -javaagent works with a bare -cp
$Manifest = Join-Path $Out "agent-manifest.mf"
"Manifest-Version: 1.0`r`nAgent-Class: com.rot.n.agent.SmokeAgent`r`nPremain-Class: com.rot.n.agent.SmokeAgent`r`nCan-Redefine-Classes: true`r`nCan-Retransform-Classes: true`r`n" |
    Set-Content -Encoding ASCII -Path $Manifest

$AsmUnpacked = Join-Path $Out "asm-unpacked"
Remove-Item $AsmUnpacked -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $AsmUnpacked | Out-Null
Push-Location $AsmUnpacked
foreach ($a in $asm) { & $jar -xf $a }
Pop-Location

Remove-Item $AgentJar -Force -ErrorAction SilentlyContinue
& $jar -cfm $AgentJar $Manifest -C $SmokeClasses . -C $AsmUnpacked .
if ($LASTEXITCODE -ne 0) { throw "agent jar failed" }

# ---- 3. W2 probe agent (instruments Bus.record; needs ASM + compiled probe sink) -
$probeAgentSrc = Get-ChildItem (Join-Path $Root "agent-probe\src") -Recurse -Filter "*.java" | ForEach-Object { $_.FullName }
& $javac --release 8 -cp "$cpAsm;$Classes" -d $ProbeClasses $probeAgentSrc
if ($LASTEXITCODE -ne 0) { throw "probe agent compile failed" }

$ProbeManifest = Join-Path $Out "probe-agent-manifest.mf"
"Manifest-Version: 1.0`r`nAgent-Class: com.rot.n.agent.ProbeAgent`r`nPremain-Class: com.rot.n.agent.ProbeAgent`r`nCan-Redefine-Classes: true`r`nCan-Retransform-Classes: true`r`n" |
    Set-Content -Encoding ASCII -Path $ProbeManifest
Remove-Item $ProbeAgentJar -Force -ErrorAction SilentlyContinue
& $jar -cfm $ProbeAgentJar $ProbeManifest -C $ProbeClasses . -C $AsmUnpacked .
if ($LASTEXITCODE -ne 0) { throw "probe agent jar failed" }

Write-Host ""
Write-Host "BUILD OK"
# ---- 4. W1 race demo ------------------------------------------------------------
if ($What -in @("all", "demo")) {
    Write-Host ""
    Write-Host "=== W1 race demo ==="
    & $java -cp $Classes com.rot.n.demo.RaceDemo
    $demoExit = $LASTEXITCODE
    Write-Host "race-demo exit=$demoExit"
    if ($demoExit -ne 0) { throw "race demo failed (exit $demoExit)" }
}

# ---- 5. W0 agent smoke test -----------------------------------------------------
if ($What -in @("all", "smoke")) {
    Write-Host ""
    Write-Host "=== W0 smoke (no agent) ==="
    & $java -cp $SmokeClasses com.rot.n.smoke.App
    Write-Host "=== W0 smoke (with -javaagent) ==="
    & $java "-javaagent:$AgentJar" -cp $SmokeClasses com.rot.n.smoke.App
    $smokeOut = & $java "-javaagent:$AgentJar" -cp $SmokeClasses com.rot.n.smoke.App 2>&1 | Out-String
    if ($smokeOut -notmatch "SMOKE-PROBE App\.<init>") {
        throw "agent smoke test FAILED: probe did not fire"
    }
    Write-Host "agent smoke test PASS"
}

# ---- 6. W2 probe trace emission + structural check --------------------------------
if ($What -in @("all", "probe")) {
    Write-Host ""
    Write-Host "=== W2 probe (control: no agent, expect no trace file) ==="
    $ctl = Join-Path $Out "trace-control.jsonl"
    if (Test-Path $ctl) { Remove-Item $ctl -Force }
    & $java "-Drotn.probe.trace=$ctl" -cp "$Classes" com.rot.n.demo.TraceDemo buggy
    $ctlExit = $LASTEXITCODE
    Write-Host "trace-demo (control) exit=$ctlExit"
    if ($ctlExit -ne 0) { throw "trace demo control failed (exit $ctlExit)" }
    if (Test-Path $ctl) { throw "control run unexpectedly wrote a trace file" }

    Write-Host "=== W2 probe (buggy run with -javaagent) ==="
    $traceBuggy = Join-Path $Out "trace-buggy.jsonl"
    if (Test-Path $traceBuggy) { Remove-Item $traceBuggy -Force }
    & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$traceBuggy" -cp "$Classes" com.rot.n.demo.TraceDemo buggy
    $buggyExit = $LASTEXITCODE
    Write-Host "trace-demo (buggy) exit=$buggyExit"
    if ($buggyExit -ne 0) { throw "trace demo failed (exit $buggyExit)" }
    if (-not (Test-Path $traceBuggy)) { throw "no trace file produced" }

    Write-Host "=== W2 probe (correct run with -javaagent) ==="
    $traceCorrect = Join-Path $Out "trace-correct.jsonl"
    if (Test-Path $traceCorrect) { Remove-Item $traceCorrect -Force }
    & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$traceCorrect" -cp "$Classes" com.rot.n.demo.TraceDemo correct
    $correctExit = $LASTEXITCODE
    Write-Host "trace-demo (correct) exit=$correctExit"
    if ($correctExit -ne 0) { throw "trace demo failed (exit $correctExit)" }
    if (-not (Test-Path $traceCorrect)) { throw "no trace file produced" }

    Write-Host "=== W2 structural tracecheck (python) ==="
    & $py (Join-Path $Repo "rot\tracecheck.py") $traceBuggy
    $tcExit = $LASTEXITCODE
    if ($tcExit -ne 0) { throw "structural tracecheck FAILED (buggy, exit $tcExit)" }
    & $py (Join-Path $Repo "rot\tracecheck.py") $traceCorrect
    $tcExit = $LASTEXITCODE
    if ($tcExit -ne 0) { throw "structural tracecheck FAILED (correct, exit $tcExit)" }
    Write-Host "W2 probe trace emission PASS"
}

# ---- 7. W3 gated replay + deterministic triple -----------------------------------
# ReplayDemo drives the protocol through the Gate scheduler with the buggy witness
# schedule. Exit codes: 0 = CONFORMANT, 10 = NON-CONFORMANT,
# 20 = REJECTED (invalid/infeasible/mismatched schedule).
if ($What -in @("all", "replay")) {
    Write-Host ""
    Write-Host "=== W3 replay (buggy triple, expect NON-CONFORMANT exit 10) ==="
    $SchedBuggy = Join-Path $Out "schedule-buggy.jsonl"
    if (-not (Test-Path $SchedBuggy)) {
        Write-Host "=== W3 witness schedule generation (rot\witness.py) ==="
        Push-Location $Repo
        & $py -m rot.witness --target buggy --n 2 --property agreement --out $SchedBuggy
        $wExit = $LASTEXITCODE
        Pop-Location
        if ($wExit -ne 0) { throw "witness schedule generation failed (exit $wExit)" }
    }
    foreach ($i in @(1, 2, 3)) {
        $t = Join-Path $Out ("replay-buggy-{0}.jsonl" -f $i)
        if (Test-Path $t) { Remove-Item $t -Force }
        & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$t" "-Drotn.probe.run=w3-buggy" -cp "$Classes" com.rot.n.demo.ReplayDemo buggy $SchedBuggy
        $e = $LASTEXITCODE
        if ($e -ne 10) { throw "buggy replay run $i : expected exit 10 (NON-CONFORMANT), got $e" }
    }
    Write-Host "  buggy triple: 3x exit 10 (NON-CONFORMANT) as expected"

    Write-Host "=== W3 replay (correct triple, expect CONFORMANT exit 0) ==="
    foreach ($i in @(1, 2, 3)) {
        $t = Join-Path $Out ("replay-correct-{0}.jsonl" -f $i)
        if (Test-Path $t) { Remove-Item $t -Force }
        & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$t" "-Drotn.probe.run=w3-correct" -cp "$Classes" com.rot.n.demo.ReplayDemo correct $SchedBuggy
        $e = $LASTEXITCODE
        if ($e -ne 0) { throw "correct replay run $i : expected exit 0 (CONFORMANT), got $e" }
    }
    Write-Host "  correct triple: 3x exit 0 (CONFORMANT) as expected"

    $hBuggy = @()
    $hCorrect = @()
    foreach ($i in @(1, 2, 3)) {
        $hBuggy += (Get-FileHash (Join-Path $Out ("replay-buggy-{0}.jsonl" -f $i)) -Algorithm SHA256).Hash
        $hCorrect += (Get-FileHash (Join-Path $Out ("replay-correct-{0}.jsonl" -f $i)) -Algorithm SHA256).Hash
    }
    if (-not ($hBuggy[0] -eq $hBuggy[1] -and $hBuggy[1] -eq $hBuggy[2])) {
        throw "buggy replay traces not byte-identical: $($hBuggy -join ', ')"
    }
    if (-not ($hCorrect[0] -eq $hCorrect[1] -and $hCorrect[1] -eq $hCorrect[2])) {
        throw "correct replay traces not byte-identical: $($hCorrect -join ', ')"
    }
    if ($hBuggy[0] -eq $hCorrect[0]) {
        throw "buggy and correct replay traces identical (unexpected)"
    }
    Write-Host ("  buggy   sha256 = " + $hBuggy[0])
    Write-Host ("  correct sha256 = " + $hCorrect[0])
    Write-Host "W3 replay determinism PASS"
}

# ---- 8. W6 probe-cost benchmark + 100x determinism gate --------------------------
# W6.1: the same W6Bench workload (tight loop over Bus.send -> Bus.record) run with
#       and without the -javaagent; overhead% = (instrumented-baseline)/baseline*100.
#       The baseline is a sub-microsecond in-memory path, so the % is large by
#       construction; the absolute added ns/record is the stable interpretable number.
# W6.2: replay the correct variant 100x with a fixed run id; assert every run exits 0
#       and all 100 traces are byte-identical (SHA256).
if ($What -in @("all", "w6")) {
    # Self-contained: ensure the witness schedule exists (shared path with W3 "replay").
    $SchedBuggy = Join-Path $Out "schedule-buggy.jsonl"
    if (-not (Test-Path $SchedBuggy)) {
        Write-Host "=== W6 witness schedule generation (rot\witness.py) ==="
        Push-Location $Repo
        & $py -m rot.witness --target buggy --n 2 --property agreement --out $SchedBuggy
        if ($LASTEXITCODE -ne 0) { throw "witness schedule generation failed" }
        Pop-Location
    }

    Write-Host ""
    Write-Host "=== W6.1 probe-cost benchmark (baseline vs -javaagent) ==="
    $benchRecords = 200000
    $baseOut = (& $java -cp "$Classes" com.rot.n.demo.W6Bench $benchRecords 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "W6Bench (baseline) failed: $baseOut" }
    if ($baseOut -notmatch "elapsed_ns=(\d+)") { throw "W6Bench (baseline) not parseable: $baseOut" }
    $baseNs = [long]$Matches[1]

    $benchTrace = Join-Path $Out "w6-bench-instrumented.jsonl"
    if (Test-Path $benchTrace) { Remove-Item $benchTrace -Force }
    $instrOut = (& $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$benchTrace" "-Drotn.probe.run=w6-bench" -cp "$Classes" com.rot.n.demo.W6Bench $benchRecords 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "W6Bench (instrumented) failed: $instrOut" }
    if ($instrOut -notmatch "elapsed_ns=(\d+)") { throw "W6Bench (instrumented) not parseable: $instrOut" }
    $instrNs = [long]$Matches[1]
    if (-not (Test-Path $benchTrace) -or ((Get-Item $benchTrace).Length -eq 0)) { throw "instrumented benchmark produced no trace" }

    $basePer     = [math]::Round($baseNs / $benchRecords, 2)
    $instrPer    = [math]::Round($instrNs / $benchRecords, 2)
    $overheadNs  = [math]::Round(($instrNs - $baseNs) / $benchRecords, 2)
    $overheadPct = [math]::Round(($instrNs - $baseNs) / $baseNs * 100, 2)
    Write-Host ("  records            = {0}" -f $benchRecords)
    Write-Host ("  baseline     = {0,12:N0} ns  ({1} ns/record)" -f $baseNs, $basePer)
    Write-Host ("  instrumented = {0,12:N0} ns  ({1} ns/record)" -f $instrNs, $instrPer)
    Write-Host ("  probe overhead = {0,12:N2} ns/record  ({1}% of baseline)" -f $overheadNs, $overheadPct)
    Write-Host "W6.1 PROBE-COST BENCHMARK: overhead reported"

    Write-Host ""
    Write-Host "=== W6.2 100x determinism gate (correct replay, fixed run id) ==="
    $runId = "w6-det"
    $N = 100
    $firstHash = $null
    $okCount = 0
    $mismatch = 0
    for ($i = 1; $i -le $N; $i++) {
        $t = Join-Path $Out ("w6-det-{0}.jsonl" -f $i)
        if (Test-Path $t) { Remove-Item $t -Force }
        & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$t" "-Drotn.probe.run=$runId" -cp "$Classes" com.rot.n.demo.ReplayDemo correct $SchedBuggy
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            $mismatch++
            Write-Host ("  run {0}: exit {1} (expected 0)" -f $i, $code)
            continue
        }
        if (-not (Test-Path $t)) {
            $mismatch++
            Write-Host ("  run {0}: no trace file" -f $i)
            continue
        }
        $h = (Get-FileHash $t -Algorithm SHA256).Hash
        if ($null -eq $firstHash) { $firstHash = $h }
        elseif ($h -ne $firstHash) {
            $mismatch++
            Write-Host ("  run {0}: sha256 differs from run 1" -f $i)
        }
        $okCount++
    }
    Write-Host ("  {0}/{1} runs exit 0; {2} hash mismatch(es)" -f $okCount, $N, $mismatch)
    if ($mismatch -ne 0) { throw "W6 determinism FAILED: $mismatch mismatch(es) in $N runs" }
    Write-Host ("  sha256 = {0}" -f $firstHash)
    Write-Host ("W6.2 DETERMINISM GATE: PASS ({0}/{1} byte-identical)" -f $N, $N)

    Write-Host ""
    Write-Host "W6 ALL CHECKS PASS"
}

# ---- 9. W7 minimal logging policy + filtered replay ------------------------------
# W7 derives the minimal log policy for the W3 obligations (agreement, validity,
# decision_before_apply) -> SPEC only, cost 1.0, agent filter "SPEC". It then
# replays the W3 scenarios with the probe filter active and asserts:
#   * only SPEC events are recorded (SEND/RECV dropped), gseq stays 0-based gapless
#   * the W2 structural gate still passes
#   * the W4 judgment is unchanged: buggy = NON-CONFORMANT (exit 10),
#     correct = CONFORMANT (exit 0)
#   * each trace is consistent with the policy the run used (logpolicy check)
#   * W6Bench (transport-only workload) records all events unfiltered, zero filtered
if ($What -in @("all", "w7")) {
    # Self-contained: ensure the witness schedule exists (shared path with W3 "replay").
    $SchedBuggy = Join-Path $Out "schedule-buggy.jsonl"
    if (-not (Test-Path $SchedBuggy)) {
        Write-Host "=== W7 witness schedule generation (rot\witness.py) ==="
        Push-Location $Repo
        & $py -m rot.witness --target buggy --n 2 --property agreement --out $SchedBuggy
        $wExit = $LASTEXITCODE
        Pop-Location
        if ($wExit -ne 0) { throw "witness schedule generation failed (exit $wExit)" }
    }

    Write-Host ""
    Write-Host "=== W7.1 derive minimal logging policy (rot\logpolicy.py) ==="
    $w7Policy = Join-Path $Out "w7-policy.json"
    if (Test-Path $w7Policy) { Remove-Item $w7Policy -Force }
    Push-Location $Repo
    & $py -m rot.logpolicy derive --obligations agreement,validity,decision_before_apply --out $w7Policy
    $dpExit = $LASTEXITCODE
    Pop-Location
    if ($dpExit -ne 0) { throw "logpolicy derive failed (exit $dpExit)" }
    if (-not (Test-Path $w7Policy)) { throw "policy document not written" }
    $polJson = Get-Content $w7Policy -Raw | ConvertFrom-Json
    if ($polJson.agent.value -ne "SPEC") {
        throw "minimal policy must enable SPEC only, got: $($polJson.agent.value)"
    }
    if ($polJson.cost.total -ne 1.0) {
        throw "minimal policy cost must be 1.0, got $($polJson.cost.total)"
    }
    Write-Host ("  minimal policy: enabled={0} disabled={1} cost={2} agent={3} digest={4}" -f
        ($polJson.enabled -join ","), ($polJson.disabled -join ","), $polJson.cost.total,
        $polJson.agent.value, $polJson.digest)
    Write-Host "W7.1 MINIMAL POLICY: SPEC only, cost 1.0"

    Write-Host ""
    Write-Host "=== W7.2 filtered replay (probe filter = SPEC) ==="
    $w7Buggy   = Join-Path $Out "w7-replay-buggy.jsonl"
    $w7Correct = Join-Path $Out "w7-replay-correct.jsonl"
    foreach ($t in @($w7Buggy, $w7Correct)) { if (Test-Path $t) { Remove-Item $t -Force } }
    & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$w7Buggy" "-Drotn.probe.run=w7-buggy" "-Drotn.probe.filter=SPEC" -cp "$Classes" com.rot.n.demo.ReplayDemo buggy $SchedBuggy
    $e = $LASTEXITCODE
    Write-Host ("  buggy   replay exit={0} (expected 10 NON-CONFORMANT)" -f $e)
    if ($e -ne 10) { throw "filtered buggy replay: expected exit 10, got $e" }
    & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$w7Correct" "-Drotn.probe.run=w7-correct" "-Drotn.probe.filter=SPEC" -cp "$Classes" com.rot.n.demo.ReplayDemo correct $SchedBuggy
    $e = $LASTEXITCODE
    Write-Host ("  correct replay exit={0} (expected 0 CONFORMANT)" -f $e)
    if ($e -ne 0) { throw "filtered correct replay: expected exit 0, got $e" }
    $evBuggy   = (Get-Content $w7Buggy   | Where-Object { $_.Trim() } |
        ForEach-Object { ($_ | ConvertFrom-Json) } | Where-Object { $_._meta -notin @("rotn-probe-header", "rotn-probe-trailer") }).Count
    $evCorrect = (Get-Content $w7Correct | Where-Object { $_.Trim() } |
        ForEach-Object { ($_ | ConvertFrom-Json) } | Where-Object { $_._meta -notin @("rotn-probe-header", "rotn-probe-trailer") }).Count
    Write-Host ("  events recorded: buggy={0} correct={1} (SPEC only; W3 full traces have SEND/RECV)" -f $evBuggy, $evCorrect)
    if ($evBuggy -le 0 -or $evCorrect -le 0) { throw "filtered traces must still record SPEC events" }

    Write-Host ""
    Write-Host "=== W7.3 W2 structural gate + W4 judgment on filtered traces ==="
    & $py (Join-Path $Repo "rot\tracecheck.py") $w7Buggy
    if ($LASTEXITCODE -ne 0) { throw "W2 structural gate FAILED on filtered buggy trace" }
    & $py (Join-Path $Repo "rot\tracecheck.py") $w7Correct
    if ($LASTEXITCODE -ne 0) { throw "W2 structural gate FAILED on filtered correct trace" }
    & $py (Join-Path $Repo "rot\tracecheck.py") --conformance $w7Buggy $SchedBuggy
    $c = $LASTEXITCODE
    if ($c -ne 10) { throw "W4 buggy filtered: expected exit 10 (NON-CONFORMANT), got $c" }
    & $py (Join-Path $Repo "rot\tracecheck.py") --conformance $w7Correct $SchedBuggy
    $c = $LASTEXITCODE
    if ($c -ne 0) { throw "W4 correct filtered: expected exit 0 (CONFORMANT), got $c" }
    Write-Host "  W2 PASS, W4 verdicts unchanged (buggy NON-CONFORMANT / correct CONFORMANT)"

    Write-Host ""
    Write-Host "=== W7.4 trace vs policy consistency (logpolicy check) ==="
    Push-Location $Repo
    & $py -m rot.logpolicy check --policy $w7Policy --trace $w7Buggy
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "filtered buggy trace not consistent with policy" }
    & $py -m rot.logpolicy check --policy $w7Policy --trace $w7Correct
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "filtered correct trace not consistent with policy" }
    Pop-Location
    Write-Host "  both filtered traces consistent with the SPEC-only policy"

    Write-Host ""
    Write-Host "=== W7.5 probe cost: W6Bench unfiltered vs SPEC-filtered ==="
    $benchRecords = 20000
    $w6u = Join-Path $Out "w7-w6-unfiltered.jsonl"
    $w6f = Join-Path $Out "w7-w6-filtered.jsonl"
    foreach ($t in @($w6u, $w6f)) { if (Test-Path $t) { Remove-Item $t -Force } }
    & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$w6u" "-Drotn.probe.run=w7-w6u" -cp "$Classes" com.rot.n.demo.W6Bench $benchRecords
    if ($LASTEXITCODE -ne 0) { throw "W6Bench (unfiltered) failed" }
    & $java "-javaagent:$ProbeAgentJar" "-Drotn.probe.trace=$w6f" "-Drotn.probe.run=w7-w6f" "-Drotn.probe.filter=SPEC" -cp "$Classes" com.rot.n.demo.W6Bench $benchRecords
    if ($LASTEXITCODE -ne 0) { throw "W6Bench (filtered) failed" }
    $uEvents = (Get-Content $w6u | Where-Object { $_.Trim() } |
        ForEach-Object { ($_ | ConvertFrom-Json) } | Where-Object { $_._meta -notin @("rotn-probe-header", "rotn-probe-trailer") }).Count
    $fEvents = (Get-Content $w6f | Where-Object { $_.Trim() } |
        ForEach-Object { ($_ | ConvertFrom-Json) } | Where-Object { $_._meta -notin @("rotn-probe-header", "rotn-probe-trailer") }).Count
    Write-Host ("  unfiltered events = {0}   filtered (SPEC) events = {1}" -f $uEvents, $fEvents)
    if ($fEvents -ne 0) { throw "W6Bench emits only SEND/RECV; SPEC filter must drop all" }
    Write-Host "  SPEC-filtered run records zero transport events -> zero trace cost"

    Write-Host ""
    Write-Host "W7 ALL CHECKS PASS"
}