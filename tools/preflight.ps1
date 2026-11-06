# =============================================================================
# Phase 0 pre-flight gate (ROTN audit Fix 3 / Fix 4).
#
# Verifies the external toolchain + reference material are in place, then
# prints a PASS/FAIL/SKIP table. Exit code 0 if every REQUIRED item PASSES
# (SKIPS allowed); non-zero if any REQUIRED item FAILS.
#
#   1  Rust >= 1.85          (build the Dogwood reference interpreter)
#   2  JDK 17                (TLC engine)
#   3  tla2tools.jar         (TLC engine)
#   4  Dogwood repo clone    (reference interpreter source + full corpus)
#   5  dogwood CLI binary    (the "bridge to reality" oracle)
#   6  AWS CLI v2            SKIPPED — real AgentCore repro is out of scope
#   7  Reference material    (APW-2 Classmethod policies pinned in samples/)
#
# Pure PowerShell; no dependencies. Safe to re-run any time.
# =============================================================================

$ErrorActionPreference = 'SilentlyContinue'
$tools = 'C:\tools'
$repo  = Split-Path $PSScriptRoot -Parent
$rustup = "$env:USERPROFILE\.cargo\bin\rustup.exe"
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$item, [string]$status, [string]$detail) {
    $results.Add([pscustomobject]@{ Item = $item; Status = $status; Detail = $detail })
}

# --- 1. Rust >= 1.85 --------------------------------------------------------
$rustc = (Get-Command rustc -ErrorAction SilentlyContinue)
if (-not $rustc -and (Test-Path "$env:USERPROFILE\.cargo\bin\rustc.exe")) {
    $rustc = [pscustomobject]@{ Source = "$env:USERPROFILE\.cargo\bin\rustc.exe" }
}
if ($rustc) {
    $v = ((& $rustc.Source --version 2>&1) -join ' ').Trim()
    $m = [regex]::Match($v, '(\d+)\.(\d+)')
    if ($m.Success) {
        $major = [int]$m.Groups[1].Value; $minor = [int]$m.Groups[2].Value
        if (($major -gt 1) -or ($major -eq 1 -and $minor -ge 85)) {
            Add-Result 'Rust >= 1.85' 'PASS' $v
        } else {
            Add-Result 'Rust >= 1.85' 'FAIL' $v
        }
    } else { Add-Result 'Rust >= 1.85' 'FAIL' $v }
} else { Add-Result 'Rust >= 1.85' 'FAIL' 'rustc not found' }

# --- 2. JDK 17 --------------------------------------------------------------
# `java -version` writes to stderr; capture via `cmd /c` so it is plain text
# (PowerShell 5.1 would otherwise surface it as a NativeCommandError, which is
# dropped under $ErrorActionPreference='SilentlyContinue').
$javaExe = "$tools\jdk17\bin\java.exe"
if (Test-Path $javaExe) {
    $jv = ((& cmd /c "$javaExe -version 2>&1") -join ' ').Trim()
    if ($jv -match '17') { Add-Result 'JDK 17' 'PASS' $jv }
    else { Add-Result 'JDK 17' 'FAIL' $jv }
} else { Add-Result 'JDK 17' 'FAIL' "missing: $javaExe" }

# --- 3. tla2tools.jar -------------------------------------------------------
$tla = "$tools\tla2tools.jar"
if (Test-Path $tla) {
    $sz = (Get-Item $tla).Length
    if ($sz -gt 1MB) { Add-Result 'tla2tools.jar' 'PASS' ("{0:N0} KB" -f ($sz/1KB)) }
    else { Add-Result 'tla2tools.jar' 'FAIL' ("suspiciously small: {0} B" -f $sz) }
} else { Add-Result 'tla2tools.jar' 'FAIL' "missing: $tla" }

# --- 4. Dogwood repo clone --------------------------------------------------
$dwRepo = "$tools\dogwood"
if (Test-Path "$dwRepo\Cargo.toml") {
    Add-Result 'Dogwood repo clone' 'PASS' $dwRepo
} else { Add-Result 'Dogwood repo clone' 'FAIL' "missing: $dwRepo\Cargo.toml" }

# --- 5. dogwood CLI binary --------------------------------------------------
$bin = $null
foreach ($c in @("$dwRepo\target\debug\dogwood.exe", "$dwRepo\target\release\dogwood.exe")) {
    if (Test-Path $c) { $bin = $c; break }
}
if ($bin) {
    $dv = ((& $bin --version 2>&1) -join ' ').Trim()
    Add-Result 'dogwood CLI binary' 'PASS' $dv
} else { Add-Result 'dogwood CLI binary' 'FAIL' 'not built yet (cargo build -p dogwood-cli)' }

# --- 6. AWS CLI v2 (SKIPPED by decision) -----------------------------------
$aws = (Get-Command aws -ErrorAction SilentlyContinue)
if ($aws) { Add-Result 'AWS CLI v2' 'SKIP' "present: $((($aws.Source))) (not required)" }
else { Add-Result 'AWS CLI v2' 'SKIP' 'not installed (real AgentCore repro out of scope)' }

# --- 7. Reference material --------------------------------------------------
$ref = "$repo\samples\reference"
$refFiles = @(Get-ChildItem -Path $ref -Filter '*.dw' -ErrorAction SilentlyContinue)
if ($refFiles.Count -ge 2) {
    Add-Result 'Reference material' 'PASS' ("{0} .dw files in samples/reference/" -f $refFiles.Count)
} else { Add-Result 'Reference material' 'FAIL' "expected >=2 .dw in $ref" }

# --- Report -----------------------------------------------------------------
Write-Output ''
Write-Output ('Phase 0 pre-flight  (tools: {0})' -f $tools)
Write-Output ('-' * 78)
$results | Format-Table -AutoSize Item, Status, Detail | Out-String | Write-Output
Write-Output ('-' * 78)

$requiredFail = @($results | Where-Object { $_.Status -eq 'FAIL' })
if ($requiredFail.Count -eq 0) {
    Write-Output 'RESULT: PASS  (all required items satisfied)'
    exit 0
} else {
    Write-Output ('RESULT: FAIL  ({0} required item(s) not satisfied)' -f $requiredFail.Count)
    exit 1
}
