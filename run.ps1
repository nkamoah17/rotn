#requires -Version 3.0
<#
.SYNOPSIS
    ROTN verification runner (2PC + ZAB) -- a thin PowerShell wrapper over pipeline.py.

.DESCRIPTION
    Three modes:

      Single run : .\run.ps1 -Target buggy   -Property agreement -Engine tlc
                   .\run.ps1 -Target correct -Property validity  -Engine auto
      List       : .\run.ps1 -List
      Matrix     : .\run.ps1 -Matrix -Engine auto
                   (runs every registered target x every registered invariant
                    and prints a verdict grid)

    The pipeline's exit code is propagated to $LASTEXITCODE / the script exit:
      0 = proven   1 = violated   2 = unknown   3 = error

    Engine:
      auto     -> TLC when a tla2tools.jar + java are present, else symbolic
      tlc      -> the real TLC model checker (requires java + the jar)
      symbolic -> the pure-Python SAT engine (offline, deterministic)
      apalache -> RESERVED (WP2 pending): accepted so it is a *known* value, but
                   NOT implemented yet. run.ps1 handles it gracefully -- a clear
                   message + exit 2 in single-run mode, a NOT_IMPL column in
                   matrix mode -- instead of passing it to pipeline.py, whose
                   argparse choices would reject it with a confusing error.

    Matrix engine:
      -Engines takes a comma-separated list (default "symbolic"). Use
      "symbolic,tlc" to cross-check both engines across every target x
      invariant and emit per-cell artifacts for CI:
        out/matrix.csv  (machine-readable; one row per target x property x engine)
        out/matrix.md   (human-readable pivoted Markdown table)

.PARAMETER Target
    Registered target name (default: correct). See -List for available targets.

.PARAMETER Property
    Invariant to pin (default: agreement). See -List for available properties.

.PARAMETER Engine
    One of: auto, tlc, symbolic (default: auto). apalache is a reserved
    placeholder for WP2 (not implemented yet): selecting it exits cleanly with
    a clear "not implemented" message rather than running.

.PARAMETER Engines
    Engine list for -Matrix mode (a PowerShell string array; default "symbolic").
    Pass comma-separated: -Engines symbolic,tlc to cross-check both engines.

.PARAMETER N
    Number of 2PC participants (default: 3).

.PARAMETER MaxStates
    State-space budget (0 = pipeline default of 200000).

.PARAMETER CegarMaxIter
    CEGAR refinement cap (0 = pipeline default of 6).

.PARAMETER Out
    Output directory for the JSON + Markdown report (default: out).

.PARAMETER TlcJar
    Explicit path to tla2tools.jar (overrides env / local Toolbox lookup).

.EXAMPLE
    .\run.ps1 -Target buggy -Property agreement -Engine symbolic

.EXAMPLE
    # Cross-check both engines across every target x invariant (CI gate).
    .\run.ps1 -Matrix -Engines symbolic,tlc
#>
[CmdletBinding()]
param(
    [string]$Target   = "correct",
    [string]$Property = "agreement",
    # apalache stays in the set (a reserved WP2 placeholder) so `-Engine
    # apalache` is *recognised* and handled gracefully below, not rejected as a
    # PowerShell parameter-binding error. See Test-ReservedEngine.
    [ValidateSet("auto", "tlc", "symbolic", "apalache")][string]$Engine = "auto",
    [string]$Engines = "symbolic",
    [int]$N            = 3,
    [int]$MaxStates    = 0,
    [int]$CegarMaxIter = 0,
    [string]$Out       = "out",
    [string]$TlcJar    = $null,
    [switch]$List,
    [switch]$Matrix
)

$ErrorActionPreference = "Continue"

# Always run from the repo root so `import rot...` and `pipeline.py` resolve.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

# Locate a Python interpreter.
if (Get-Command "python" -ErrorAction SilentlyContinue) { $py = "python" }
elseif (Get-Command "py" -ErrorAction SilentlyContinue) { $py = "py" }
else { Write-Error "Python interpreter not found on PATH."; exit 3 }

# ---- engine registry -------------------------------------------------------
# Engines pipeline.py actually accepts (argparse choices: auto|tlc|symbolic).
# `apalache` is a reserved placeholder for WP2 (Apalache integration). It stays
# in the -Engine ValidateSet so it is *recognised* (not a binding error), but
# run.ps1 intercepts it BEFORE calling pipeline.py -- which would otherwise fail
# with a confusing "invalid choice" argparse error -- and reports it clearly.
$SupportedEngines = @("auto", "tlc", "symbolic")
$ReservedEngines  = @("apalache")
$ReservedMarker   = "NOT_IMPL"

function Test-ReservedEngine {
    param([string]$e)
    return ($null -ne $e -and $ReservedEngines -contains $e.ToLower())
}

function ConvertTo-MatrixMarkdown {
    <#
    .SYNOPSIS
        Pivot the flat matrix rows (target,property,engine,status) into a
        readable Markdown table with one column per engine.
    #>
    param([string[]]$engineList, [string[]]$csvDataLines, [int]$n)

    $order = New-Object System.Collections.ArrayList
    $cells = @{}
    foreach ($line in $csvDataLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $f = @(($line -split '","') | ForEach-Object { $_ -replace '^"','' -replace '"$','' })
        if ($f.Count -ne 4) { continue }
        $key = ($f[0] + "|" + $f[1])
        if (-not $cells.ContainsKey($key)) { $cells[$key] = @{}; [void]$order.Add($key) }
        $cells[$key][$f[2]] = $f[3]
    }

    $md = New-Object System.Collections.ArrayList
    [void]$md.Add("# ROTN Verification Matrix")
    [void]$md.Add("")
    [void]$md.Add(("Participants (n): {0}" -f $n))
    [void]$md.Add(("Engines: {0}" -f ($engineList -join ", ")))
    [void]$md.Add("")
    $hdr = "| target | property |"
    $sep = "| --- | --- |"
    foreach ($e in $engineList) { $hdr += (" {0} |" -f $e); $sep += " --- |" }
    [void]$md.Add($hdr)
    [void]$md.Add($sep)
    foreach ($key in $order) {
        $kp = $key -split '\|', 2
        $row = ("| {0} | {1} |" -f $kp[0], $kp[1])
        foreach ($e in $engineList) {
            $st = "n/a"
            if ($cells[$key].ContainsKey($e)) { $st = $cells[$key][$e] }
            $row += (" {0} |" -f $st)
        }
        [void]$md.Add($row)
    }
    [void]$md.Add("")
    [void]$md.Add("Legend: PROVEN=0  VIOLATED=1  UNKNOWN=2  ERROR=3  NOT_IMPL=reserved, not yet implemented (WP2).")
    return $md
}

function Build-Args {
    param([string]$t, [string]$p, [bool]$quiet, [string]$eng = $null)
    if (-not $eng) { $eng = $Engine }
    $a = @("pipeline.py", $t, "--property", $p, "--engine", $eng,
           "--n", [string]$N, "--out", $Out)
    if ($quiet)           { $a += "--quiet" }
    if ($MaxStates -gt 0) { $a += @("--max-states", [string]$MaxStates) }
    if ($CegarMaxIter -gt 0) { $a += @("--cegar-max-iter", [string]$CegarMaxIter) }
    if ($TlcJar)          { $a += @("--tlc-jar", $TlcJar) }
    return $a
}

function Code-To-Status {
    param([int]$code)
    switch ($code) {
        0       { return "PROVEN" }
        1       { return "VIOLATED" }
        2       { return "UNKNOWN" }
        default { return "ERROR" }
    }
}

# ---- mode: list ------------------------------------------------------------
if ($List) {
    & $py "pipeline.py" "--list"
    exit $LASTEXITCODE
}

# ---- mode: matrix ----------------------------------------------------------
if ($Matrix) {
    # Per-target invariant sets (ZAB targets expose different invariants than 2PC).
    $targets = (& $py -c "import rot.targets as t; print(' '.join(t.names()))" |
        Out-String).Trim() -split "\s+"
    $propFor = @{}
    foreach ($t in $targets) {
        $propFor[$t] = (& $py -c "import rot.targets as t; print(' '.join(t.list_properties('$t')))" |
            Out-String).Trim() -split "\s+"
    }

    # Resolve the engine list. Two gotchas handled here:
    #   1. PowerShell is case-insensitive, so a local $engines would collide
    #      with the $Engines parameter -- we use $engineList instead.
    #   2. The invoking shell may mangle the separator (comma/space/none), so
    #      we detect engine names as substrings rather than splitting.
    # Also honours the "all"/"both" shorthand for "symbolic,tlc".
    $engSpec = "$Engines".ToLower()
    $engineList = New-Object System.Collections.ArrayList
    if ($engSpec -match 'all' -and $engSpec -notmatch 'symbolic' -and $engSpec -notmatch 'tlc') {
        [void]$engineList.Add("symbolic")
        [void]$engineList.Add("tlc")
    } else {
        if ($engSpec -match 'symbolic') { [void]$engineList.Add("symbolic") }
        if ($engSpec -match 'tlc')      { [void]$engineList.Add("tlc") }
        if ($engSpec -match 'apalache') { [void]$engineList.Add("apalache") }
    }
    if ($engineList.Count -eq 0) { [void]$engineList.Add("symbolic") }
    $engineList = @($engineList)
    $colW = 12
    $csvLines = @("target,property,engine,status")
    Write-Host ("ROTn verification matrix   (n={0})" -f $N)
    $hdr = ("target".PadRight(13) + "property".PadRight(24))
    foreach ($e in $engineList) { $hdr += $e.PadRight($colW) }
    Write-Host $hdr.TrimEnd()
    Write-Host ("-" * $hdr.Length)

    $anyError = 0
    foreach ($t in $targets) {
        foreach ($p in $propFor[$t]) {
            $row = $t.PadRight(13) + $p.PadRight(24)
            foreach ($e in $engineList) {
                if (Test-ReservedEngine $e) {
                    # Reserved (WP2): do NOT call pipeline.py (argparse would
                    # reject it). Record a clear marker in the grid / CSV / MD.
                    $status = $ReservedMarker
                    $row += $status.PadRight($colW)
                    $csvLines += ('"{0}","{1}","{2}","{3}"' -f $t, $p, $e, $status)
                    continue
                }
                $args = Build-Args -t $t -p $p -quiet $true -eng $e
                $res = & $py @args 2>&1
                $code = $LASTEXITCODE
                if ($code -ge 3) {
                    $anyError = 1
                    Write-Host ("  [{0} / {1} / {2}]" -f $t, $p, $e)
                    $res | ForEach-Object { Write-Host ("    " + $_) }
                }
                $status = Code-To-Status -code $code
                $row += $status.PadRight($colW)
                $csvLines += ('"{0}","{1}","{2}","{3}"' -f $t, $p, $e, $status)
            }
            Write-Host $row.TrimEnd()
        }
    }
    Write-Host ("-" * $hdr.Length)
    Write-Host "legend: PROVEN=0   VIOLATED=1   UNKNOWN=2   ERROR=3   NOT_IMPL=reserved (WP2)"
    # Per-cell CSV for CI (out/matrix.csv) + a readable Markdown matrix
    # (out/matrix.md), both written from the same per-cell rows.
    $outDir = Join-Path $here $Out
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
    $csvPath = Join-Path $outDir "matrix.csv"
    $csvLines | Set-Content -Path $csvPath -Encoding utf8
    Write-Host ("wrote {0}" -f $csvPath)

    # Human-readable Markdown matrix (out/matrix.md), pivoted from the CSV rows.
    $dataLines = @()
    if ($csvLines.Count -gt 1) { $dataLines = @($csvLines[1..($csvLines.Count - 1)]) }
    $mdPath = Join-Path $outDir "matrix.md"
    $md = ConvertTo-MatrixMarkdown -engineList $engineList -csvDataLines $dataLines -n $N
    $md | Set-Content -Path $mdPath -Encoding utf8
    Write-Host ("wrote {0}" -f $mdPath)

    exit $anyError
}

# ---- mode: single run ------------------------------------------------------
if (Test-ReservedEngine $Engine) {
    Write-Host ("Engine '{0}' is RESERVED (WP2 pending) and not implemented yet." -f $Engine)
    Write-Host ("Available engines: {0}." -f ($SupportedEngines -join ", "))
    Write-Host "No verdict was produced. (exit 2 = UNKNOWN)"
    exit 2
}
$args = Build-Args -t $Target -p $Property -quiet $false
& $py @args
exit $LASTEXITCODE
