# coach-example -- coach a buggy spend-cap back in bounds, *with a proof*.
#
# Runs the 5-step coaching loop (Detect -> Explain -> Correct -> Re-check ->
# Close) on the one-word-buggy spend-cap policy and writes the deterministic,
# hashable CoachingArtifact to coaching.json.
#
# Usage:  .\run.ps1 [-MaxInflight <K>]
#
# Exit codes: 0 = closed (the corrected policy re-proved),
#             1 = open   (the correction did not re-prove -- fail-closed),
#             3 = error.
[CmdletBinding()]
param(
    [int]$MaxInflight = 3
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

$policy = Join-Path $PSScriptRoot "spendcap-buggy.dw"
$out    = Join-Path $PSScriptRoot "coaching.json"

python -m rot coach `
    --policy $policy `
    --max-inflight $MaxInflight `
    --out $out

$code = $LASTEXITCODE
if ($code -eq 0) {
    Write-Host "`n  coaching closed: $out"
} elseif ($code -eq 1) {
    Write-Host "`n  coaching OPEN (fail-closed): $out" -ForegroundColor Yellow
} else {
    Write-Host "`n  coaching error (exit $code)" -ForegroundColor Red
}
exit $code