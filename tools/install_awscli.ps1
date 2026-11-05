# Installs AWS CLI v2 (MSI, x86_64) locally and verifies it.
# Safe to re-run: reuses the download if present.
$ErrorActionPreference = 'Stop'

$msi = Join-Path $env:TEMP 'awscliv2.msi'
if (-not (Test-Path $msi)) {
    Write-Host 'Downloading AWS CLI v2 MSI...'
    Invoke-WebRequest -Uri 'https://awscli.amazonaws.com/awscli-exe-windows-x86_64.msi' -OutFile $msi -UseBasicParsing
}
Write-Host ('MSI size: ' + (Get-Item $msi).Length + ' bytes')

$log = Join-Path $env:TEMP 'awscli-setup.log'
$args = '/i "{0}" /qn /norestart /L*ve "{1}"' -f $msi, $log
$p = Start-Process msiexec.exe -ArgumentList $args -PassThru -Wait
Write-Host ('msiexec exit code: ' + $p.ExitCode)

# Verify
$candidates = @(
    'C:\Program Files\Amazon AWS CLIV2\aws.exe',
    (Join-Path $env:LOCALAPPDATA 'Programs\Amazon AWS CLIV2\aws.exe')
)
$awsExe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $awsExe) { throw 'aws.exe not found after install; check ' + $log }
$ver = & $awsExe --version
Write-Host $ver
