# Installs AWS CLI v2 (MSI, amd64) locally and verifies it.
# Resolves the exact latest asset URL from the GitHub API (the old
# awscli.amazonaws.com URL 404s now).  Safe to re-run: reuses the download.
$ErrorActionPreference = 'Stop'

# 1. Discover the exact latest amd64 MSI asset URL from the GitHub API.
$url = $null
try {
    $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/aws/awscli/releases/latest' -UseBasicParsing
    $asset = $rel.assets | Where-Object { $_.name -match '^awscliv2-windows-amd64(-ssl)?\.msi$' } | Select-Object -First 1
    if ($asset) { $url = $asset.browser_download_url; Write-Host ('Latest asset: ' + $asset.name) }
    else { Write-Host ('no amd64 msi asset found; assets: ' + (($rel.assets | ForEach-Object { $_.name }) -join ', ')) }
} catch {
    Write-Host ('GitHub API lookup failed: ' + $_.Exception.Message)
}
if (-not $url) { $url = 'https://github.com/aws/awscli/releases/latest/download/awscliv2-windows-amd64-ssl.msi' }
Write-Host ('Using URL: ' + $url)

# 2. Download (resume-safe).
$msi = Join-Path $env:TEMP 'awscliv2.msi'
if (Test-Path $msi) { Remove-Item $msi -Force }
Write-Host 'Downloading...'
Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
Write-Host ('Downloaded: ' + (Get-Item $msi).Length + ' bytes')

# 3. Install (machine-wide, quiet).
$log = Join-Path $env:TEMP 'awscli-setup.log'
$args = '/i "{0}" /qn /norestart /l*v "{1}" ALLUSERS=1' -f $msi, $log
$p = Start-Process msiexec.exe -ArgumentList $args -PassThru -Wait
Write-Host ('msiexec exit code: ' + $p.ExitCode)

# 4. Verify.
$cands = @(
    'C:\Program Files\Amazon AWS CLIV2\aws.exe',
    (Join-Path $env:LOCALAPPDATA 'Programs\Amazon AWS CLIV2\aws.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Amazon\AWSCLIV2\aws.exe')
)
$awsExe = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $awsExe) {
    $awsExe = Get-ChildItem 'C:\Program Files\Amazon*','C:\Program Files (x86)\Amazon*',$env:LOCALAPPDATA -Recurse -Filter aws.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}
if ($awsExe) { Write-Host ('FOUND: ' + $awsExe); & $awsExe --version }
else { throw 'aws.exe not found after install; see ' + $log }