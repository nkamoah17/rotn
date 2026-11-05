$ErrorActionPreference = 'Continue'
$h = 'bedrock-agentcore-control.us-east-1.amazonaws.com'

Write-Host '=== 1. DNS resolution ==='
try {
    $r = Resolve-DnsName $h -ErrorAction Stop
    $r | Where-Object { $_.RecordType -eq 'A' -or $_.RecordType -eq 'CNAME' } |
        Select-Object Name, RecordType, IPAddress, TargetHost | Format-Table -AutoSize | Out-String | Write-Host
    if (-not $r) { Write-Host 'NO DNS RECORDS RETURNED' }
} catch {
    Write-Host ('DNS FAIL: ' + $_.Exception.Message)
}

Write-Host '=== 2. TCP 443 connectivity ==='
try {
    $t = Test-NetConnection $h -Port 443 -WarningAction SilentlyContinue
    Write-Host ('TcpTestSucceeded = ' + $t.TcpTestSucceeded)
    Write-Host ('RemoteAddress    = ' + $t.RemoteAddress)
} catch {
    Write-Host ('TCP FAIL: ' + $_.Exception.Message)
}

Write-Host '=== 3. Proxy environment (process) ==='
Write-Host ('HTTP_PROXY   = ' + [Environment]::GetEnvironmentVariable('HTTP_PROXY','Process'))
Write-Host ('HTTPS_PROXY  = ' + [Environment]::GetEnvironmentVariable('HTTPS_PROXY','Process'))
Write-Host ('NO_PROXY     = ' + [Environment]::GetEnvironmentVariable('NO_PROXY','Process'))
Write-Host ('AWS_HTTP_PROXY   = ' + [Environment]::GetEnvironmentVariable('AWS_HTTP_PROXY','Process'))
Write-Host ('AWS_HTTPS_PROXY  = ' + [Environment]::GetEnvironmentVariable('AWS_HTTPS_PROXY','Process'))

Write-Host '=== 4. Proxy environment (user/machine) ==='
Write-Host ('user  HTTPS_PROXY = ' + [Environment]::GetEnvironmentVariable('HTTPS_PROXY','User'))
Write-Host ('mach  HTTPS_PROXY = ' + [Environment]::GetEnvironmentVariable('HTTPS_PROXY','Machine'))

Write-Host '=== 5. Direct HTTPS to endpoint (HEAD) ==='
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = Invoke-WebRequest -Uri ('https://' + $h + '/') -Method Head -UseBasicParsing -TimeoutSec 15
    Write-Host ('HTTP ' + $resp.StatusCode + ' in ' + $sw.ElapsedMilliseconds + 'ms')
} catch {
    $sw = [System.Diagnostics.Stopwatch]::Stopwatch()
    Write-Host ('HTTPS FAIL: ' + $_.Exception.Message)
    if ($_.Exception.InnerException) { Write-Host ('  INNER: ' + $_.Exception.InnerException.Message) }
}

Write-Host '=== 6. Sanity: can we reach a known-good AWS host? ==='
try {
    $t2 = Test-NetConnection 'sts.amazonaws.com' -Port 443 -WarningAction SilentlyContinue
    Write-Host ('sts.amazonaws.com:443 TcpTestSucceeded = ' + $t2.TcpTestSucceeded)
} catch {
    Write-Host ('sts TCP FAIL: ' + $_.Exception.Message)
}