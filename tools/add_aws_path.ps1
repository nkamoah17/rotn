# Add the AWS CLI v2 dir to the user PATH (idempotent), then verify the
# repro's common.py resolves both CLIs.
$awsDir = 'C:\Program Files\Amazon\AWSCLIV2'
$cur = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = @()
if ($cur) { $parts = $cur -split ';' | Where-Object { $_ -ne '' } }
if ($parts -notcontains $awsDir) {
    $new = ($parts + $awsDir) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $new, 'User')
    Write-Host 'ADDED to user PATH'
} else {
    Write-Host 'already in user PATH'
}
Write-Host ('user PATH contains AWSCLIV2 : ' + ((([Environment]::GetEnvironmentVariable('Path','User')) -split ';') -contains $awsDir))