# run_tests.ps1 -- W5: compile + run the JUnit tests for the 2PC model + scheduler gate.
#
#   .\run_tests.ps1
#
# Compiles the model + scheduler (build\classes) and the JUnit tests
# (build\test-classes), then runs all W5 test classes via JUnitCore.
# Exits non-zero on any failure. Self-contained: does not depend on build.ps1,
# but is compatible with its output layout.

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSCommandPath                 # ...\ROTN\twopc-java
$Repo = Split-Path -Parent $Root                          # ...\ROTN
$Lib  = Join-Path $Repo "third_party"
$Classes = Join-Path $Root "build\classes"
$TestClasses = Join-Path $Root "build\test-classes"

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

$Jdk = Find-Jdk
$javac = Join-Path $Jdk "bin\javac.exe"
$java  = Join-Path $Jdk "bin\java.exe"
& $javac -version | Out-Host

# --- JUnit + hamcrest ---------------------------------------------------------
$JUnitJar = Get-ChildItem $Lib -Filter "junit-4*.jar" | Select-Object -First 1
$HamcrestJar = Get-ChildItem $Lib -Filter "hamcrest-core-*.jar" | Select-Object -First 1
if (-not $JUnitJar)   { throw "junit jar not found in $Lib" }
if (-not $HamcrestJar) { throw "hamcrest jar not found in $Lib" }
$JUnitCp = "$($JUnitJar.FullName);$($HamcrestJar.FullName)"
Write-Host "[tests] junit     = $($JUnitJar.FullName)"
Write-Host "[tests] hamcrest  = $($HamcrestJar.FullName)"

# --- 1. compile model + scheduler (tests depend on these two packages) --------
Write-Host "[tests] compiling model + scheduler -> build\classes ..."
$srcFiles = @()
foreach ($p in @("src\com\rotn\twopc\*.java", "src\com\rotn\scheduler\*.java")) {
    $srcFiles += (Get-ChildItem (Join-Path $Root $p) -ErrorAction SilentlyContinue).FullName
}
if ($srcFiles.Count -eq 0) { throw "no model sources found under $Root\src" }
New-Item -ItemType Directory -Force -Path $Classes | Out-Null
& $javac --release 8 -d $Classes $srcFiles
if ($LASTEXITCODE -ne 0) { throw "model + scheduler compile failed" }

# --- 2. compile tests ----------------------------------------------------------
Write-Host "[tests] compiling tests -> build\test-classes ..."
$testFiles = (Get-ChildItem (Join-Path $Root "tests") -Recurse -Filter "*.java" | ForEach-Object { $_.FullName })
if ($testFiles.Count -eq 0) { throw "no test sources found under $Root\tests" }
New-Item -ItemType Directory -Force -Path $TestClasses | Out-Null
& $javac --release 8 -cp "$Classes;$JUnitCp" -d $TestClasses $testFiles
if ($LASTEXITCODE -ne 0) { throw "test compile failed" }

# --- 3. run tests ---------------------------------------------------------------
$testCp = "$Classes;$TestClasses;$JUnitCp"
$testClasses = @(
    "com.rot.n.tests.TwoPhaseCommitTest",
    "com.rot.n.tests.NeverRefinesTest",
    "com.rot.n.tests.ScheduleReaderTest",
    "com.rot.n.tests.GateTest",
    "com.rot.n.tests.ReplayTraceTest"
)
Write-Host "[tests] running $($testClasses.Count) test classes ..."
& $java -cp $testCp org.junit.runner.JUnitCore $testClasses
$exit = $LASTEXITCODE
if ($exit -eq 0) { Write-Host "[tests] ALL TESTS PASSED" -ForegroundColor Green }
else { Write-Host "[tests] TESTS FAILED (exit $exit)" -ForegroundColor Red }
exit $exit