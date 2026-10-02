# scripts/test-launch.ps1
# Automated Desktop Executable Launch & Longevity Verification for ARC Desktop

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " ARC Desktop Executable Launch Verification Script" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Locate Compiled Executable
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$candidatePaths = @(
    (Join-Path $repoRoot "src-tauri\target\release\arc-desktop.exe"),
    (Join-Path $repoRoot "src-tauri\target\debug\arc-desktop.exe"),
    (Join-Path $repoRoot "src-tauri\target\release\arc.exe"),
    (Join-Path $repoRoot "src-tauri\target\debug\arc.exe")
)

$exePath = $null
foreach ($path in $candidatePaths) {
    if (Test-Path -Path $path -PathType Leaf) {
        $exePath = $path
        break
    }
}

if (-not $exePath) {
    Write-Error "ERROR: Compiled executable not found. Checked candidate paths:`n$($candidatePaths -join "`n")"
    exit 1
}

$fileItem = Get-Item -Path $exePath
$fileSizeMB = [math]::Round($fileItem.Length / 1MB, 2)
Write-Host "[1/5] Located executable: $exePath" -ForegroundColor Green
Write-Host "      File size: $fileSizeMB MB ($($fileItem.Length) bytes)" -ForegroundColor Gray

# Verify Windows PE Header ("MZ")
$bytes = [System.IO.File]::ReadAllBytes($exePath)[0..1]
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    Write-Error "ERROR: Target file does not have valid Windows PE magic bytes (MZ): $exePath"
    exit 1
}
Write-Host "[2/5] Verified Windows PE binary signature (0x4D 0x5A / 'MZ')." -ForegroundColor Green

# 2. Launch Process in Background
Write-Host "[3/5] Launching desktop application process..." -ForegroundColor Cyan
$process = Start-Process -FilePath $exePath -PassThru

if (-not $process -or $process.Id -le 0) {
    Write-Error "ERROR: Failed to launch process or invalid process ID returned."
    exit 1
}

$procId = $process.Id
Write-Host "      Process launched successfully. Process ID (PID): $procId" -ForegroundColor Green

# 3. Assert Process Longevity (>= 5 seconds without crashing)
$durationSeconds = 6
Write-Host "[4/5] Monitoring process longevity for $durationSeconds seconds..." -ForegroundColor Cyan

$hasCrashed = $false
for ($i = 1; $i -le $durationSeconds; $i++) {
    Start-Sleep -Seconds 1
    
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $proc -or $proc.HasExited) {
        $exitCode = if ($proc) { $proc.ExitCode } else { "Unknown" }
        Write-Error "ERROR: Process (PID: $procId) exited prematurely at second $i with exit code: $exitCode"
        $hasCrashed = $true
        break
    }

    $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
    $title = $proc.MainWindowTitle
    if ([string]::IsNullOrWhiteSpace($title)) {
        $title = "<initializing / background window>"
    }
    Write-Host "      [$i/$durationSeconds s] PID: $procId | WorkingSet: $memMB MB | Window: '$title'" -ForegroundColor Gray
}

if ($hasCrashed) {
    exit 1
}

# 4. Final Health Check before Graceful Termination
$finalProc = Get-Process -Id $procId -ErrorAction SilentlyContinue
if (-not $finalProc -or $finalProc.HasExited) {
    Write-Error "ERROR: Process terminated before completion of the observation window."
    exit 1
}

$finalMemMB = [math]::Round($finalProc.WorkingSet64 / 1MB, 2)
Write-Host "[5/5] Longevity check PASSED (Ran stably for >= 5s, WorkingSet: $finalMemMB MB)." -ForegroundColor Green
Write-Host "      Initiating graceful process termination (Stop-Process -Id $procId)..." -ForegroundColor Cyan

Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
$terminated = $process.WaitForExit(3000)

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " SUCCESS: ARC Desktop executable launched and verified stably." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green

exit 0
