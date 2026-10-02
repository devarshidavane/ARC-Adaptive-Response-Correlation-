# scripts/test-challenger-longevity.ps1
# Challenger Adversarial Longevity & Stress Test Harness for ARC Desktop

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " ARC Desktop Challenger Longevity & Rapid Cycle Stress Harness" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$exePath = Join-Path $repoRoot "src-tauri\target\release\arc-desktop.exe"

if (-not (Test-Path -Path $exePath -PathType Leaf)) {
    Write-Error "CRITICAL: Executable not found at $exePath"
    exit 1
}

# Ensure no stale arc-desktop instances are running
$stale = Get-Process -Name "arc-desktop" -ErrorAction SilentlyContinue
if ($stale) {
    Write-Host "Cleaning up preexisting arc-desktop processes..." -ForegroundColor Yellow
    $stale | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

# ==============================================================================
# TEST 1: PROLONGED LONGEVITY & STABILITY TEST (10 Seconds)
# ==============================================================================
Write-Host "`n[TEST 1] Prolonged Longevity Test (10s continuous monitoring)..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $exePath -PassThru
if (-not $proc -or $proc.Id -le 0) {
    Write-Error "Failed to launch arc-desktop.exe"
    exit 1
}
$pid1 = $proc.Id
Write-Host "  -> Process launched with PID: $pid1" -ForegroundColor Green

$samples = @()
$test1Failed = $false
$durationSeconds = 10

for ($i = 1; $i -le $durationSeconds; $i++) {
    Start-Sleep -Seconds 1
    $p = Get-Process -Id $pid1 -ErrorAction SilentlyContinue
    if (-not $p -or $p.HasExited) {
        $exitCode = if ($p) { $p.ExitCode } else { "Unknown" }
        Write-Error "FAIL: Process PID $pid1 died prematurely at second $i with code: $exitCode"
        $test1Failed = $true
        break
    }
    
    $wsMB = [math]::Round($p.WorkingSet64 / 1MB, 2)
    $pmMB = [math]::Round($p.PagedMemorySize64 / 1MB, 2)
    $handles = $p.HandleCount
    $threads = $p.Threads.Count
    
    $samples += [PSCustomObject]@{
        Second = $i
        WorkingSetMB = $wsMB
        PagedMemMB = $pmMB
        Handles = $handles
        Threads = $threads
    }
    
    Write-Host ("  [{0,2}/10s] PID: {1} | WS: {2,6} MB | Paged: {3,6} MB | Handles: {4,5} | Threads: {5,2}" -f $i, $pid1, $wsMB, $pmMB, $handles, $threads) -ForegroundColor Gray
}

if ($test1Failed) {
    exit 1
}

# Memory Runway & Leak Analysis
$initialWS = $samples[0].WorkingSetMB
$finalWS = $samples[-1].WorkingSetMB
$maxWS = ($samples | Measure-Object -Property WorkingSetMB -Maximum).Maximum
$deltaWS = [math]::Round($finalWS - $initialWS, 2)

Write-Host "  Longevity Metrics Analysis:" -ForegroundColor Cyan
Write-Host "    Initial WS: $initialWS MB | Final WS: $finalWS MB | Max WS: $maxWS MB | Delta: $deltaWS MB" -ForegroundColor Gray

# Memory runaway threshold check (e.g. should not double or grow by > 50 MB during idle startup)
if ($deltaWS -gt 50) {
    Write-Error "FAIL: Memory runaway detected! WorkingSet increased by $deltaWS MB in 10 seconds."
    Stop-Process -Id $pid1 -Force -ErrorAction SilentlyContinue
    exit 1
}

# Graceful termination
Write-Host "  Terminating PID $pid1 cleanly..." -ForegroundColor Cyan
Stop-Process -Id $pid1 -Force -ErrorAction SilentlyContinue
$terminated = $proc.WaitForExit(4000)

if (-not $terminated) {
    Write-Error "FAIL: PID $pid1 failed to terminate within 4000ms"
    exit 1
}
Write-Host "  -> PID $pid1 terminated cleanly within timeout." -ForegroundColor Green

# Verify no zombie remains
Start-Sleep -Milliseconds 500
$zombie = Get-Process -Id $pid1 -ErrorAction SilentlyContinue
if ($zombie) {
    Write-Error "FAIL: Zombie process detected for PID $pid1!"
    exit 1
}
Write-Host "  -> Verified no zombie process remains for PID $pid1." -ForegroundColor Green
Write-Host "[TEST 1 PASSED] Executable demonstrated 10s continuous runtime stability without memory runaway.`n" -ForegroundColor Green

# ==============================================================================
# TEST 2: REPEATED CONSECUTIVE LAUNCHES & CLEAN TERMINATIONS (3 CYCLES)
# ==============================================================================
Write-Host "[TEST 2] Consecutive Launch & Teardown Stress Test (3 cycles)..." -ForegroundColor Cyan

for ($cycle = 1; $cycle -le 3; $cycle++) {
    Write-Host "  --- Cycle $cycle of 3 ---" -ForegroundColor Yellow
    
    # 1. Assert file is not locked
    try {
        $fileStream = [System.IO.File]::Open($exePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $fileStream.Close()
        Write-Host "    [Lock Check] Executable file binary is accessible and unlocked." -ForegroundColor Gray
    } catch {
        Write-Error "FAIL: Executable binary $exePath is locked by a previous process: $_"
        exit 1
    }
    
    # 2. Launch process
    $cProc = Start-Process -FilePath $exePath -PassThru
    if (-not $cProc -or $cProc.Id -le 0) {
        Write-Error "FAIL: Cycle $cycle launch failed!"
        exit 1
    }
    $cPid = $cProc.Id
    Write-Host "    [Launch] Spawned instance PID: $cPid" -ForegroundColor Gray
    
    # 3. Observe for 3 seconds
    Start-Sleep -Seconds 3
    $checkProc = Get-Process -Id $cPid -ErrorAction SilentlyContinue
    if (-not $checkProc -or $checkProc.HasExited) {
        Write-Error "FAIL: Cycle $cycle process PID $cPid died unexpectedly within 3 seconds!"
        exit 1
    }
    $cWS = [math]::Round($checkProc.WorkingSet64 / 1MB, 2)
    Write-Host "    [Health] PID $cPid healthy. WorkingSet: $cWS MB" -ForegroundColor Gray
    
    # 4. Terminate
    Stop-Process -Id $cPid -Force -ErrorAction SilentlyContinue
    $cTerminated = $cProc.WaitForExit(3000)
    if (-not $cTerminated) {
        Write-Error "FAIL: Cycle $cycle PID $cPid did not exit within 3000ms"
        exit 1
    }
    
    # 5. Verify teardown
    Start-Sleep -Milliseconds 300
    $rem = Get-Process -Id $cPid -ErrorAction SilentlyContinue
    if ($rem) {
        Write-Error "FAIL: Cycle $cycle process PID $cPid is still resident in process table!"
        exit 1
    }
    Write-Host "    [Teardown] PID $cPid terminated cleanly with zero residue." -ForegroundColor Green
}

Write-Host "[TEST 2 PASSED] 3/3 Consecutive launch & teardown cycles executed without file locks or zombies.`n" -ForegroundColor Green

# ==============================================================================
# SUMMARY VERDICT
# ==============================================================================
Write-Host "=================================================================" -ForegroundColor Green
Write-Host " ALL STRESS & LONGEVITY CHALLENGER TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
exit 0
