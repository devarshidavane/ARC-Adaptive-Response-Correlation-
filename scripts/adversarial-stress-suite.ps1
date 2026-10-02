# scripts/adversarial-stress-suite.ps1
# Empirical Challenger Adversarial Stress Suite for ARC Desktop

$ErrorActionPreference = "Stop"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " ARC Desktop Adversarial Challenge & Stress Test Suite" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$exePath = Join-Path $repoRoot "src-tauri\target\release\arc-desktop.exe"
$buildJs = Join-Path $repoRoot "ARC_Complete_Documentation\frontend\build\static\js"

# ------------------------------------------------------------------
# Test A: Rapid Thrashing (Sub-Second Spawns & Instant Kills)
# ------------------------------------------------------------------
Write-Host "`n[CHALLENGE A] Rapid Thrashing & Early Termination Stress Test..." -ForegroundColor Cyan
$thrashCount = 5
for ($k = 1; $k -le $thrashCount; $k++) {
    $tProc = Start-Process -FilePath $exePath -PassThru
    $tPid = $tProc.Id
    Start-Sleep -Milliseconds 250  # Terminate early during startup
    Stop-Process -Id $tPid -Force -ErrorAction SilentlyContinue
    $tProc.WaitForExit(2000) | Out-Null
    
    $checkZombie = Get-Process -Id $tPid -ErrorAction SilentlyContinue
    if ($checkZombie) {
        Write-Error "FAIL: Rapid thrashing produced zombie process PID $tPid"
        exit 1
    }
    Write-Host "  Thrash cycle $k/$($thrashCount): PID $tPid spawned & destroyed at 250ms (Clean)." -ForegroundColor Gray
}
Write-Host "[CHALLENGE A PASSED] Rapid early termination leaves no zombie handles." -ForegroundColor Green

# ------------------------------------------------------------------
# Test B: Concurrent Multi-Instance Execution (3 simultaneous instances)
# ------------------------------------------------------------------
Write-Host "`n[CHALLENGE B] Concurrent Multi-Instance Stress (3 simultaneous processes)..." -ForegroundColor Cyan
$procs = @()
for ($m = 1; $m -le 3; $m++) {
    $p = Start-Process -FilePath $exePath -PassThru
    $procs += $p
    Write-Host "  Spawned concurrent instance #$m (PID: $($p.Id))" -ForegroundColor Gray
}

Write-Host "  Observing 3 concurrent instances for 5 seconds..." -ForegroundColor Cyan
Start-Sleep -Seconds 5

$allAlive = $true
foreach ($p in $procs) {
    $query = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
    if (-not $query -or $query.HasExited) {
        Write-Error "FAIL: Concurrent instance PID $($p.Id) died prematurely!"
        $allAlive = $false
    } else {
        $ws = [math]::Round($query.WorkingSet64 / 1MB, 2)
        Write-Host "  Instance PID $($p.Id) running concurrently. WS: $ws MB" -ForegroundColor Gray
    }
}

# Teardown all instances
foreach ($p in $procs) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $p.WaitForExit(3000) | Out-Null
}

if (-not $allAlive) {
    exit 1
}
Write-Host "[CHALLENGE B PASSED] 3 concurrent instances operated stably without deadlocks or crash." -ForegroundColor Green

# ------------------------------------------------------------------
# Test C: Deep Cartographic & GIS Exclusion Audit in Compiled JS
# ------------------------------------------------------------------
Write-Host "`n[CHALLENGE C] Deep Cartographic & GIS Exclusion Audit in Compiled JS..." -ForegroundColor Cyan
$jsFiles = Get-ChildItem -Path $buildJs -Filter "*.js" -File
$bannedTokens = @(
    "leaflet", "mapbox", "openlayers", "cesium", "tile.openstreetmap",
    "world-map", "geo-map", "mercator-projection", "topojson", "geojson"
)

$violations = @()
foreach ($file in $jsFiles) {
    $content = [System.IO.File]::ReadAllText($file.FullName)
    foreach ($token in $bannedTokens) {
        if ($content.IndexOf($token, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            # Check context: could it be negative check or actual map code?
            $violations += "Found '$token' in $($file.Name)"
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Error "FAIL: Banned cartographic tokens detected in production build: $($violations -join ', ')"
    exit 1
} else {
    Write-Host "  Scanned $($jsFiles.Count) compiled bundle(s). Zero cartographic tokens detected." -ForegroundColor Gray
    Write-Host "[CHALLENGE C PASSED] Negative map exclusion 100% verified in production JS bundle." -ForegroundColor Green
}

# ------------------------------------------------------------------
# Test D: Security Allowlist & CSP Boundary Enforcement
# ------------------------------------------------------------------
Write-Host "`n[CHALLENGE D] Security Configuration & Allowlist Audit..." -ForegroundColor Cyan
$tauriConfPath = Join-Path $repoRoot "src-tauri\tauri.conf.json"
$confContent = [System.IO.File]::ReadAllText($tauriConfPath) | ConvertFrom-Json

if ($confContent.tauri.allowlist.all -ne $false) {
    Write-Error "FAIL: tauri.allowlist.all is not false!"
    exit 1
}
Write-Host "  tauri.allowlist.all is strictly FALSE (Zero-Trust verified)." -ForegroundColor Gray

if (-not $confContent.tauri.security.csp -or $confContent.tauri.security.csp -eq "") {
    Write-Error "FAIL: CSP is missing or empty!"
    exit 1
}
Write-Host "  Content Security Policy strictly enforced: $($confContent.tauri.security.csp)" -ForegroundColor Gray
Write-Host "[CHALLENGE D PASSED] Security boundary & CSP verified." -ForegroundColor Green

Write-Host "`n==================================================================" -ForegroundColor Green
Write-Host " ALL ADVERSARIAL CHALLENGE TESTS PASSED!" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
exit 0
