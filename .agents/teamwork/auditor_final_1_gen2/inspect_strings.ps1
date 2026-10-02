$path = 'src-tauri/target/release/arc-desktop.exe'
$bytes = [System.IO.File]::ReadAllBytes($path)
$ascii = [System.Text.Encoding]::ASCII.GetString($bytes)

$patterns = @(
    "rust_begin_unwind",
    "core::fmt",
    "alloc::string::String",
    "tauri",
    "get_network_topology",
    "get_live_alerts",
    "get_threat_intel_feeds",
    "get_system_info",
    "arc_desktop",
    "webview",
    "wry"
)

Write-Output "--- String Search Results in Binary ---"
foreach ($p in $patterns) {
    $found = $ascii.Contains($p)
    $count = 0
    if ($found) {
        # count occurrences
        $matches = [regex]::Matches($ascii, [regex]::Escape($p))
        $count = $matches.Count
    }
    Write-Output "Pattern: '$p' -> Found: $found (Count: $count)"
}

# Check imported DLLs mentioned in binary
Write-Output "`n--- Detected DLL References ---"
$dllMatches = [regex]::Matches($ascii, '(?i)[a-z0-9_\-\.]+\.dll')
$uniqueDlls = $dllMatches | ForEach-Object { $_.Value.ToLower() } | Select-Object -Unique | Sort-Object
$uniqueDlls | ForEach-Object { Write-Output "  DLL: $_" }
