$path = 'src-tauri/target/release/arc-desktop.exe'
$bytes = [System.IO.File]::ReadAllBytes($path)

function Search-Bytes ($pattern) {
    $patBytes = [System.Text.Encoding]::UTF8.GetBytes($pattern)
    $found = 0
    for ($i = 0; $i -le $bytes.Length - $patBytes.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $patBytes.Length; $j++) {
            if ($bytes[$i + $j] -ne $patBytes[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            $found++
        }
    }
    return $found
}

$testStrings = @(
    "get_network_topology",
    "get_live_alerts",
    "get_threat_intel_feeds",
    "get_system_info",
    "threat_alert_stream",
    "simulate_alert_event",
    "acknowledge_alert",
    "lookup_ioc",
    "ARC Threat Intelligence",
    "arc-desktop",
    "tauri",
    "Tokio",
    "sysinfo",
    "serde"
)

foreach ($s in $testStrings) {
    $c = Search-Bytes $s
    Write-Output "String '$s' found $c times"
}
