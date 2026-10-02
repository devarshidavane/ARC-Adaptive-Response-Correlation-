$path = "src-tauri/target/release/arc-desktop.exe"
$bytes = [System.IO.File]::ReadAllBytes($path)
$latin1 = [System.Text.Encoding]::GetEncoding("iso-8859-1").GetString($bytes)
$terms = @(
    "topology",
    "network",
    "Edge Firewall",
    "Primary DC",
    "Database Cluster",
    "acknowledge_alert",
    "lookup_ioc",
    "get_analytics",
    "get_system_info"
)
foreach ($t in $terms) {
    $idx = $latin1.IndexOf($t, [System.StringComparison]::OrdinalIgnoreCase)
    Write-Output "$t : $idx"
}
