$bytes = [System.IO.File]::ReadAllBytes('src-tauri/target/release/arc-desktop.exe')
function Dump-Region($start, $len) {
    $slice = New-Object byte[] $len
    [Array]::Copy($bytes, $start, $slice, 0, $len)
    $text = [System.Text.Encoding]::ASCII.GetString($slice)
    $clean = $text -replace '[^\x20-\x7E]', "`n"
    $lines = $clean -split "`n" | Where-Object { $_.Trim().Length -ge 4 }
    $lines | ForEach-Object { Write-Output "[$start] $_" }
}

Write-Output "--- Region 1221000..1222000 ---"
Dump-Region 1221000 1000

Write-Output "`n--- Region 1231000..1234000 ---"
Dump-Region 1231000 3000
