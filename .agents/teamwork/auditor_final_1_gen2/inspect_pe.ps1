$path = 'src-tauri/target/release/arc-desktop.exe'
$bytes = [System.IO.File]::ReadAllBytes($path)
Write-Output ("Total File Size: " + $bytes.Length)

# Check MZ
$mz = [System.Text.Encoding]::ASCII.GetString($bytes[0..1])
Write-Output ("MZ Signature: " + $mz)

# PE offset at 0x3C
$peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
Write-Output ("PE Header Offset: 0x" + $peOffset.ToString("X"))

$peSig = [System.BitConverter]::ToString($bytes[$peOffset..($peOffset+3)])
Write-Output ("PE Signature: " + $peSig)

# Machine at peOffset + 4
$machine = [System.BitConverter]::ToUInt16($bytes, $peOffset + 4)
Write-Output ("Machine Type: 0x" + $machine.ToString("X") + " (AMD64 = 0x8664)")

# Number of sections at peOffset + 6
$numSections = [System.BitConverter]::ToUInt16($bytes, $peOffset + 6)
Write-Output ("Number of Sections: " + $numSections)

# Optional Header Size at peOffset + 20
$optHdrSize = [System.BitConverter]::ToUInt16($bytes, $peOffset + 20)
$optHdrOffset = $peOffset + 24
$magic = [System.BitConverter]::ToUInt16($bytes, $optHdrOffset)
Write-Output ("Optional Header Magic: 0x" + $magic.ToString("X") + " (PE32+ = 0x20B)")

$subsystem = [System.BitConverter]::ToUInt16($bytes, $optHdrOffset + 68)
Write-Output ("Subsystem: 0x" + $subsystem.ToString("X") + " (GUI = 0x2, CUI = 0x3)")

# Sections
$sectionOffset = $optHdrOffset + $optHdrSize
Write-Output "Sections:"
for ($i = 0; $i -lt $numSections; $i++) {
    $secStart = $sectionOffset + ($i * 40)
    $secName = [System.Text.Encoding]::ASCII.GetString($bytes[$secStart..($secStart+7)]).Trim([char]0)
    $vSize = [System.BitConverter]::ToUInt32($bytes, $secStart + 8)
    $rawSize = [System.BitConverter]::ToUInt32($bytes, $secStart + 16)
    Write-Output ("  " + $secName + " - VirtualSize: " + $vSize + " RawSize: " + $rawSize)
}
