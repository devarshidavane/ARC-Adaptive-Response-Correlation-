$files = @(
    "tests/e2e/tier1_feature_coverage.js",
    "tests/e2e/tier2_boundary_cases.js",
    "tests/e2e/tier3_cross_feature.js",
    "tests/e2e/tier4_real_world_scenarios.js"
)

foreach ($f in $files) {
    Write-Output "=== Auditing $f ==="
    $content = Get-Content -Raw $f
    # match each test block { id: '...', ... async run(...) { ... } }
    $testMatches = [regex]::Matches($content, 'id:\s*[\x27"]([^\x27"]+)[\x27"][\s\S]*?async run\s*\([^)]*\)\s*\{([\s\S]*?)\n\s*\}\s*\},?')
    Write-Output "Found $($testMatches.Count) tests in $f"

    foreach ($m in $testMatches) {
        $id = $m.Groups[1].Value
        $body = $m.Groups[2].Value

        # Check for checks
        $hasCheck = ($body -match 'fs\.' -or $body -match 'readFileSafe' -or $body -match 'readJsonSafe' -or $body -match 'scanDirectory' -or $body -match 'exists\(' -or $body -match 'findDesktopExecutable' -or $body -match 'queryInDomOrSource' -or $body -match 'JSON\.parse' -or $body -match '\.test\(' -or $body -match '\.includes\(' -or $body -match 'if\s*\(')
        
        $hasConditionalFail = ($body -match 'status:\s*[\x27"]FAIL[\x27"]' -or $body -match 'status:\s*ctx\.strict')
        $hasPass = ($body -match 'status:\s*[\x27"]PASS[\x27"]')

        if (-not $hasCheck) {
            Write-Output "  [ALERT - NO CHECK] $id"
        }
        if (-not $hasConditionalFail) {
            Write-Output "  [ALERT - NO FAIL PATH] $id"
        }
    }
}
