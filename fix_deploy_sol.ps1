# =============================================================================
# fix_deploy_sol.ps1  (ghost project - opacusio/opacus)
#
# FIX FOR: deploy_wghost.ps1 crash at line 163, during STEP 2:
#   Test-Path : "path contains invalid characters"
#   if (-not (Test-Path -LiteralPath $bakSol)) { Copy-Item -LiteralPath $Sol ...
#
# ROOT CAUSE (script bug, zero cargo/forge involvement)
#   PowerShell variable names are CASE-INSENSITIVE. deploy_wghost.ps1 used:
#     line 31:  $Sol = Join-Path $Contracts "wGHOST.sol"   <- the PATH
#     line 93:  $sol = $raw.Replace("`r`n", "`n")          <- the FILE CONTENT
#   -> line 93 silently OVERWRITES the path variable with the whole file
#      text. Line 162 then builds   $bakSol = "<whole file text>.bak-sol"
#      and line 163 Test-Path aborts on the invalid path characters.
#   The crash hit BEFORE Copy-Item/WriteAllText, so nothing was written:
#   contracts\wGHOST.sol on disk is still the original unpatched file and
#   no garbage .bak-sol file was created. A clean re-run is safe.
#
# FIX
#   Rename the content variable $sol -> $solText (6 lines, 7 tokens).
#   $Sol keeps the path everywhere; lines 162-163 stay byte-identical.
#   STEP 3-5 (forge build/test/deploy) are not touched: the
#   `--constructor-args [0xAddr] 1` form was already rehearsed end-to-end
#   on a local anvil chain with foundry 1.8.5 (5/5 tests, broadcast ok).
#
#   - pure ASCII, no here-strings, no native calls, run with -File
# =============================================================================

$ErrorActionPreference = "Stop"

$Target = "$PSScriptRoot\deploy_wghost.ps1"
$Bak    = "$Target.bak-solfix1"

if (-not (Test-Path -LiteralPath $Target)) {
    Write-Output "[!] NOT FOUND: $Target"
    exit 1
}

$bytes  = [System.IO.File]::ReadAllBytes($Target)
$hadBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)
$text   = [System.Text.Encoding]::UTF8.GetString($bytes)
if ($hadBom) { $text = $text.Substring(1) }

if ($text.Contains('solText')) {
    Write-Output "[=] deploy_wghost.ps1 already fixed (solText marker present) - nothing to do"
    exit 0
}

# --- exact replacements: pattern -> replacement, expected occurrence count -----
$rules = @(
    @('$sol = $raw.Replace(',   '$solText = $raw.Replace(',     1),
    @('$sol.Contains(',         '$solText.Contains(',           3),
    @('$sol = $sol.Replace(',   '$solText = $solText.Replace(', 1),
    @('$Sol, $sol.Replace(',    '$Sol, $solText.Replace(',      1)
)

$total = 0
foreach ($r in $rules) {
    $old  = $r[0]
    $new  = $r[1]
    $want = $r[2]
    $cnt = [regex]::Matches($text, [regex]::Escape($old)).Count
    if ($cnt -ne $want) {
        Write-Output ("[!] pattern {0} found {1} time(s), expected {2} - file drift, no write" -f $old, $cnt, $want)
        Write-Output "    paste deploy_wghost.ps1 back to the assistant"
        exit 1
    }
    $text = $text.Replace($old, $new)
    $total = $total + $cnt
}

# --- post-checks (abort without write on any mismatch) --------------------------
$left = [regex]::Matches($text, '\$sol\b').Count
if ($left -ne 0) {
    Write-Output ("[!] {0} raw `$sol token(s) still present - aborting, no write" -f $left)
    exit 1
}
$toks = [regex]::Matches($text, '\$solText\b').Count
if ($toks -ne 7) {
    Write-Output ("[!] `$solText token count is {0}, expected 7 - aborting, no write" -f $toks)
    exit 1
}
if (-not $text.Contains('$bakSol = "$Sol.bak-sol"')) {
    Write-Output "[!] backup path line vanished - aborting, no write"
    exit 1
}

if (-not (Test-Path -LiteralPath $Bak)) { Copy-Item -LiteralPath $Target -Destination $Bak }
$enc = New-Object System.Text.UTF8Encoding($hadBom)
[System.IO.File]::WriteAllText($Target, $text, $enc)

Write-Output ("  [+] patched: {0}" -f $Target)
Write-Output ("  [+] backup:  {0}" -f $Bak)
Write-Output '  [+] renamed 7 $sol tokens -> $solText on 6 lines ($Sol keeps the path)'
Write-Output ""
Write-Output "DEPLOY_WGHOST SOLVAR FIX COMPLETE"
Write-Output ""
Write-Output "What you got:"
Write-Output '  $sol (file content) no longer shadows $Sol (file path): PS is case-insensitive,'
Write-Output '  so line 93 used to overwrite the path and line 162 built $bakSol from file text.'
Write-Output "  Nothing else changed: patch pack, test suite, foundry.toml, deploy gate."
Write-Output "  contracts\wGHOST.sol was never touched by the failed run - no cleanup needed."
Write-Output ""
Write-Output "Next steps:"
Write-Output "  re-run: powershell -ExecutionPolicy Bypass -File .\deploy_wghost.ps1"
Write-Output "  STEP 2: patches wGHOST.sol (A/B/C) + backup .bak-sol + writes test suite"
Write-Output "  STEP 3/4: forge build + 5/5 tests (first build downloads solc 0.8.24)"
Write-Output "  STEP 5: without env vars = BUILD-ONLY; to deploy on Sepolia (throwaway key!):"
Write-Output '    $env:SEPOLIA_RPC_URL = "https://<provider>/v3/<key>"'
Write-Output '    $env:DEPLOYER_PRIVATE_KEY = "0x..."'
Write-Output "  after deploy: setx WGHOST_ADDRESS <addr>, then run wire_wghost_env.ps1"
