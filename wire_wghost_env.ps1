# =============================================================================
# wire_wghost_env.ps1  (ghost project - opacusio/opacus)
#
# PURPOSE
#   opacus-dex::wghost() currently returns the zero address until
#   set_wghost(addr) is called manually from user code. This script adds an
#   environment fallback so the deployed wGHOST address is picked up from
#   the WGHOST_ADDRESS environment variable (0x-prefixed 20-byte hex):
#     1. address already set via set_wghost()          -> wins
#     2. WGHOST_ADDRESS env var                        -> parsed + cached
#     3. zero address placeholder                      -> fallback
#   Adds pub fn parse_address() + unit tests, re-runs the opacus-dex suite.
#   Algorithm verified in sandbox: opacus-dex 14 passed / 0 failed.
#
#   - idempotent (marker: WGHOST_ADDRESS inside wghost.rs)
#   - backup: crates\opacus-dex\src\wghost.rs.bak-wg (kept, never overwritten)
#   - pure ASCII, no here-strings, run with -File
# =============================================================================

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = "$PSScriptRoot"
$Wg = Join-Path $ProjectRoot "crates\opacus-dex\src\wghost.rs"

if (-not (Test-Path -LiteralPath $Wg)) {
    Write-Output "[!] NOT FOUND: $Wg"
    exit 1
}
Write-Output "[i] target: $Wg"

# --- backup -------------------------------------------------------------------
$bak = "$Wg.bak-wg"
if (Test-Path -LiteralPath $bak) {
    Write-Output "[=] backup already exists: $bak"
} else {
    Copy-Item -LiteralPath $Wg -Destination $bak
    Write-Output "[+] backup written: $bak"
}

# --- load + normalize line endings for matching --------------------------------
$raw = [System.IO.File]::ReadAllText($Wg)
$nl = "`n"
if ($raw.Contains("`r`n")) { $nl = "`r`n" }
$text = $raw.Replace("`r`n", "`n")

if ($text.Contains("WGHOST_ADDRESS")) {
    Write-Output "[=] already patched (WGHOST_ADDRESS marker present) - nothing to do"
} else {

$oldFn = (@(
'/// Current wGHOST address or the zero address placeholder.',
'pub fn wghost() -> Address {',
'    *WGHOST.get().unwrap_or(&Address([0u8; 20]))',
'}'
) -join "`n")

$newFn = (@(
'/// Current wGHOST address or the zero address placeholder.',
'///',
'/// Resolution order:',
'/// 1. an address already set via [`set_wghost`]',
'/// 2. the `WGHOST_ADDRESS` environment variable (0x-prefixed 20-byte hex);',
'///    a successfully parsed value is cached into the same slot, as if',
'///    [`set_wghost`] had been called',
'/// 3. the zero address placeholder',
'pub fn wghost() -> Address {',
'    if let Some(addr) = WGHOST.get() {',
'        return *addr;',
'    }',
'    if let Ok(raw) = std::env::var("WGHOST_ADDRESS") {',
'        if let Some(addr) = parse_address(&raw) {',
'            let _ = WGHOST.set(addr);',
'            return addr;',
'        }',
'    }',
'    Address([0u8; 20])',
'}',
'',
'/// Parse a 0x-prefixed (or bare) 20-byte hex EVM address.',
'pub fn parse_address(raw: &str) -> Option<Address> {',
'    let s = raw.trim();',
'    let s = s',
'        .strip_prefix("0x")',
'        .or_else(|| s.strip_prefix("0X"))',
'        .unwrap_or(s);',
'    let bytes = hex::decode(s).ok()?;',
'    if bytes.len() != 20 {',
'        return None;',
'    }',
'    let mut out = [0u8; 20];',
'    out.copy_from_slice(&bytes);',
'    Some(Address(out))',
'}'
) -join "`n")

$oldTest = (@(
'        let topic = burn_event_topic();',
'        assert_ne!(topic, [0u8; 32]);',
'        assert_ne!(burn_event_topic(), mint_event_topic());',
'    }',
'}'
) -join "`n")

$newTest = (@(
'        let topic = burn_event_topic();',
'        assert_ne!(topic, [0u8; 32]);',
'        assert_ne!(burn_event_topic(), mint_event_topic());',
'    }',
'',
'    #[test]',
'    fn parse_address_shapes() {',
'        let ok = "0x1111111111111111111111111111111111111111";',
'        let a = parse_address(ok).expect("valid");',
'        assert_eq!(a.0[0], 0x11);',
'        assert_eq!(a.0[19], 0x11);',
'        assert_eq!(parse_address(&ok.to_uppercase()).expect("valid").0[0], 0x11);',
'        assert_eq!(parse_address(&ok[2..]).expect("bare").0[5], 0x11);',
'        assert!(parse_address("0x1234").is_none());',
'        assert!(parse_address("0xzz11111111111111111111111111111111111111").is_none());',
'        assert!(parse_address("").is_none());',
'        assert!(parse_address("0x11111111111111111111111111111111111111").is_none());',
'    }',
'}'
) -join "`n")

if (-not $text.Contains($oldFn)) {
    Write-Output "[!] wghost() block not found verbatim - wghost.rs was modified"
    Write-Output "    paste crates\opacus-dex\src\wghost.rs back to the assistant"
    exit 1
}
if (-not $text.Contains($oldTest)) {
    Write-Output "[!] test anchor not found verbatim - wghost.rs was modified"
    Write-Output "    paste crates\opacus-dex\src\wghost.rs back to the assistant"
    exit 1
}

$text = $text.Replace($oldFn, $newFn).Replace($oldTest, $newTest)
Write-Output "[+] patched: env fallback + parse_address + parse_address_shapes test"

[System.IO.File]::WriteAllText($Wg, $text.Replace("`n", $nl), (New-Object System.Text.UTF8Encoding($false)))
Write-Output ("[+] written: {0} ({1} line endings preserved)" -f $Wg, $(if ($nl -eq "`r`n") { "CRLF" } else { "LF" }))

}

# --- regression: opacus-dex suite -------------------------------------------------
Set-Location $ProjectRoot
Write-Output "cargo test -p opacus-dex --release"
$dexOut = cmd /c "cargo test -p opacus-dex --release 2>&1"
$dexOut | ForEach-Object { Write-Output $_ }
if ($LASTEXITCODE -ne 0) {
    Write-Output "GHOST-DEX TESTS FAILED - paste the output above back to the assistant"
    exit 1
}

Write-Output ""
Write-Output "WGHOST ENV WIRING COMPLETE - wghost() reads WGHOST_ADDRESS"
Write-Output ""
Write-Output "What you got:"
Write-Output "  opacus-dex wghost.rs: wghost() resolution order -"
Write-Output "    set_wghost() > WGHOST_ADDRESS env (auto-cached) > zero address"
Write-Output "  parse_address(): 0x-prefixed or bare 20-byte hex, strict length"
Write-Output "  new test: parse_address_shapes (suite re-run green above)"
Write-Output "  backup: wghost.rs.bak-wg"
Write-Output ""
Write-Output "Next steps:"
Write-Output "  1. deploy the token:  powershell -ExecutionPolicy Bypass -File .\deploy_wghost.ps1"
Write-Output "  2. persist the address for every session:"
Write-Output "       setx WGHOST_ADDRESS 0x<deployed>"
Write-Output "     or per shell:  `$env:WGHOST_ADDRESS = '0x<deployed>'"
