# =====================================================================
# fix_bridge_toml.ps1
# Ghost project - repair crates\opacus-bridge\Cargo.toml after
# add_bridge_dex.ps1:
#
#   error: cannot extend value of type inline table with a dotted key
#     --> crates\opacus-bridge\Cargo.toml:14:1
#      |
#   14 | serde.workspace = true
#      | ^^^^^
#
# Root cause: add_bridge_dex.ps1 inserted value-style deps
#   serde = { version = "1", features = ["derive"] }
#   serde_json = "1" ...
# right after [dependencies], while this manifest declares deps via
# workspace inheritance (serde.workspace = true). TOML forbids declaring
# the same dependency twice in one section, whichever pair collides:
#   inline table first + dotted later -> "cannot extend value of type
#                                        inline table with a dotted key"
#   plain string first + dotted later -> "Cannot overwrite a value"
#
# What this script does (idempotent, touches ONLY the bridge manifest):
#   R1 drops dotted  X.* = ...  lines whose base X is already defined by
#      an earlier value line in the same section
#   R2 drops duplicate dotted lines
#   R3 drops duplicate value defs (keeps the first)
#   R4 replaces  X.workspace = true  with a concrete tested spec when the
#      root workspace does NOT define X (known crates only, else warning)
#   R5 ensures all 5 bridge deps exist: curve25519-dalek, blake3, hex,
#      serde, serde_json (adds any missing one)
# Then re-runs both test suites:
#   cargo test -p opacus-bridge --release
#   cargo test -p opacus-dex --release
# Backup: crates\opacus-bridge\Cargo.toml.bak-toml
# =====================================================================

$ErrorActionPreference = "Stop"

# ---- adjust if your project lives elsewhere ----
$ProjectRoot = "$PSScriptRoot"
$tomlPath = Join-Path $ProjectRoot "crates\opacus-bridge\Cargo.toml"
$rootToml = Join-Path $ProjectRoot "Cargo.toml"

Write-Host "=== Ghost: fix opacus-bridge Cargo.toml (dotted-key conflict) ===" -ForegroundColor Cyan

if (!(Test-Path $tomlPath)) {
    Write-Host "ERROR: $tomlPath not found." -ForegroundColor Red
    exit 1
}
if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found in PATH." -ForegroundColor Red
    exit 1
}

# ---- backup ----
Copy-Item $tomlPath "$tomlPath.bak-toml" -Force
Write-Host "  backup -> crates\opacus-bridge\Cargo.toml.bak-toml"

$lines = [System.IO.File]::ReadAllLines($tomlPath)

Write-Host ""
Write-Host "=== BEFORE ==="
$i = 0
foreach ($ln in $lines) { $i++; Write-Host ("{0,3}: {1}" -f $i, $ln) }

# ---- root workspace keys ([workspace.dependencies] + [workspace.package]) ----
$wsKeys = New-Object 'System.Collections.Generic.HashSet[string]'
if (Test-Path $rootToml) {
    $section = ""
    foreach ($ln in [System.IO.File]::ReadAllLines($rootToml)) {
        if ($ln -match '^\s*\[([^\]]+)\]\s*$') { $section = $Matches[1].Trim(); continue }
        if ($section -eq "workspace.dependencies" -or $section -eq "workspace.package") {
            if ($ln -match '^\s*([A-Za-z0-9_\-]+)\s*=') { [void]$wsKeys.Add($Matches[1]) }
        }
    }
}
Write-Host ""
Write-Host ("  root workspace keys: " + (($wsKeys | Sort-Object) -join ", "))

# ---- specs verified in sandbox (bridge-dex-1: opacus-bridge 15 passed) ----
$KnownSpec = @{
    "serde"            = 'serde = { version = "1", features = ["derive"] }'
    "serde_json"       = 'serde_json = "1"'
    "hex"              = 'hex = "0.4"'
    "blake3"           = 'blake3 = "1"'
    "curve25519-dalek" = 'curve25519-dalek = { version = "4", features = ["rand_core"] }'
    "anyhow"           = 'anyhow = "1"'
    "thiserror"        = 'thiserror = "1"'
    "tokio"            = 'tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "net"] }'
    "rand"             = 'rand = "0.8"'
    "rand_core"        = 'rand_core = { version = "0.6", features = ["getrandom"] }'
    "sha2"             = 'sha2 = "0.10"'
    "sha3"             = 'sha3 = "0.10"'
    "once_cell"        = 'once_cell = "1"'
    "subtle"           = 'subtle = "2"'
    "zeroize"          = 'zeroize = "1"'
    "futures"          = 'futures = "0.3"'
}

# ---- classify a manifest line ----
# dotted: X.<sub> = ...   |   value: X = ...   |   $null: everything else
function Classify([string]$ln) {
    if ($ln -match '^\s*([A-Za-z0-9_\-]+)\.([A-Za-z0-9_\-]+)\s*=') {
        return @{ kind = "dotted"; base = $Matches[1]; sub = $Matches[2] }
    }
    if ($ln -match '^\s*([A-Za-z0-9_\-]+)\s*=') {
        return @{ kind = "value"; base = $Matches[1]; sub = "" }
    }
    return $null
}

# ---- pass 1: FIRST def (value or dotted) per "section|base" ----
$firstDef = @{}
$section = ""
for ($i = 0; $i -lt $lines.Count; $i++) {
    $ln = $lines[$i]
    if ($ln -match '^\s*\[([^\]]+)\]\s*$') { $section = $Matches[1].Trim(); continue }
    $c = Classify $ln
    if ($c -ne $null) {
        $key = $section + "|" + $c["base"]
        if (!$firstDef.ContainsKey($key)) { $firstDef[$key] = "$i|" + $c["kind"] }
    }
}

# ---- pass 2: rewrite ----
$section = ""
$out = New-Object 'System.Collections.Generic.List[string]'
$removed = New-Object 'System.Collections.Generic.List[string]'
$replaced = New-Object 'System.Collections.Generic.List[string]'
$warnings = New-Object 'System.Collections.Generic.List[string]'
$seenDotted = New-Object 'System.Collections.Generic.HashSet[string]'

for ($i = 0; $i -lt $lines.Count; $i++) {
    $ln = $lines[$i]
    if ($ln -match '^\s*\[([^\]]+)\]\s*$') { $section = $Matches[1].Trim(); $out.Add($ln); continue }
    $c = Classify $ln
    if ($c -ne $null) {
        $kind = $c["kind"]; $base = $c["base"]; $sub = $c["sub"]
        $key = $section + "|" + $base
        $isFirst = $true
        $firstKind = "value"
        if ($firstDef.ContainsKey($key)) {
            $parts = $firstDef[$key] -split '\|'
            if ([int]$parts[0] -ne $i) { $isFirst = $false }
            $firstKind = $parts[1]
        }
        if (!$isFirst) {
            # a definition of base already exists earlier in this section
            if ($kind -eq "dotted") {
                if ($firstKind -eq "dotted") {
                    # R2: exact duplicate dotted line
                    $sig = $section + "|" + $ln.Trim()
                    if ($seenDotted.Contains($sig)) {
                        [void]$removed.Add($ln.Trim() + "   # duplicate")
                        continue
                    }
                    # different dotted sub-keys accumulate legally -> keep
                    [void]$seenDotted.Add($sig)
                    $out.Add($ln)
                    continue
                }
                # R1: value def earlier + dotted now -> drop dotted line
                [void]$removed.Add($ln.Trim())
                continue
            } else {
                # R3: duplicate value def (or value def after dotted) -> keep first
                if ($firstKind -eq "dotted") {
                    [void]$warnings.Add("dropped later value def after dotted inheritance: " + $ln.Trim())
                } else {
                    [void]$removed.Add($ln.Trim() + "   # duplicate")
                }
                continue
            }
        }
        # first definition of base in this section
        if ($kind -eq "dotted") {
            # R4: unresolvable workspace inheritance
            if ($sub -eq "workspace" -and !$wsKeys.Contains($base)) {
                if ($KnownSpec.ContainsKey($base)) {
                    [void]$replaced.Add($ln.Trim() + "  ->  " + $KnownSpec[$base])
                    $out.Add($KnownSpec[$base])
                    continue
                }
                [void]$warnings.Add("unresolved workspace inheritance kept: " + $ln.Trim())
            }
        }
        $out.Add($ln)
        continue
    }
    $out.Add($ln)
}

# ---- R5: ensure the 5 bridge deps are declared ----
$required = @("curve25519-dalek", "blake3", "hex", "serde", "serde_json")
$missing = New-Object 'System.Collections.Generic.List[string]'
foreach ($n in $required) {
    $declared = $false
    foreach ($ln in $out) {
        if ($ln -match ('^\s*' + [regex]::Escape($n) + '\s*=')) { $declared = $true; break }
        if ($ln -match ('^\s*' + [regex]::Escape($n) + '\.workspace\s*=') -and $wsKeys.Contains($n)) { $declared = $true; break }
    }
    if (!$declared) { [void]$missing.Add($n) }
}
$addedMissing = $false
if ($missing.Count -gt 0) {
    $out2 = New-Object 'System.Collections.Generic.List[string]'
    $inserted = $false
    foreach ($ln in $out) {
        $out2.Add($ln)
        if (!$inserted -and $ln -match '^\s*\[dependencies\]\s*$') {
            foreach ($n in $missing) { $out2.Add($KnownSpec[$n]) }
            $inserted = $true
        }
    }
    if (!$inserted) {
        $out2.Add("")
        $out2.Add("[dependencies]")
        foreach ($n in $missing) { $out2.Add($KnownSpec[$n]) }
    }
    $out = $out2
    $addedMissing = $true
    Write-Host ""
    Write-Host ("  R5: added missing deps: " + ($missing -join ", ")) -ForegroundColor Yellow
}

# ---- changes report ----
Write-Host ""
Write-Host "=== CHANGES ==="
if ($removed.Count -gt 0) {
    foreach ($r in $removed) { Write-Host ("  REMOVED  : " + $r) -ForegroundColor Yellow }
} else {
    Write-Host "  REMOVED  : (none)"
}
if ($replaced.Count -gt 0) {
    foreach ($r in $replaced) { Write-Host ("  REPLACED : " + $r) -ForegroundColor Yellow }
} else {
    Write-Host "  REPLACED : (none)"
}
if ($warnings.Count -gt 0) {
    foreach ($w in $warnings) { Write-Host ("  WARNING  : " + $w) -ForegroundColor Yellow }
}

$changed = ($removed.Count -gt 0) -or ($replaced.Count -gt 0) -or $addedMissing
if ($changed) {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($tomlPath, $out, $utf8)
    Write-Host "  manifest rewritten (UTF-8, no BOM)"
} else {
    Write-Host "  manifest already clean - no rewrite needed"
}

Write-Host ""
Write-Host "=== AFTER ==="
$i = 0
foreach ($ln in [System.IO.File]::ReadAllLines($tomlPath)) { $i++; Write-Host ("{0,3}: {1}" -f $i, $ln) }

# ---- tests (same suites as add_bridge_dex.ps1) ----
Write-Host ""
Push-Location $ProjectRoot
try {
    Write-Host "=== running: cargo test -p opacus-bridge --release ===" -ForegroundColor Cyan
    cargo test -p opacus-bridge --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BRIDGE TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "BRIDGE TESTS PASSED (DLEq + swap protocol + monero-rpc)" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== running: cargo test -p opacus-dex --release ===" -ForegroundColor Cyan
    cargo test -p opacus-dex --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "DEX TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "DEX TESTS PASSED (RLP/ABI/EIP-155/Uniswap calldata/rpc)" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " BRIDGE TOML FIXED - manifest conflict resolved, suites re-run" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
