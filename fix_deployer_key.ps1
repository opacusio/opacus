# =============================================================================
# fix_deployer_key.ps1  (ghost project - opacusio/opacus)
#
# Replaces the PUBLIC anvil #0 key inside deployer.key with a fresh random
# key. Zero typing: nothing to copy, nothing to paste.
#
# Why: deployer.key currently holds 0xf39F...92266 - the most famous private
# key in the world (anvil/Foundry account #0, hardcoded in every Foundry
# install and tutorial). Bots sweep gas sent to it on Sepolia within seconds,
# and with quorum 1/1 anyone could mint unlimited wGHOST. Do NOT fund it.
#
# What it does (idempotent, safe to re-run):
#   - deployer.key holds a NON-public key -> prints it, exits (no changes)
#   - deployer.key holds anvil #0 (or missing/invalid):
#       cast wallet new -> cross-check -> backup old file -> write new key
#
# Run:
#   powershell -ExecutionPolicy Bypass -File .\fix_deployer_key.ps1
# then re-run the launcher:
#   powershell -ExecutionPolicy Bypass -File .\run_sepolia_deploy.ps1
# =============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$ProjectRoot = $PSScriptRoot
$KeyFile     = Join-Path $ProjectRoot 'deployer.key'
$Cast        = Join-Path $ProjectRoot 'tools\foundry\cast.exe'

# known anvil #0 fingerprints (public knowledge - used for detection only)
$Anvil0Pk   = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
$Anvil0Addr = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266'

function Die([string]$msg) {
    Write-Output ''
    Write-Output ('FATAL: ' + $msg)
    Write-Output 'Paste the FULL output above back to the assistant.'
    exit 1
}

Write-Output '============================================================='
Write-Output ' fix_deployer_key: fresh random deployer key (zero typing)'
Write-Output '============================================================='

if (-not (Test-Path -LiteralPath $Cast)) { Die ('cast.exe not found: ' + $Cast) }

# ---------------- STEP 1: decide rotate or skip ----------------
Write-Output ''
Write-Output 'STEP 1: checking deployer.key'
$cur    = $null
$cAddr  = ''
$rotate = $true
if (Test-Path -LiteralPath $KeyFile) {
    $cur = ([System.IO.File]::ReadAllText($KeyFile)).Trim()
    if ($cur -and ($cur -notmatch '^0x')) { $cur = '0x' + $cur }
    if ($cur -match '^0x[0-9a-fA-F]{64}$') {
        $cLine = $Cast + ' wallet address --private-key ' + $cur + ' 2>&1'
        $cOut  = cmd /c $cLine
        $cAddr = (($cOut | Out-String).Trim())
        Write-Output ('  [i] current key file address: ' + $cAddr)
        if (($cAddr -match '^0x[0-9a-fA-F]{40}$') -and
            ($cAddr.ToLower() -ne $Anvil0Addr) -and
            ($cur.ToLower()  -ne $Anvil0Pk)) {
            $rotate = $false
        }
    } else {
        Write-Output '  [i] key file content is not a valid key - will regenerate'
    }
} else {
    Write-Output '  [i] deployer.key not found - will generate'
}

if (-not $rotate) {
    Write-Output '  [ok] deployer.key already holds a fresh NON-public key - nothing to do'
    Write-Output ''
    Write-Output '============================================================='
    Write-Output ' FUND THIS ADDRESS (or just re-run run_sepolia_deploy.ps1):'
    Write-Output ('    ' + $cAddr)
    Write-Output '============================================================='
    exit 0
}

# ---------------- STEP 2: generate a fresh key ----------------
Write-Output ''
Write-Output 'STEP 2: generating a fresh random wallet (cast wallet new)'
$wLine = $Cast + ' wallet new 2>&1'
$wOut  = cmd /c $wLine
$wText = ($wOut | Out-String)
# 64-hex token is unambiguous -> the private key
$mK = [regex]::Match($wText, '0x[0-9a-fA-F]{64}')
if (-not $mK.Success) {
    Write-Output '  [!] could not find private key in cast output:'
    $wOut | ForEach-Object { Write-Output ('      {0}' -f $_) }
    Die 'cast wallet new parsing failed'
}
$pk = $mK.Value
# remove the key from the text before searching for the 40-hex address
# (a 64-hex string contains 40-hex substrings - never match inside it)
$rest = $wText.Remove($mK.Index, $mK.Length)
$mA   = [regex]::Match($rest, '0x[0-9a-fA-F]{40}')

# authoritative address: always DERIVED from the key
$aLine = $Cast + ' wallet address --private-key ' + $pk + ' 2>&1'
$aOut  = cmd /c $aLine
$dep   = (($aOut | Out-String).Trim())
if (-not ($dep -match '^0x[0-9a-fA-F]{40}$')) { Die 'could not derive address from the new key' }
if ($dep.ToLower() -eq $Anvil0Addr)           { Die 'improbable: generated key equals anvil #0 - aborting' }
if ($mA.Success -and ($mA.Value.ToLower() -ne $dep.ToLower())) { Die 'parsed address does not match derived address' }

# ---------------- STEP 3: backup the old key (never destroy) ----------------
Write-Output ''
if (Test-Path -LiteralPath $KeyFile) {
    $bak = Join-Path $ProjectRoot 'deployer.key.bak-anvil0'
    if (Test-Path -LiteralPath $bak) {
        $bak = Join-Path $ProjectRoot ('deployer.key.bak-anvil0-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    }
    Move-Item -LiteralPath $KeyFile -Destination $bak
    Write-Output ('STEP 3: old (public) key moved to: ' + (Split-Path $bak -Leaf))
} else {
    Write-Output 'STEP 3: no old key file to back up'
}

# ---------------- STEP 4: write the new key ----------------
[System.IO.File]::WriteAllText($KeyFile, $pk + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Output ''
Write-Output 'STEP 4: fresh key written to deployer.key'
Write-Output ('  [ok] deployer (quorum 1/1): ' + $dep)

Write-Output ''
Write-Output '============================================================='
Write-Output ' DONE. The OLD address 0xf39F...92266 is public - forget it'
Write-Output ' (its 0.000048 ETH dust can be claimed by anyone anyway).'
Write-Output ''
Write-Output ' FUND THE NEW ADDRESS:'
Write-Output ('    ' + $dep)
Write-Output ''
Write-Output '  faucet: https://sepolia-faucet.pk910.de'
Write-Output '          (paste the NEW address above, mine ~0.05 ETH, Claim)'
Write-Output '  alt   : https://faucets.chain.link/sepolia'
Write-Output ''
Write-Output ' After the balance lands - RE-RUN:'
Write-Output '   powershell -ExecutionPolicy Bypass -File .\run_sepolia_deploy.ps1'
Write-Output '============================================================='
