# =============================================================================
# run_sepolia_deploy.ps1  (ghost project - opacusio/opacus)
#
# ONE-SHOT LAUNCHER for the wGHOST Sepolia deploy. Zero manual typing:
#
#   STEP 1: ensure a deployer key
#           - no contracts\..\deployer.key -> generates a fresh throwaway
#             wallet via "cast wallet new" and saves it (deployer.key)
#           - existing valid key is reused (idempotent)
#   STEP 2: check Sepolia balance via public RPC
#           - below 0.005 ETH -> prints THE address to fund + faucet link
#             and stops; just re-run after funding
#   STEP 3: clears broken SEPOLIA_RPC_URL (public RPC is used), wires the
#           key and launches deploy_wghost.ps1 (with -NoProfile)
#
# Why: the deploy gate kept rejecting DEPLOYER_PRIVATE_KEY because literal
# placeholder texts were pasted into the env var. This flow has NO
# placeholders and NOTHING to copy by hand - the address to fund is printed
# by the script itself.
#
# Run:
#   powershell -ExecutionPolicy Bypass -File .\run_sepolia_deploy.ps1
# Idempotent: safe to re-run (key reused; deploy_wghost.ps1 skips re-deploy
# if contracts\wghost.address already holds a deployed contract).
# =============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$ProjectRoot = $PSScriptRoot
$Contracts   = Join-Path $ProjectRoot 'contracts'
$ToolsDir    = Join-Path $ProjectRoot 'tools\foundry'
$Forge       = Join-Path $ToolsDir 'forge.exe'
$Cast        = Join-Path $ToolsDir 'cast.exe'
$Deployer    = Join-Path $ProjectRoot 'deploy_wghost.ps1'
$KeyFile     = Join-Path $ProjectRoot 'deployer.key'
$Rpc         = 'https://ethereum-sepolia-rpc.publicnode.com'
$MinWei      = [decimal]5000000000000000   # 0.005 ETH hard floor

function Die([string]$msg) {
    Write-Output ''
    Write-Output ('FATAL: ' + $msg)
    Write-Output 'Paste the FULL output above back to the assistant.'
    exit 1
}

Write-Output '============================================================='
Write-Output ' run_sepolia_deploy: wGHOST -> Sepolia (zero-typing flow)'
Write-Output '============================================================='

# ---------------- STEP 0: sanity ----------------
Write-Output ''
Write-Output 'STEP 0: sanity checks'
if (-not (Test-Path -LiteralPath $Forge))    { Die ('forge.exe not found: ' + $Forge) }
if (-not (Test-Path -LiteralPath $Cast))     { Die ('cast.exe not found: ' + $Cast) }
if (-not (Test-Path -LiteralPath $Deployer)) { Die ('deploy_wghost.ps1 not found: ' + $Deployer) }
Write-Output '  [ok] tools + deploy script present'

# ---------------- STEP 1: deployer key ----------------
Write-Output ''
Write-Output 'STEP 1: deployer key'
if (Test-Path -LiteralPath $KeyFile) {
    $pk = ([System.IO.File]::ReadAllText($KeyFile)).Trim()
    Write-Output ('  [=] reusing existing key file: ' + $KeyFile)
} else {
    Write-Output '  [+] generating a fresh throwaway wallet (cast wallet new)'
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
    [System.IO.File]::WriteAllText($KeyFile, $pk + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
    if ($mA.Success) { Write-Output ('      parsed address: ' + $mA.Value) }
    Write-Output ('      key saved to:   ' + $KeyFile)
}
if (-not ($pk -match '^0x[0-9a-fA-F]{64}$')) {
    Write-Output ('      key file content is NOT a valid 0x + 64 hex key')
    Write-Output ('      fix: delete the file and re-run')
    Write-Output ('           Remove-Item -LiteralPath "' + $KeyFile + '"')
    Die 'invalid deployer.key content'
}
# authoritative address: always DERIVED from the key
$aLine = $Cast + ' wallet address --private-key ' + $pk + ' 2>&1'
$aOut  = cmd /c $aLine
$dep   = (($aOut | Out-String).Trim())
if (-not ($dep -match '^0x[0-9a-fA-F]{40}$')) {
    Write-Output '  [!] cast wallet address output:'
    $aOut | ForEach-Object { Write-Output ('      {0}' -f $_) }
    Die 'could not derive deployer address'
}
Write-Output ('  [ok] deployer (quorum 1/1): ' + $dep)

# ---------------- STEP 2: balance gate ----------------
Write-Output ''
Write-Output 'STEP 2: Sepolia balance check'
$bLine = $Cast + ' balance ' + $dep + ' --rpc-url ' + $Rpc + ' 2>&1'
$bOut  = cmd /c $bLine
$bText = (($bOut | Out-String).Trim())
if (-not ($bText -match '^\d+$')) {
    Write-Output '  [!] cast balance output:'
    $bOut | ForEach-Object { Write-Output ('      {0}' -f $_) }
    Die 'could not read balance from RPC'
}
$bal = [decimal]$bText
$eth = ($bal / [decimal]1000000000000000000).ToString('0.000000')
if ($bal -lt $MinWei) {
    Write-Output ('  [i] balance: ' + $eth + ' ETH - not enough for the deploy')
    Write-Output ''
    Write-Output '============================================================='
    Write-Output ' ONE STEP LEFT: FUND THIS ADDRESS'
    Write-Output '============================================================='
    Write-Output ''
    Write-Output ('    ' + $dep)
    Write-Output ''
    Write-Output '  faucet: https://sepolia-faucet.pk910.de'
    Write-Output '          (paste the address above, mine a few minutes, Claim)'
    Write-Output '  alt   : https://faucets.chain.link/sepolia'
    Write-Output '  0.05 ETH is plenty. After the balance lands - RE-RUN:'
    Write-Output '    powershell -ExecutionPolicy Bypass -File .\run_sepolia_deploy.ps1'
    Write-Output ''
    exit 0
}
Write-Output ('  [ok] balance: ' + $eth + ' ETH')

# ---------------- STEP 3: launch the deploy ----------------
Write-Output ''
Write-Output 'STEP 3: launching deploy_wghost.ps1'
Remove-Item Env:SEPOLIA_RPC_URL -ErrorAction SilentlyContinue
[Environment]::SetEnvironmentVariable('SEPOLIA_RPC_URL', $null, 'User')
$env:DEPLOYER_PRIVATE_KEY = $pk
& powershell -NoProfile -ExecutionPolicy Bypass -File $Deployer
if ($LASTEXITCODE -ne 0) {
    Write-Output ''
    Write-Output 'DEPLOY SCRIPT FAILED - paste the FULL output above back to the assistant.'
    exit 1
}

Write-Output ''
Write-Output '============================================================='
Write-Output ' RUN_SEPOLIA_DEPLOY: DONE'
Write-Output '============================================================='
Write-Output ('  deployer key file (TESTNET throwaway - delete when done):')
Write-Output ('    ' + $KeyFile)
Write-Output '  follow the deploy banner: setx WGHOST_ADDRESS 0x... then'
Write-Output '  powershell -ExecutionPolicy Bypass -File .\wire_wghost_env.ps1'
