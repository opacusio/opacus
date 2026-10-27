# =============================================================================
# finalize_wghost.ps1  (ghost project - opacusio/opacus)
#
# Post-deploy finalizer for wGHOST on Sepolia. Zero typing: replaces the
# manual "setx WGHOST_ADDRESS 0x..." step printed by the deploy banner
# (that step needs hand-copying an address - the exact thing this project
# keeps getting wrong).
#
# What it does (idempotent, safe to re-run):
#   STEP 1  read the deployed address from contracts\wghost.address
#   STEP 2  on-chain smoke test via public RPC:
#             bytecode present (hard gate)
#             name / symbol / decimals / totalSupply (informational)
#             quorumThreshold == 1, quorum(0) == your deployer (hard on mismatch)
#   STEP 3  persist WGHOST_ADDRESS (setx, User level = permanent)
#   STEP 4  run wire_wghost_env.ps1 when present (opacus-dex picks wGHOST up)
#
# Run AFTER deploy_wghost.ps1 finished with "Deployed to: 0x...":
#   powershell -ExecutionPolicy Bypass -File .\finalize_wghost.ps1
# =============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$ProjectRoot = $PSScriptRoot
$AddrFile    = Join-Path $ProjectRoot 'contracts\wghost.address'
$KeyFile     = Join-Path $ProjectRoot 'deployer.key'
$Cast        = Join-Path $ProjectRoot 'tools\foundry\cast.exe'
$Wire        = Join-Path $ProjectRoot 'wire_wghost_env.ps1'
$Rpc         = 'https://ethereum-sepolia-rpc.publicnode.com'

# known anvil #0 address (public knowledge - used for detection only)
$Anvil0Addr = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266'

function Die([string]$msg) {
    Write-Output ''
    Write-Output ('FATAL: ' + $msg)
    Write-Output 'Paste the FULL output above back to the assistant.'
    exit 1
}

Write-Output '============================================================='
Write-Output ' finalize_wghost: smoke test + persist + wire (zero typing)'
Write-Output '============================================================='

if (-not (Test-Path -LiteralPath $Cast)) { Die ('cast.exe not found: ' + $Cast) }

# ---------------- STEP 1: the deployed address ----------------
Write-Output ''
Write-Output 'STEP 1: reading contracts\wghost.address'
if (-not (Test-Path -LiteralPath $AddrFile)) {
    Write-Output '  [i] wghost.address not found - the deploy has not run yet.'
    Write-Output '      1) claim the mined ETH on the faucet'
    Write-Output '      2) powershell -ExecutionPolicy Bypass -File .\run_sepolia_deploy.ps1'
    Write-Output '      3) re-run THIS script afterwards'
    exit 0
}
$lines = [System.IO.File]::ReadAllLines($AddrFile)
$addr  = $lines[0].Trim()
if (-not ($addr -match '^0x[0-9a-fA-F]{40}$')) { Die ('wghost.address holds no valid address: ' + $addr) }
$tx = ''
foreach ($ln in $lines) { if ($ln -match '^tx:\s*(0x[0-9a-fA-F]{64})') { $tx = $Matches[1] } }
Write-Output ('  [ok] wGHOST: ' + $addr)
if ($tx) { Write-Output ('  [ok] deploy tx: ' + $tx) }

# ---------------- STEP 2: on-chain smoke test ----------------
Write-Output ''
Write-Output 'STEP 2: on-chain smoke test (public RPC)'
$cLine = $Cast + ' code ' + $addr + ' --rpc-url ' + $Rpc + ' 2>&1'
$cOut  = cmd /c $cLine
$code  = (($cOut | Out-String).Trim())
if (-not (($code -match '^0x[0-9a-fA-F]{2,}$') -and ($code.Length -gt 2))) {
    Write-Output '  [!] no bytecode visible via RPC yet (public node lag or hiccup)'
    Write-Output '      wait 1-2 minutes and re-run this script'
    exit 1
}
Write-Output ('  [ok] bytecode present ({0} bytes on-chain)' -f [math]::Floor(($code.Length - 2) / 2))

function CallContract([string]$sig, [string]$argsStr) {
    $l = $Cast + ' call ' + $addr + ' "' + $sig + '" ' + $argsStr + ' --rpc-url ' + $Rpc + ' 2>&1'
    return ((cmd /c $l | Out-String).Trim())
}
function IsOk([string]$v) {
    return (($v -match '^\S') -and ($v -notmatch '(?i)error') -and ($v -notmatch '(?i)revert'))
}

$name   = CallContract 'name()(string)' ''
$symbol = CallContract 'symbol()(string)' ''
$dec    = CallContract 'decimals()(uint8)' ''
$supply = CallContract 'totalSupply()(uint256)' ''
$thresh = CallContract 'quorumThreshold()(uint256)' ''
if (IsOk $name)   { Write-Output ('  [ok] name:     ' + $name) }   else { Write-Output '  [i] name:     n/a' }
if (IsOk $symbol) { Write-Output ('  [ok] symbol:   ' + $symbol) } else { Write-Output '  [i] symbol:   n/a' }
if ($dec -match '^\d+$')    { Write-Output ('  [ok] decimals: ' + $dec) } else { Write-Output '  [i] decimals: n/a' }
if ($supply -match '^\d+$') { Write-Output ('  [ok] totalSupply: ' + $supply + ' wei (0 = expected until the first bridge mint)') } else { Write-Output '  [i] totalSupply: n/a' }
if ($thresh -match '^\d+$') {
    if ($thresh -eq '1') { Write-Output '  [ok] quorumThreshold: 1 (single-signer testnet setup)' }
    else { Write-Output ('  [!] quorumThreshold: ' + $thresh + ' (expected 1)') }
} else {
    Write-Output '  [i] quorumThreshold: n/a'
}

# quorum[0] must be YOUR fresh deployer - never a public key
$q0  = CallContract 'quorum(uint256)(address)' '0'
$dep = ''
if (Test-Path -LiteralPath $KeyFile) {
    $k = ([System.IO.File]::ReadAllText($KeyFile)).Trim()
    if ($k -and ($k -notmatch '^0x')) { $k = '0x' + $k }
    if ($k -match '^0x[0-9a-fA-F]{64}$') {
        $dLine = $Cast + ' wallet address --private-key ' + $k + ' 2>&1'
        $dep   = ((cmd /c $dLine | Out-String).Trim())
    }
}
if (($q0 -match '^0x[0-9a-fA-F]{40}$') -and ($dep -match '^0x[0-9a-fA-F]{40}$')) {
    if ($q0.ToLower() -eq $Anvil0Addr) {
        Write-Output ('  [!] quorum[0]: ' + $q0)
        Die 'quorum[0] is the PUBLIC anvil #0 key - the contract must not be wired; re-deploy with the fresh key'
    }
    if ($q0.ToLower() -eq $dep.ToLower()) {
        Write-Output ('  [ok] quorum[0] == your fresh deployer: ' + $q0)
    } else {
        Write-Output ('  [!] quorum[0]: ' + $q0)
        Write-Output ('  [!] deployer:  ' + $dep)
        Die 'quorum member mismatch - the deployed contract is NOT owned by your fresh key'
    }
} else {
    Write-Output '  [i] quorum(0) / deployer derivation: n/a (check skipped)'
}

# ---------------- STEP 3: persist WGHOST_ADDRESS ----------------
Write-Output ''
Write-Output 'STEP 3: persisting WGHOST_ADDRESS (User level, permanent)'
$cur = [Environment]::GetEnvironmentVariable('WGHOST_ADDRESS', 'User')
if ($cur) { Write-Output ('  [=] previous value: ' + $cur) }
$env:WGHOST_ADDRESS = $addr
$sOut = cmd /c ('setx WGHOST_ADDRESS ' + $addr + ' 2>&1')
$sOut | ForEach-Object { Write-Output ('  {0}' -f $_) }
if ($LASTEXITCODE -ne 0) { Die 'setx failed' }
Write-Output '  [ok] WGHOST_ADDRESS saved (new terminal windows will see it)'

# ---------------- STEP 4: wire opacus-dex ----------------
Write-Output ''
if (Test-Path -LiteralPath $Wire) {
    Write-Output 'STEP 4: wiring opacus-dex (wire_wghost_env.ps1)'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $Wire
    if ($LASTEXITCODE -ne 0) {
        Write-Output '  [!] wire_wghost_env.ps1 exited nonzero - paste its output back'
    } else {
        Write-Output '  [ok] opacus-dex wired to wGHOST'
    }
} else {
    Write-Output 'STEP 4: wire_wghost_env.ps1 not found in project root - skipped'
    Write-Output '  (run it later from the project root when it is present)'
}

# ---------------- banner ----------------
Write-Output ''
Write-Output '============================================================='
Write-Output ' WGHOST FINALIZE COMPLETE'
Write-Output '============================================================='
Write-Output ('  token:     ' + $addr)
if ($tx) { Write-Output ('  deploy tx: ' + $tx) }
Write-Output ('  etherscan: https://sepolia.etherscan.io/address/' + $addr)
Write-Output ('  WGHOST_ADDRESS: ' + $addr + ' (User level, permanent)')
Write-Output '  next: ghost lock tx -> quorum signature -> mint on Sepolia;'
Write-Output '        wGHOST trades on Uniswap V2/V3 like any ERC20'
Write-Output '  mainnet: multi-signer quorum + external audit FIRST (AUDIT REQUIRED)'
Write-Output '============================================================='
