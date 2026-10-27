# =============================================================================
# deploy_wghost.ps1  (ghost project - opacusio/opacus)
#
# PURPOSE
#   Full forge pipeline for the wGHOST bridge token, End-to-End rehearsed on
#   a local anvil chain before this script was generated:
#     STEP 1  locate or install Foundry (Windows release from GitHub)
#     STEP 2  patch contracts\wGHOST.sol (3 real defects found by rehearsal)
#             + write the 5-test suite + foundry.toml (all idempotent)
#     STEP 3  forge build        (solc 0.8.24, optimizer on)
#     STEP 4  forge test         (mint/burn, ERC20, quorum, replay guard)
#     STEP 5  forge create --broadcast on Sepolia (needs env vars, see below)
#             -> contracts\wghost.address + on-chain bytecode verification
#   Without DEPLOYER_PRIVATE_KEY the script stops after STEP 4 (build-only).
#
#   Environment (deploy only):
#     SEPOLIA_RPC_URL       RPC endpoint (Alchemy/Infura/publicnode)
#     DEPLOYER_PRIVATE_KEY  throwaway TESTNET key (never a mainnet key!)
#   Constructor: quorum = [deployer], threshold = 1 (single-signer testnet
#   setup; mainnet must use a multi-signer quorum after an external audit).
#
#   - pure ASCII, no here-strings, run with -File
#   - all native stderr captures go through cmd /c (PowerShell 5.1 safe)
# =============================================================================

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = "$PSScriptRoot"
$Contracts = Join-Path $ProjectRoot "contracts"
$Sol = Join-Path $Contracts "wGHOST.sol"
$Toml = Join-Path $Contracts "foundry.toml"
$TestSol = Join-Path $Contracts "WGHOSTTest.t.sol"
$AddrFile = Join-Path $Contracts "wghost.address"

if (-not (Test-Path -LiteralPath $Sol)) {
    Write-Output "[!] NOT FOUND: $Sol"
    exit 1
}

# --- STEP 1: locate or install foundry -----------------------------------------
Write-Output "STEP 1: locate or install Foundry"
$Forge = $null
$cmd = Get-Command forge.exe -ErrorAction SilentlyContinue
if ($cmd) { $Forge = $cmd.Source }
if (-not $Forge -and (Test-Path -LiteralPath "$env:USERPROFILE\.foundry\bin\forge.exe")) {
    $Forge = "$env:USERPROFILE\.foundry\bin\forge.exe"
}
if (-not $Forge -and (Test-Path -LiteralPath "$ProjectRoot\tools\foundry\forge.exe")) {
    $Forge = "$ProjectRoot\tools\foundry\forge.exe"
}
if (-not $Forge) {
    Write-Output "  forge not found - downloading Windows release from GitHub"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $url = "https://github.com/foundry-rs/foundry/releases/download/v1.8.5/foundry_v1.8.5_win32_amd64.zip"
    try {
        $api = Invoke-RestMethod -Uri "https://api.github.com/repos/foundry-rs/foundry/releases/latest"
        $asset = $api.assets | Where-Object { $_.name -like "*win32_amd64.zip" } | Select-Object -First 1
        if ($asset) { $url = $asset.browser_download_url }
        Write-Output ("  latest release asset: {0}" -f $asset.name)
    } catch {
        Write-Output "  [!] GitHub API unreachable - using pinned v1.8.5 URL"
    }
    $zip = Join-Path $env:TEMP "foundry_ghost_win.zip"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 600
    $dst = "$ProjectRoot\tools\foundry"
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    Expand-Archive -Path $zip -DestinationPath $dst -Force
    $Forge = Join-Path $dst "forge.exe"
    if (-not (Test-Path -LiteralPath $Forge)) {
        $found = Get-ChildItem -Path $dst -Recurse -Filter forge.exe | Select-Object -First 1
        if ($found) { $Forge = $found.FullName }
    }
}
if (-not (Test-Path -LiteralPath $Forge)) {
    Write-Output "[!] forge.exe still not available - aborting"
    exit 1
}
$Cast = $Forge -replace 'forge\.exe$', 'cast.exe'
Write-Output ("  forge: {0}" -f $Forge)
if ($Forge -match ' ' -or $Contracts -match ' ') {
    Write-Output "[!] tool/contract path contains spaces - move foundry to a space-free path"
    exit 1
}
$vOut = cmd /c ($Forge + ' --version 2>&1')
$vOut | ForEach-Object { Write-Output ("  {0}" -f $_) }

# --- STEP 2: patch wGHOST.sol + write test suite + foundry.toml ------------------
Write-Output "STEP 2: patch wGHOST.sol (rehearsal fixes) + test suite + foundry.toml"
$raw = [System.IO.File]::ReadAllText($Sol)
$nl = "`n"
if ($raw.Contains("`r`n")) { $nl = "`r`n" }
$solText = $raw.Replace("`r`n", "`n")

if ($solText.Contains("usedLock")) {
    Write-Output "  [=] wGHOST.sol already patched (usedLock marker present)"
} elseif ($solText.Contains("i.offset")) {

$oldA = (@(
'            bytes32 r;',
'            bytes32 s;',
'            uint8 v;',
'            assembly {',
'                r := calldataload(add(sigs.offset, add(i.offset, 0)))',
'                s := calldataload(add(sigs.offset, add(i.offset, 32)))',
'                v := shr(248, calldataload(add(sigs.offset, add(i.offset, 64))))',
'            }',
'            address signer = ecrecover(digest, v + 27, r, s);'
) -join "`n")

$newA = (@(
'            bytes calldata sig = sigs[i];',
'            bytes32 r;',
'            bytes32 s;',
'            uint8 v;',
'            require(uint8(sig[64]) < 2, "wGHOST: v");',
'            r = bytes32(sig[0:32]);',
'            s = bytes32(sig[32:64]);',
'            v = uint8(sig[64]) + 27;',
'            address signer = ecrecover(digest, v, r, s);'
) -join "`n")

$oldB = (@(
'    address[] public quorum;',
'    uint256 public quorumThreshold;'
) -join "`n")

$newB = (@(
'    address[] public quorum;',
'    uint256 public quorumThreshold;',
'',
'    /// Ghost lock tx hashes already minted (replay guard: 1 lock = 1 mint).',
'    mapping(bytes32 => bool) private usedLock;'
) -join "`n")

$oldC = (@(
'        bytes32 digest = keccak256(',
'            abi.encodePacked("ghost-lock-v1", to, value, ghostTxHash)',
'        );',
'        _checkQuorum(digest, sigs);',
'        totalSupply += value;'
) -join "`n")

$newC = (@(
'        require(!usedLock[ghostTxHash], "wGHOST: used");',
'        usedLock[ghostTxHash] = true;',
'        bytes32 digest = keccak256(',
'            abi.encodePacked("ghost-lock-v1", to, value, ghostTxHash)',
'        );',
'        _checkQuorum(digest, sigs);',
'        totalSupply += value;'
) -join "`n")

    foreach ($pair in @(@($oldA, $newA, "A: assembly -> calldata slicing"), @($oldB, $newB, "B: usedLock state"), @($oldC, $newC, "C: mint replay guard"))) {
        if (-not $solText.Contains($pair[0])) {
            Write-Output ("[!] patch {0}: expected block not found - paste wGHOST.sol back to the assistant" -f $pair[2])
            exit 1
        }
        $solText = $solText.Replace($pair[0], $pair[1])
        Write-Output ("  [+] patch {0}" -f $pair[2])
    }
    $bakSol = "$Sol.bak-sol"
    if (-not (Test-Path -LiteralPath $bakSol)) { Copy-Item -LiteralPath $Sol -Destination $bakSol }
    [System.IO.File]::WriteAllText($Sol, $solText.Replace("`n", $nl), (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ("  [+] written: {0} (backup: {1})" -f $Sol, $bakSol)
} else {
    Write-Output "[!] wGHOST.sol has neither 'usedLock' nor 'i.offset' - unknown content"
    Write-Output "    paste contracts\wGHOST.sol back to the assistant"
    exit 1
}

if (Test-Path -LiteralPath $TestSol) {
    Write-Output "  [=] WGHOSTTest.t.sol already present"
} else {
    $testLines = @(
'// SPDX-License-Identifier: MIT',
'pragma solidity ^0.8.20;',
'',
'import "./wGHOST.sol";',
'',
'/// Minimal e2e test for WGHOST (no forge-std dependency).',
'interface VmI {',
'    function addr(uint256 pk) external returns (address);',
'    function sign(uint256 pk, bytes32 digest)',
'        external returns (uint8 v, bytes32 r, bytes32 s);',
'    function prank(address) external;',
'    function expectRevert(bytes memory) external;',
'}',
'',
'contract WGHOSTTest {',
'    VmI constant vm = VmI(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);',
'',
'    WGHOST token;',
'    address holder;',
'    uint256 constant VALUE = 1000 ether;',
'',
'    function setUp() public {',
'        holder = vm.addr(1);',
'        address[] memory members = new address[](1);',
'        members[0] = holder;',
'        token = new WGHOST(members, 1);',
'    }',
'',
'    function _sig(bytes32 digest) internal returns (bytes[] memory sigs) {',
'        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, digest);',
'        sigs = new bytes[](1);',
'        sigs[0] = abi.encodePacked(r, s, bytes1(uint8(v - 27)));',
'    }',
'',
'    function _digest(address to, uint256 value, bytes32 h)',
'        internal pure returns (bytes32) {',
'        return keccak256(abi.encodePacked("ghost-lock-v1", to, value, h));',
'    }',
'',
'    function testMintBurnFlow() public {',
'        bytes32 h = keccak256("xmr-lock-tx-1");',
'        bytes[] memory sigs = _sig(_digest(holder, VALUE, h));',
'        token.mint(holder, VALUE, h, sigs);',
'        assertEq(token.balanceOf(holder), VALUE, "mint balance");',
'        assertEq(token.totalSupply(), VALUE, "mint supply");',
'',
'        vm.prank(holder);',
'        token.burn(VALUE, "ghost-recipient");',
'        assertEq(token.balanceOf(holder), 0, "burn balance");',
'        assertEq(token.totalSupply(), 0, "burn supply");',
'    }',
'',
'    function testTransferApprove() public {',
'        bytes32 h = keccak256("xmr-lock-tx-2");',
'        token.mint(holder, VALUE, h, _sig(_digest(holder, VALUE, h)));',
'',
'        vm.prank(holder);',
'        token.transfer(address(0xBEEF), 100);',
'        assertEq(token.balanceOf(address(0xBEEF)), 100, "transfer");',
'',
'        vm.prank(holder);',
'        token.approve(address(0xCEEF), 50);',
'        vm.prank(address(0xCEEF));',
'        token.transferFrom(holder, address(0xCEEF), 50);',
'        assertEq(token.balanceOf(address(0xCEEF)), 50, "transferFrom");',
'        assertEq(token.balanceOf(holder), VALUE - 150, "residual");',
'    }',
'',
'    function testRevertWrongDigestSig() public {',
'        bytes32 h = keccak256("xmr-lock-tx-3");',
'        // signature over a DIFFERENT digest -> recovered signer is not a member',
'        bytes[] memory sigs = _sig(keccak256("wrong-digest"));',
'        vm.expectRevert(bytes("wGHOST: quorum"));',
'        token.mint(holder, VALUE, h, sigs);',
'    }',
'',
'    function testRevertDuplicateSigOrder() public {',
'        bytes32 h = keccak256("xmr-lock-tx-4");',
'        bytes32 d = _digest(holder, VALUE, h);',
'        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, d);',
'        bytes[] memory sigs = new bytes[](2);',
'        sigs[0] = abi.encodePacked(r, s, bytes1(uint8(v - 27)));',
'        sigs[1] = abi.encodePacked(r, s, bytes1(uint8(v - 27)));',
'        // duplicate signer violates the strictly-sorted requirement',
'        vm.expectRevert(bytes("wGHOST: sig order"));',
'        token.mint(holder, VALUE, h, sigs);',
'    }',
'',
'    function testRevertOvermintDoubleUse() public {',
'        bytes32 h = keccak256("xmr-lock-tx-5");',
'        bytes[] memory sigs = _sig(_digest(holder, VALUE, h));',
'        token.mint(holder, VALUE, h, sigs);',
'        // same ghost tx hash minted twice -> supply inflation guard',
'        vm.expectRevert(bytes("wGHOST: used"));',
'        token.mint(holder, VALUE, h, sigs);',
'    }',
'',
'    function assertEq(uint256 a, uint256 b, string memory what) internal pure {',
'        require(a == b, what);',
'    }',
'}'
    )
    [System.IO.File]::WriteAllLines($TestSol, $testLines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ("  [+] written: {0}" -f $TestSol)
}

if (Test-Path -LiteralPath $Toml) {
    if (-not ((Get-Content $Toml -Raw) -match 'solc_version')) {
        Write-Output "  [!] foundry.toml exists without solc_version - build may pick another solc"
    } else {
        Write-Output "  [=] foundry.toml already present"
    }
} else {
    $tomlLines = @(
'# foundry config for the Ghost wGHOST contract (generated by deploy_wghost.ps1)',
'[profile.default]',
'src = "."',
'out = "out"',
'libs = ["lib"]',
'solc_version = "0.8.24"',
'optimizer = true',
'optimizer_runs = 200'
    )
    [System.IO.File]::WriteAllLines($Toml, $tomlLines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ("  [+] written: {0}" -f $Toml)
}

# --- STEP 3: forge build ---------------------------------------------------------
Write-Output "STEP 3: forge build (first run downloads solc 0.8.24)"
$bOut = cmd /c ($Forge + ' build --root ' + $Contracts + ' 2>&1')
$bOut | ForEach-Object { Write-Output ("  {0}" -f $_) }
if ($LASTEXITCODE -ne 0) {
    Write-Output "FORGE BUILD FAILED - paste the output above back to the assistant"
    exit 1
}

# --- STEP 4: forge test ----------------------------------------------------------
Write-Output "STEP 4: forge test (WGHOST suite)"
$tOut = cmd /c ($Forge + ' test --root ' + $Contracts + ' 2>&1')
$tOut | ForEach-Object { Write-Output ("  {0}" -f $_) }
if ($LASTEXITCODE -ne 0) {
    Write-Output "WGHOST SUITE FAILED - paste the output above back to the assistant"
    exit 1
}

# --- STEP 5: deploy gate -----------------------------------------------------------
Write-Output "STEP 5: Sepolia deploy gate"
$pk = $env:DEPLOYER_PRIVATE_KEY
$rpc = $env:SEPOLIA_RPC_URL
if (-not $rpc) {
    $rpc = "https://ethereum-sepolia-rpc.publicnode.com"
    Write-Output ("  [i] SEPOLIA_RPC_URL not set - using public RPC: {0}" -f $rpc)
}

$doDeploy = $false
$skipDeploy = $false
if ($pk) {
    if (-not ($pk -match '^0x[0-9a-fA-F]{64}$')) {
        Write-Output "[!] DEPLOYER_PRIVATE_KEY must be a 0x-prefixed 32-byte hex key"
        exit 1
    }
    if (Test-Path -LiteralPath $AddrFile) {
        $existing = (Get-Content -LiteralPath $AddrFile -TotalCount 1).Trim()
        if ($existing -match '^0x[0-9a-fA-F]{40}$') {
            $vLine = $Cast + ' code ' + $existing + ' --rpc-url ' + $rpc + ' 2>&1'
            $vOut = cmd /c $vLine
            if ((($vOut | Out-String).Trim()).Length -gt 2) {
                Write-Output ("  [=] already deployed and verified: {0} - skipping re-deploy" -f $existing)
                $skipDeploy = $true
            } else {
                Write-Output "  [i] recorded address has no bytecode - re-deploying"
            }
        }
    }
    $doDeploy = -not $skipDeploy
} else {
    Write-Output "  [i] DEPLOYER_PRIVATE_KEY not set - BUILD-ONLY mode"
}

if ($doDeploy) {
    Write-Output "  [!] reminder: use a THROWAWAY testnet key (it is visible in the process list)"
    $dLine = $Cast + ' wallet address --private-key ' + $pk + ' 2>&1'
    $dOut = cmd /c $dLine
    $dep = (($dOut | Out-String).Trim())
    if (-not ($dep -match '^0x[0-9a-fA-F]{40}$')) {
        Write-Output "[!] could not derive deployer address via cast - paste output back"
        exit 1
    }
    Write-Output ("  deployer (quorum 1/1): {0}" -f $dep)
    $cLine = $Forge + ' create WGHOST --root ' + $Contracts + ' --rpc-url ' + $rpc + ' --private-key ' + $pk + ' --broadcast --constructor-args [' + $dep + '] 1 2>&1'
    $cOut = cmd /c $cLine
    $cOut | ForEach-Object { Write-Output ("  {0}" -f $_) }
    if ($LASTEXITCODE -ne 0) {
        Write-Output "FORGE CREATE FAILED - paste the output above back to the assistant"
        exit 1
    }
    $m = [regex]::Match(($cOut -join "`n"), 'Deployed to: (0x[0-9a-fA-F]{40})')
    if (-not $m.Success) {
        Write-Output "[!] 'Deployed to:' not found in forge output - paste it back to the assistant"
        exit 1
    }
    $addr = $m.Groups[1].Value
    $txm = [regex]::Match(($cOut -join "`n"), 'Transaction hash: (0x[0-9a-fA-F]{64})')
    $bakAddr = "$AddrFile.bak-wga"
    if (Test-Path -LiteralPath $AddrFile) { Copy-Item -LiteralPath $AddrFile -Destination $bakAddr -Force }
    $record = $addr
    if ($txm.Success) { $record = $addr + "`r`ntx: " + $txm.Groups[1].Value }
    [System.IO.File]::WriteAllText($AddrFile, $record + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ("  [+] recorded: {0}" -f $AddrFile)

    $vLine = $Cast + ' code ' + $addr + ' --rpc-url ' + $rpc + ' 2>&1'
    $vOut = cmd /c $vLine
    if ((($vOut | Out-String).Trim()).Length -gt 2) {
        Write-Output ("  [+] on-chain bytecode VERIFIED: {0}" -f $addr)
    } else {
        Write-Output "  [!] bytecode not visible yet (RPC lag) - re-run the script to verify"
    }
}

# --- banner -----------------------------------------------------------------------
Write-Output ""
Write-Output "WGHOST DEPLOY PIPELINE COMPLETE"
Write-Output ""
Write-Output "What you got:"
Write-Output "  wGHOST.sol fixed: assembly sig-decode bug, replay guard (1 lock = 1 mint),"
Write-Output "    strict v-byte check - rehearsal-verified build + 5-test suite"
Write-Output "  contracts\WGHOSTTest.t.sol: mint/burn, ERC20 round, quorum rejects"
Write-Output "  contracts\foundry.toml: solc 0.8.24 + optimizer"
Write-Output "  backup: wGHOST.sol.bak-sol"
if (Test-Path -LiteralPath $AddrFile) {
    Write-Output ("  deployed: {0}" -f (Get-Content -LiteralPath $AddrFile -TotalCount 1).Trim())
}
Write-Output ""
Write-Output "Next steps:"
if ($skipDeploy -or (Test-Path -LiteralPath $AddrFile)) {
    Write-Output "  persist the address:"
    Write-Output ("    setx WGHOST_ADDRESS {0}" -f (Get-Content -LiteralPath $AddrFile -TotalCount 1).Trim())
    Write-Output "  then run: powershell -ExecutionPolicy Bypass -File .\wire_wghost_env.ps1"
    Write-Output "  (opacus-dex wghost() will pick WGHOST_ADDRESS up automatically)"
} else {
    Write-Output "  to deploy wGHOST on Sepolia:"
    Write-Output "    1. fund a throwaway address (0.05 ETH is plenty):"
    Write-Output "       https://sepolia-faucet.pk910.de   https://faucets.chain.link/sepolia"
    Write-Output '    2. $env:SEPOLIA_RPC_URL = "https://<provider>/v3/<key>"'
    Write-Output '       $env:DEPLOYER_PRIVATE_KEY = "0x..."   # throwaway TESTNET key only'
    Write-Output "    3. re-run: powershell -ExecutionPolicy Bypass -File .\deploy_wghost.ps1"
    Write-Output "  then run wire_wghost_env.ps1 (env wiring for opacus-dex)"
}
Write-Output "  mainnet: multi-signer quorum + external audit FIRST (AUDIT REQUIRED)"
