# =============================================================================
# publish_ghost.ps1  v2  (ghost project - opacusio/opacus)
#
# Zero-typing GitHub publish of the ghost monorepo. Safe by construction:
#
#   STEP 0  sanity: git.exe found, project root present, repo present/init
#   STEP 1  git identity forced LOCAL (kopylovap-prog + noreply e-mail),
#           verified by reading it back
#   STEP 2  .gitignore guards (secrets / binaries / artifacts) + README
#   STEP 3  git add -A + SECRET GATE: scans the index for keys, .env, .pem,
#           backups, tools/ - auto-untracks offenders (files stay on disk)
#   STEP 4  commit (skipped when nothing changed) + branch -> main
#   STEP 5  remote origin -> https://github.com/opacusio/opacus.git
#   STEP 6  push (gh credential helper when available; a GitHub login window
#           popping up during push is NORMAL - complete it in the browser)
#
# v2 fix: git and gh are now invoked DIRECTLY from PowerShell - no cmd
#   wrapper, no quote tricks. The v1 wrapper built the command line through
#   the shell with hand-made quoting; when PowerShell passes such a string
#   to the shell, the embedded quotes are escaped in a way the shell does
#   not understand, so the executable name got corrupted and Windows
#   returned error 123 "The filename, directory name, or volume label
#   syntax is incorrect" (the Russian error text the user saw). That broke
#   every git call whose git.exe lives outside the default install dir
#   (here: D:\Git\cmd\git.exe) and made the STEP 1 "[+]" lines unreliable.
#   Direct invocation passes every argument as its own token and needs no
#   quoting at all; every step is now gated on the real exit code.
#
# Idempotent: safe to re-run (second run just pushes new commits).
# NEVER force-pushes; a rejected push means the remote is not empty.
# =============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$ProjectRoot = $PSScriptRoot
$RepoUrl     = 'https://github.com/opacusio/opacus.git'
$GiFile      = Join-Path $ProjectRoot '.gitignore'
$ReadMe      = Join-Path $ProjectRoot 'README.md'
$GitUser     = 'kopylovap-prog'
$GitMail     = 'kopylovap-prog@users.noreply.github.com'

function Die([string]$msg) {
    Write-Output ''
    Write-Output ('FATAL: ' + $msg)
    Write-Output 'Paste the FULL output above back to the assistant.'
    exit 1
}

function GitRun {
    # Direct invocation: every token is passed to git.exe as its own
    # argument (PowerShell quotes spaces and specials correctly), so the
    # non-standard install path D:\Git\cmd\git.exe needs no manual quoting.
    # stderr is folded into the captured output so it can be parsed and
    # shown; ErrorActionPreference is relaxed inside the call because under
    # 'Stop' a native stderr line would throw a NativeCommandError.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $Git -C $ProjectRoot @args 2>&1 } finally { $ErrorActionPreference = $prev }
    $code  = $LASTEXITCODE
    $lines = @($out | ForEach-Object { if ($null -ne $_) { $_.ToString() } })
    $global:LASTEXITCODE = $code
    return $lines
}

function GhRun {
    # Same pattern for the gh CLI (its path usually contains spaces:
    # C:\Program Files\GitHub CLI\gh.exe - manual quoting would break too).
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $gh.Source @args 2>&1 } finally { $ErrorActionPreference = $prev }
    $code  = $LASTEXITCODE
    $lines = @($out | ForEach-Object { if ($null -ne $_) { $_.ToString() } })
    $global:LASTEXITCODE = $code
    return $lines
}

Write-Output '============================================================='
Write-Output ' publish_ghost v2: safe zero-typing GitHub publish'
Write-Output '============================================================='

# ---------------- STEP 0: sanity ----------------
Write-Output ''
Write-Output 'STEP 0: sanity checks'
$Git = $null
$g = Get-Command git.exe -ErrorAction SilentlyContinue
if ($g) { $Git = $g.Source }
if (-not $Git -and (Test-Path -LiteralPath 'C:\Program Files\Git\cmd\git.exe')) {
    $Git = 'C:\Program Files\Git\cmd\git.exe'
}
if (-not $Git) {
    Die 'git.exe not found - install Git for Windows (git-scm.com), then re-run'
}
if (-not (Test-Path -LiteralPath $ProjectRoot)) { Die ('project root not found: ' + $ProjectRoot) }
Write-Output ('  [ok] git: ' + $Git)
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot '.git'))) {
    GitRun init | Out-Null
    if ($LASTEXITCODE -ne 0) { Die 'git init failed' }
    Write-Output '  [+] git repository initialized'
} else {
    Write-Output '  [=] git repository already present'
}

# ---------------- STEP 1: identity (forced local + verified) ----------------
Write-Output ''
Write-Output 'STEP 1: git identity'
$n = ((GitRun config user.name) | Out-String).Trim()
$e = ((GitRun config user.email) | Out-String).Trim()
if ($n -ne $GitUser) {
    GitRun config --local user.name $GitUser | Out-Null
    if ($LASTEXITCODE -ne 0) { Die 'could not set user.name' }
    $v = ((GitRun config user.name) | Out-String).Trim()
    if ($v -ne $GitUser) { Die ('user.name verification failed: [' + $v + ']') }
    Write-Output ('  [+] user.name set (local): {0} (was: "{1}")' -f $GitUser, $n)
} else {
    Write-Output ('  [=] user.name: {0}' -f $n)
}
if ($e -ne $GitMail) {
    GitRun config --local user.email $GitMail | Out-Null
    if ($LASTEXITCODE -ne 0) { Die 'could not set user.email' }
    $v = ((GitRun config user.email) | Out-String).Trim()
    if ($v -ne $GitMail) { Die ('user.email verification failed: [' + $v + ']') }
    Write-Output ('  [+] user.email set (local): {0} (was: "{1}")' -f $GitMail, $e)
} else {
    Write-Output ('  [=] user.email: {0}' -f $e)
}

# ---------------- STEP 2: .gitignore guards + README ----------------
Write-Output ''
Write-Output 'STEP 2: .gitignore guards + README'
$need = @(
    '# -- publish_ghost.ps1: secrets & local artifacts (do not remove)',
    'deployer.key',
    'deployer.key.*',
    '*.key',
    '*.pem',
    '.env',
    '.env.*',
    'target/',
    'tools/',
    'node_modules/',
    'out/',
    'cache/',
    'contracts/out/',
    'contracts/cache/',
    '*.bak',
    '*.bak-*'
)
$have = @()
if (Test-Path -LiteralPath $GiFile) {
    $have = @([System.IO.File]::ReadAllLines($GiFile)) | ForEach-Object { $_.Trim() }
}
$missing = @($need | Where-Object { $have -notcontains $_ })
if ($missing.Count -gt 0) {
    $lines = @()
    if (Test-Path -LiteralPath $GiFile) { $lines += @([System.IO.File]::ReadAllLines($GiFile)) + '' }
    $lines += $missing
    [System.IO.File]::WriteAllLines($GiFile, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ('  [+] .gitignore updated (+{0} guard lines)' -f $missing.Count)
} else {
    Write-Output '  [=] .gitignore already complete'
}
if (-not (Test-Path -LiteralPath $ReadMe)) {
    $rm = @(
        '# Ghost',
        '',
        'Privacy payment network: Monero-style ring-CT fused with Zcash-style Halo2',
        'FCMP++ spend proofs, an Ethereum-side wrapped token (wGHOST) and DEX/bridge',
        'tooling.',
        '',
        '- crates/ - Rust workspace: opacus-zk (Halo2 IPA circuits, real prover),',
        '  opacus-wallet (shielded spend flow), opacus-bridge (Monero DLEq / atomic swap /',
        '  RPC), opacus-dex (Uniswap calldata, EIP-155 signer)',
        '- contracts/ - wGHOST.sol (quorum-mint ERC20 wrapper) + forge test suite',
        '- zero-typing Sepolia deploy pipeline at the repo root:',
        '  run_sepolia_deploy.ps1 -> deploy_wghost.ps1 -> finalize_wghost.ps1',
        '',
        'Status: testnet. opacus-zk: real IPA spend proof at mainnet tree depth (2^32).',
        'wGHOST: deployed on Sepolia (contracts/wghost.address), quorum 1/1.',
        'Value conservation in-circuit is planned (v0.4). AUDIT REQUIRED before any',
        'mainnet use. Testnet keys are throwaway and never committed.'
    )
    [System.IO.File]::WriteAllLines($ReadMe, [string[]]$rm, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output '  [+] README.md written'
} else {
    Write-Output '  [=] README.md already present'
}

# ---------------- STEP 3: stage + SECRET GATE ----------------
Write-Output ''
Write-Output 'STEP 3: staging + secret gate'
GitRun add -A | Out-Null
if ($LASTEXITCODE -ne 0) { Die 'git add failed' }
$tracked = @(GitRun ls-files)
$bad = @()
foreach ($t in $tracked) {
    $p = ($t -replace '\\', '/').Trim()
    if (-not $p) { continue }
    $b = ($p -split '/')[-1]
    if (($b -like '*deployer.key*') -or ($b -like '*.key') -or ($b -like '*.pem') -or
        ($b -eq '.env') -or (($b -like '.env.*') -and ($b -ne '.env.example')) -or
        ($b -like '*.bak') -or ($b -like '*.bak-*') -or
        ($p -like 'tools/*')) {
        $bad += $p
    }
}
if ($bad.Count -gt 0) {
    foreach ($p in $bad) {
        GitRun rm --cached --quiet -- $p | Out-Null
        if ($LASTEXITCODE -ne 0) { Die ('could not untrack: ' + $p) }
    }
    GitRun add -A | Out-Null
    Write-Output '  [!] removed from the index (files KEPT on disk, now git-ignored):'
    $bad | ForEach-Object { Write-Output ('      ' + $_) }
} else {
    Write-Output '  [ok] index clean: no keys, no .env, no backups, no binaries'
}

# ---------------- STEP 4: commit + branch main ----------------
Write-Output ''
Write-Output 'STEP 4: commit + branch'
GitRun diff --cached --quiet | Out-Null
if ($LASTEXITCODE -eq 1) {
    $msg = 'ghost: monorepo - zk FCMP++ (Halo2), wallet, bridge, dex, swap, wGHOST Sepolia deploy chain'
    GitRun commit -m $msg | ForEach-Object { Write-Output ('  {0}' -f $_) }
    if ($LASTEXITCODE -ne 0) { Die 'git commit failed' }
} elseif ($LASTEXITCODE -ne 0) {
    Die ('git diff --cached failed (exit ' + $LASTEXITCODE + ')')
} else {
    Write-Output '  [=] nothing new to commit'
}
GitRun rev-parse HEAD | Out-Null
if ($LASTEXITCODE -eq 0) {
    $br = ((GitRun rev-parse --abbrev-ref HEAD) | Out-String).Trim()
    if ($br -eq 'main') {
        Write-Output '  [=] branch: main'
    } elseif ($br -eq 'HEAD') {
        GitRun checkout -B main | Out-Null
        if ($LASTEXITCODE -ne 0) { Die 'could not create branch main (detached HEAD)' }
        Write-Output '  [+] detached HEAD -> new branch main'
    } else {
        GitRun branch -M main | Out-Null
        if ($LASTEXITCODE -ne 0) { Die 'could not rename branch to main' }
        Write-Output ('  [+] branch: {0} -> main' -f $br)
    }
} else {
    # unborn HEAD: no commits yet - just point HEAD at refs/heads/main
    GitRun symbolic-ref HEAD refs/heads/main | Out-Null
    if ($LASTEXITCODE -ne 0) { Die 'could not point unborn HEAD at main' }
    Write-Output '  [+] initial branch: main (no commits yet)'
}

# ---------------- STEP 5: remote ----------------
Write-Output ''
Write-Output 'STEP 5: remote origin'
$r = @(GitRun remote get-url origin)
if ($LASTEXITCODE -ne 0) {
    GitRun remote add origin $RepoUrl | Out-Null
    if ($LASTEXITCODE -ne 0) { Die 'git remote add failed' }
    Write-Output ('  [+] origin -> {0}' -f $RepoUrl)
} else {
    $cur = (($r | Out-String).Trim())
    if ($cur.ToLower() -ne $RepoUrl.ToLower()) {
        GitRun remote set-url origin $RepoUrl | Out-Null
        if ($LASTEXITCODE -ne 0) { Die 'git remote set-url failed' }
        Write-Output ('  [+] origin updated: {0} -> {1}' -f $cur, $RepoUrl)
    } else {
        Write-Output '  [=] origin already set'
    }
}

# ---------------- STEP 6: push ----------------
Write-Output ''
Write-Output 'STEP 6: push'
$gh = Get-Command gh -ErrorAction SilentlyContinue
if ($gh) {
    $gs = @(GhRun auth status)
    $gsText = ($gs | Out-String)
    if (($LASTEXITCODE -eq 0) -and ($gsText -match 'Logged in') -and ($gsText -notmatch 'not logged in')) {
        GhRun auth setup-git | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Output '  [+] gh credential helper active' }
    }
}
$env:GIT_TERMINAL_PROMPT = '0'
Write-Output '  [i] pushing (a GitHub login window may appear - complete it and the push continues)'
$pOut = @(GitRun push -u origin main)
$pOut | ForEach-Object { Write-Output ('  {0}' -f $_) }
if ($LASTEXITCODE -ne 0) {
    $pt = ($pOut | Out-String)
    if ($pt -match '(?i)rejected') {
        Write-Output ''
        Write-Output '  [!] push rejected - the remote branch is NOT empty (GitHub may hold an'
        Write-Output '      auto-created README). Do NOT force-push blindly -'
        Write-Output '      paste the FULL output above back to the assistant.'
    } elseif ($pt -match '(?i)authentication|could not read Username|terminal prompts disabled') {
        Write-Output '  [!] auth failed - run: gh auth login   (or complete the credential-manager'
        Write-Output '      window), then re-run this script. Paste the FULL output back too.'
    }
    exit 1
}

Write-Output ''
Write-Output '============================================================='
Write-Output ' GHOST PUBLISH COMPLETE'
Write-Output '============================================================='
Write-Output '  repo:   https://github.com/opacusio/opacus'
Write-Output '  pushed: main (source, contracts, deploy scripts, docs)'
Write-Output '  kept local only (git-ignored): deployer.key*, *.bak*,'
Write-Output '    tools/, build artifacts (target/, out/, cache/)'
Write-Output '============================================================='
