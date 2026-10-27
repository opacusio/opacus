# =============================================================================
# fix_wire_eap.ps1  (ghost project - opacusio/opacus)
#
# WHAT HAPPENED
#   wire_opacusd_swap.ps1 aborted at STEP 6:
#     $netOut = cargo test -p opacus-network --release 2>&1
#     -> NativeCommandError / RemoteException on "Compiling opacus-network"
#   Root cause (PowerShell 5.1 quirk, NOT a cargo failure):
#     cargo writes its progress ("Compiling ...") to STDERR.
#     Under $ErrorActionPreference = "Stop" (line 16 of the wire script),
#     every stderr line captured via 2>&1 becomes an ErrorRecord -> the
#     FIRST stderr line raises a terminating error. No test ever ran.
#
# FIX
#   Route stderr-merging captures through cmd.exe so stderr is merged into
#   stdout BEFORE PowerShell sees it (plain strings only, EAP=Stop safe,
#   $LASTEXITCODE still propagates the cargo exit code):
#     $netOut = cargo test -p opacus-network --release 2>&1
#   becomes
#     $netOut = cmd /c "cargo test -p opacus-network --release 2>&1"
#
#   - idempotent: transformed lines no longer match; safe to re-run
#   - backup: wire_opacusd_swap.ps1.bak-eap1 (kept, never overwritten)
#   - pure ASCII, no here-strings, run with -File
# =============================================================================

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = "$PSScriptRoot"
$Target = Join-Path $ProjectRoot "wire_opacusd_swap.ps1"

if (-not (Test-Path -LiteralPath $Target)) {
    Write-Output "[!] NOT FOUND: $Target"
    exit 1
}
Write-Output "[i] target: $Target"

# --- backup -------------------------------------------------------------------
$bak = "$Target.bak-eap1"
if (Test-Path -LiteralPath $bak) {
    Write-Output "[=] backup already exists: $bak"
} else {
    Copy-Item -LiteralPath $Target -Destination $bak
    Write-Output "[+] backup written: $bak"
}

# --- transform ------------------------------------------------------------------
# This exact regex is byte-identical to the validated Python reference
# (scripts/fix_wire_eap_ref.py). Groups: 1=indent 2=assign 3=amp 4=exe 5=args 6=tail
$rx = [regex]'^(?<i>\s*)(?<v>\$\w+\s*=\s*)(&\s+)?(?<exe>cargo|git|forge|rustup)\s+(?<a>[^|]*\S)\s*2>&1(?<tail>\s*\|.*)?$'

$lines = [System.IO.File]::ReadAllLines($Target)
$patched = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]
$out = New-Object System.Collections.Generic.List[string]

foreach ($line in $lines) {
    $m = $rx.Match($line)
    $alreadyCmd = $line -match 'cmd\s+/c'
    if ($m.Success -and -not $alreadyCmd) {
        $argstr = $m.Groups[5].Value
        if ($argstr.IndexOf('"') -ge 0) {
            # quoted arguments - leave untouched, report below
            $skipped.Add($line.Trim())
            $out.Add($line)
            continue
        }
        # note: $tail (if any) stays OUTSIDE the quotes
        $new = '{0}{1}cmd /c "{2} {3} 2>&1"{4}' -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[4].Value, $argstr, $m.Groups[6].Value
        $out.Add($new)
        $patched.Add($new.Trim())
    } else {
        $out.Add($line)
    }
}

# UTF8 with BOM (original file layout), CRLF line endings preserved by WriteAllLines
[System.IO.File]::WriteAllLines($Target, $out, [System.Text.Encoding]::UTF8)

# --- report ----------------------------------------------------------------------
Write-Output ""
Write-Output ("[+] patched stderr captures: {0}" -f $patched.Count)
foreach ($p in $patched) { Write-Output ("    {0}" -f $p) }
if ($skipped.Count -gt 0) {
    Write-Output "[!] left untouched (quoted args) - fix manually if needed:"
    foreach ($s in $skipped) { Write-Output ("    {0}" -f $s) }
}

# --- verify: no unguarded native stderr captures remain ---------------------------
$check = [System.IO.File]::ReadAllLines($Target)
$left = 0
$n = 0
foreach ($line in $check) {
    $n++
    if ($rx.Match($line).Success -and ($line -notmatch 'cmd\s+/c')) {
        $left++
        Write-Output ("[!] line {0} still unguarded: {1}" -f $n, $line.Trim())
    }
}
if ($left -eq 0) {
    Write-Output "[+] verify OK: no native stderr captures outside cmd /c remain"
}

if ($patched.Count -eq 0) {
    if (Select-String -LiteralPath $Target -Pattern 'cmd /c "cargo' -Quiet) {
        Write-Output "[=] already fixed earlier - nothing to do"
    } else {
        Write-Output "[!] nothing matched - paste the STEP 6 lines back to the assistant"
    }
}

Write-Output ""
Write-Output "WIRE EAP FIX DONE - cargo stderr is now PowerShell 5.1 safe"
Write-Output ""
Write-Output "What you got:"
Write-Output "  wire_opacusd_swap.ps1 STEP 6 + STEP 7: cargo test captures routed"
Write-Output "    through cmd /c - 'Compiling...' stderr lines can no longer"
Write-Output "    raise NativeCommandError under ErrorActionPreference=Stop"
Write-Output "  exit codes still propagate: LASTEXITCODE = cargo exit code"
Write-Output "  backup: wire_opacusd_swap.ps1.bak-eap1 (original kept)"
Write-Output ""
Write-Output "Next steps:"
Write-Output "  powershell -ExecutionPolicy Bypass -File .\wire_opacusd_swap.ps1"
Write-Output "  (steps 1-5 are idempotent: markers + .bak-svc backups)"
Write-Output "  paste back: STEP 6 + STEP 7 test output and the final banner"
