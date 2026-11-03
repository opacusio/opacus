#!/usr/bin/env python3
"""Sync the release test counters across the repo docs.

The test counters shown in the README quick-start block (and in the gh-pages
site copy) drift every release. This tool re-derives them from the workspace
the same way CI runs them (ci.yml: plain `cargo test --workspace`, default
features):

    cargo test --workspace -- --list            -> total tests (incl. ignored)
    cargo test --workspace -- --ignored --list  -> ignored (slow) tests
    default pass = total - ignored

Both listings are parsed twice (the libtest summary rows "N tests, M
benchmarks" and the "...: test" item lines) and cross-checked against each
other.

Usage (release flow):

    python3 scripts/sync_test_counts.py                    # dry-run gate: exit 1 = stale
    python3 scripts/sync_test_counts.py --apply            # rewrite the counters in place
    python3 scripts/sync_test_counts.py --apply --file /path/to/gh-pages/worktree/index.html
    python3 scripts/sync_test_counts.py --check --set 445 4   # skip the cargo build

Notes:
  - Built-in target: README.md, with the two anchored rules for the
    "N tests pass by default" and the "N slow ... are ignored by default"
    sentences. --file adds extra copies (site HTML) synced with the generic
    "<num> ... tests" pattern, where the number may be wrapped in inline tags
    ("<b>441</b><span>... workspace tests ...", "# 441 tests").
  - A required rule that matches nothing is an error (wording drifted):
    update the rule table in this script, never the docs by hand.
  - Only the digits are rewritten; the surrounding bytes (including CRLF
    line endings) are preserved verbatim, and files already in sync are not
    written at all, so a no-op run keeps `git status` clean.
  - The counters describe the default-feature test surface. Historical
    numbers inside CHANGELOG.md are intentionally never touched.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SUMMARY_RE = re.compile(r"^\s*(\d+) tests?, (\d+) benchmarks?\s*$")
ITEM_RE = re.compile(r": test\s*$")

# (name, counter, pattern, required); the pattern must carry exactly one
# named group `num` (the counter) and may carry a `tail` group, which is
# preserved verbatim after the rewritten number.
# counters: "default" = total - ignored, "ignored", "total".
Rule = tuple[str, str, re.Pattern[str], bool]

README_RULES: list[Rule] = [
    (
        "readme-default",
        "default",
        re.compile(r"(?P<num>\d[\d,]*)(?P<tail>\s+tests pass by default)"),
        True,
    ),
    (
        "readme-ignored",
        "ignored",
        re.compile(r"(?P<num>\d[\d,]*)(?P<tail>\s+slow\b[^\n]*?are ignored by default)"),
        True,
    ),
]

# Generic rule for extra copies (site HTML). The number must be followed by
# the word "tests" either directly ("# 441 tests") or across inline markup
# tags plus at most two lowercase words ("<b>441</b><span>workspace tests").
# The tags act as the markup boundary: prose like "92 bridge tests" or
# "17 new tests" (no tags between the number and the word) is never matched,
# so --file targets must be markup copies, not prose documents - those need
# anchored rules like README_RULES.
EXTRA_RULE: Rule = (
    "generic-default",
    "default",
    re.compile(
        r"(?P<num>\d[\d,]*)"
        r"(?P<tail>"
        r"(?:\s*</?[a-zA-Z][^>\n]*>)+\s*(?:[a-z][a-z-]*\s+){0,2}tests\b"
        r"|\s+tests\b)"
    ),
    True,
)


def run_list(cargo: str, filters: list[str]) -> tuple[int, int, int]:
    """Run `cargo test --workspace -- <filters> --list`.

    Returns (chosen_count, item_line_count, test_target_count).
    """
    cmd = [cargo, "test", "--workspace", "--", *filters, "--list"]
    env = dict(os.environ, CARGO_TERM_COLOR="never")
    print(f"$ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(f"error: {' '.join(cmd)} failed (exit {proc.returncode})")
    summary_sum = items = targets = 0
    for line in proc.stdout.splitlines():
        m = SUMMARY_RE.match(line)
        if m:
            summary_sum += int(m.group(1))
            targets += 1
        elif ITEM_RE.search(line):
            items += 1
    if summary_sum == 0 and items == 0:
        raise SystemExit("error: no tests parsed from the --list output")
    if summary_sum and items and summary_sum != items:
        print(f"note: summary rows sum {summary_sum} != item lines {items}; using {summary_sum}")
    return (summary_sum or items), items, targets


def git_head() -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    return out.stdout.strip() or None


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="sync_test_counts.py",
        description="Re-derive the workspace test counters and sync them into README.md / site copies.",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true",
        help="dry-run (default): report stale counters, exit 1 if any",
    )
    mode.add_argument(
        "--apply", action="store_true",
        help="rewrite the counters in place",
    )
    ap.add_argument(
        "--set", nargs=2, type=int, metavar=("TOTAL", "IGNORED"),
        help="skip the cargo build and use these numbers",
    )
    ap.add_argument(
        "--file", dest="files", action="append", default=[], metavar="PATH",
        help="extra copy to sync with the generic pattern (repeatable), e.g. a gh-pages index.html",
    )
    ap.add_argument(
        "--cargo", default=os.environ.get("CARGO", "cargo"),
        help="cargo binary (default: %(default)s)",
    )
    args = ap.parse_args()
    apply_mode = args.apply

    if args.set is not None:
        total, ignored = args.set
    else:
        total, _items_total, _targets = run_list(args.cargo, [])
        ignored, _items_ignored, _targets2 = run_list(args.cargo, ["--ignored"])
        if ignored >= total:
            raise SystemExit(
                f"error: ignored listing ({ignored}) >= total ({total}) - "
                "the --ignored filter did not apply; aborting"
            )
    default = total - ignored
    head = git_head()
    where = f" @ {head}" if head else ""
    print(f"workspace surface{where}: total {total} | ignored {ignored} | default pass {default}")

    targets: list[tuple[Path, list[Rule]]] = [(REPO_ROOT / "README.md", README_RULES)]
    for extra in args.files:
        targets.append((Path(extra), [EXTRA_RULE]))

    pending: list[tuple[Path, str]] = []
    stale = 0
    fatal = False
    for path, rules in targets:
        try:
            text = path.read_bytes().decode("utf-8")
        except FileNotFoundError:
            print(f"error: missing target file: {path}")
            fatal = True
            continue
        new_text = text
        notes: list[str] = []
        for name, counter, pattern, required in rules:
            want = {"default": default, "ignored": ignored, "total": total}[counter]
            hits = 0

            def sub(m: re.Match, want: int = want) -> str:
                nonlocal hits
                hits += 1
                old = m.group("num")
                if int(old.replace(",", "")) == want:
                    return m.group(0)
                line_no = new_text.count("\n", 0, m.start()) + 1
                notes.append(f"  {path}:{line_no}: {counter} {old} -> {want}")
                return f"{want}{m.group('tail')}"

            new_text = pattern.sub(sub, new_text)
            if hits == 0 and required:
                print(
                    f"error: rule '{name}' matched nothing in {path} - "
                    "wording drifted; update the rule table in the script"
                )
                fatal = True
        if notes:
            stale += len(notes)
            print(f"{'fixing' if apply_mode else 'would fix'} {path}:")
            for note in notes:
                print(note)
            pending.append((path, new_text))
        else:
            print(f"ok {path} (in sync)")

    if fatal:
        return 2
    if stale == 0:
        print("all counters in sync")
        return 0
    if not apply_mode:
        print(f"{stale} stale counter(s); run with --apply to fix")
        return 1
    for path, new_text in pending:
        path.write_bytes(new_text.encode("utf-8"))
        print(f"applied: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
