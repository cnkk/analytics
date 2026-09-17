#!/usr/bin/env python3
"""
Back-test the Plausible semgrep/opengrep rules against real pull requests.

For every PR listed in expectations.yaml the harness builds two trees:

  after  = the PR head, exactly as it was merged
  before = the same head with the PR's own diff reverse-applied

Reverse-applying the PR onto its own head (rather than diffing against the base
commit) is deliberate: several of these branches were cut from an older master,
so a base..head diff drags in hundreds of unrelated files and the "before" tree
would not be the code the PR actually changed.

It then runs the ruleset over both trees and checks that each rule fires on the
vulnerable files before the fix and is silent on them after it.

Usage:
    python3 .semgrep/backtest/backtest.py                 # run everything
    python3 .semgrep/backtest/backtest.py --pr 6402       # one PR
    python3 .semgrep/backtest/backtest.py --keep          # keep the trees
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RULES = REPO / ".semgrep" / "plausible-security.yaml"
WORK = Path(os.environ.get("BACKTEST_WORKDIR", "/tmp/plausible-semgrep-backtest"))
SEMGREP = os.environ.get("SEMGREP_BIN", "semgrep")

# Only these trees are materialised; the rules never look anywhere else.
ARCHIVE_PATHS = ["lib", "assets/js", "tracker/src"]
APPLY_INCLUDES = ["lib/*", "assets/js/*", "tracker/src/*"]


def load_expectations() -> dict:
    """Minimal YAML subset reader so the harness has no pip dependencies."""
    try:
        import yaml  # type: ignore

        return yaml.safe_load((HERE / "expectations.yaml").read_text())
    except ImportError:
        pass

    data: dict = {"prs": []}
    current: dict | None = None
    list_key: str | None = None
    for raw in (HERE / "expectations.yaml").read_text().splitlines():
        line = raw.split(" #")[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if stripped.startswith("- pr:"):
            current = {"pr": int(stripped.split(":", 1)[1].strip())}
            data["prs"].append(current)
            list_key = None
        elif current is not None and indent >= 4 and stripped.startswith("- "):
            assert list_key, f"list item without key: {stripped}"
            current[list_key].append(stripped[2:].strip().strip("\"'"))
        elif current is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            key, value = key.strip(), value.strip()
            if value in ("[]", "{}"):
                current[key] = []
                list_key = None
            elif value:
                current[key] = value.strip("\"'")
                list_key = None
            else:
                current[key] = []
                list_key = key
    return data


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> str:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{proc.stderr}")
    return proc.stdout


def fetch_patch(pr: int) -> Path:
    patches = WORK / "patches"
    patches.mkdir(parents=True, exist_ok=True)
    dest = patches / f"{pr}.diff"
    if dest.exists() and dest.stat().st_size:
        return dest
    url = f"https://github.com/plausible/analytics/pull/{pr}.diff"
    with urllib.request.urlopen(url, timeout=60) as resp:
        dest.write_bytes(resp.read())
    return dest


def changed_files(patch: Path) -> set[str]:
    """Paths the PR touches, taken from the patch itself, so a rule is judged on
    the code the PR actually changed rather than on the whole tree."""
    paths: set[str] = set()
    for line in patch.read_text(errors="replace").splitlines():
        if line.startswith(("+++ b/", "--- a/")):
            candidate = line[6:].strip()
            if candidate != "/dev/null":
                paths.add(candidate)
    return paths


def build_trees(pr: int, head: str) -> tuple[Path, Path]:
    """Materialise before/ and after/ trees for one PR."""
    root = WORK / "trees" / str(pr)
    after, before = root / "after", root / "before"
    if root.exists():
        shutil.rmtree(root)
    after.mkdir(parents=True)

    # `git archive` works on a shallow-fetched commit: the tree is complete even
    # though its ancestors are not.
    run(["git", "fetch", "-q", "--depth=1", "origin", head], cwd=REPO, check=False)
    archive = subprocess.run(
        ["git", "archive", head, *ARCHIVE_PATHS],
        cwd=REPO,
        capture_output=True,
        check=True,
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(after)], input=archive, check=True)

    shutil.copytree(after, before)
    includes = [f"--include={p}" for p in APPLY_INCLUDES]
    run(["git", "apply", "-R", "-p1", *includes, str(fetch_patch(pr))], cwd=before)
    return before, after


def fingerprint(path: Path, start: int, end: int) -> str:
    """Whitespace-normalised text of the full source line(s) the match sits on.

    Two reasons not to use the line number or the matched substring alone:
    a PR that adds a moduledoc shifts every line below it, and `generic` mode
    reports only the leading token of a match (the whole `live ...` route comes
    back as the 4 bytes "live"), which would make every route look identical."""
    blob = path.read_bytes()
    line_start = blob.rfind(b"\n", 0, start) + 1
    line_end = blob.find(b"\n", end)
    line_end = len(blob) if line_end == -1 else line_end
    return " ".join(blob[line_start:line_end].decode("utf-8", "replace").split())


def scan(tree: Path) -> dict[str, Counter]:
    """rule id -> Counter of (relative path, source text).

    A Counter rather than a set so that two identical vulnerable lines in one
    file are two findings, and fixing one of them registers as progress."""
    proc = subprocess.run(
        [
            SEMGREP,
            "--metrics=off",
            "--quiet",
            "--disable-version-check",
            "--config",
            str(RULES),
            "--json",
            str(tree),
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(f"semgrep failed on {tree}:\n{proc.stderr[-4000:]}")
    payload = json.loads(proc.stdout)
    for err in payload.get("errors", []):
        print(f"    ! semgrep error: {err.get('message', err)[:200]}", file=sys.stderr)

    findings: dict[str, Counter] = defaultdict(Counter)
    for res in payload["results"]:
        rule = res["check_id"].split(".")[-1]
        abs_path = Path(res["path"])
        rel = str(abs_path.relative_to(tree))
        text = fingerprint(abs_path, res["start"]["offset"], res["end"]["offset"])
        findings[rule][(rel, text)] += 1
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr", type=int, action="append", help="limit to these PRs")
    ap.add_argument("--keep", action="store_true", help="keep the built trees")
    args = ap.parse_args()

    expectations = load_expectations()
    prs = [p for p in expectations["prs"] if not args.pr or int(p["pr"]) in args.pr]

    failures: list[str] = []
    print(f"ruleset: {RULES}")
    print(f"workdir: {WORK}\n")

    for spec in prs:
        pr = int(spec["pr"])
        title = spec.get("title", "")
        print(f"── PR #{pr} — {title}")

        before_tree, after_tree = build_trees(pr, spec["head"])
        before, after = scan(before_tree), scan(after_tree)
        changed = changed_files(fetch_patch(pr))

        for rule in spec.get("detects", []):
            hits_before = Counter(
                {f: n for f, n in before.get(rule, Counter()).items() if f[0] in changed}
            )
            hits_after = Counter(
                {f: n for f, n in after.get(rule, Counter()).items() if f[0] in changed}
            )
            fixed = hits_before - hits_after

            if not hits_before:
                failures.append(f"#{pr} {rule}: expected a hit BEFORE the fix, got none")
                print(f"   FAIL {rule}: silent on the vulnerable code")
                continue
            if not fixed:
                failures.append(
                    f"#{pr} {rule}: still fires on every location after the fix"
                )
                print(
                    f"   FAIL {rule}: {sum(hits_before.values())} before / "
                    f"{sum(hits_after.values())} after"
                )
                continue

            print(
                f"   PASS {rule}: {sum(hits_before.values())} before -> "
                f"{sum(hits_after.values())} after"
            )
            for path, text in sorted(fixed):
                print(f"          caught {path}: {text[:96]}")

        for rule in spec.get("silent", []):
            noise = [
                f
                for f in list(before.get(rule, Counter())) + list(after.get(rule, Counter()))
                if f[0] in changed
            ]
            if noise:
                failures.append(
                    f"#{pr} {rule}: expected silence on the changed files, got {len(noise)}"
                )
                print(f"   FAIL {rule}: fired on {noise[0][0]}")
            else:
                print(f"   PASS {rule}: silent on this PR's files, as expected")
        print()

    if not args.keep:
        shutil.rmtree(WORK / "trees", ignore_errors=True)

    if failures:
        print(f"{len(failures)} failure(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("all back-test expectations met")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
