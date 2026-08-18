#!/usr/bin/env python3
"""Run pyright over angr and compare the result against the checked-in baseline.

``pyright-baseline.json`` records, for every (file, rule) pair, how many diagnostics that pair is
currently allowed to produce. It deliberately stores counts rather than line numbers, so editing a
file above an existing error does not invalidate the baseline.

This is a strictly-shrinking ledger: a pair that produces more diagnostics than the baseline allows
fails the check, and ``--update`` refuses to write a baseline with a larger total than the one it
replaces. Suppressing an error with ``# type: ignore`` therefore buys nothing -- the count drops
either way, so the incentive is to fix the declaration instead.

Usage:
    python scripts/typecheck.py             # check against the baseline (this is what CI runs)
    python scripts/typecheck.py --stats     # print the current breakdown by rule, no comparison
    python scripts/typecheck.py --update    # lock in an improvement
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "pyright-baseline.json"


def run_pyright(targets: list[str]) -> list[dict]:
    proc = subprocess.run(
        # --pythonpath pins import resolution to the interpreter this script runs under. Without it
        # pyright picks an interpreter of its own choosing, misses angr's dependencies, and reports
        # hundreds of phantom reportMissingImports.
        [sys.executable, "-m", "pyright", "--outputjson", "--pythonpath", sys.executable, *targets],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if "{" not in proc.stdout:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit("pyright produced no JSON report")
    # pyright and its dependencies occasionally print to stdout before the report.
    return json.loads(proc.stdout[proc.stdout.index("{") :])["generalDiagnostics"]


def tally(diagnostics: list[dict]) -> dict[str, dict[str, int]]:
    counts: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for diag in diagnostics:
        if diag["severity"] != "error":
            continue
        path = Path(diag["file"]).resolve().relative_to(REPO_ROOT).as_posix()
        counts[path][diag.get("rule", "<no-rule>")] += 1
    return {path: dict(sorted(rules.items())) for path, rules in sorted(counts.items())}


def total_of(counts: dict[str, dict[str, int]]) -> int:
    return sum(sum(rules.values()) for rules in counts.values())


def load_baseline() -> dict[str, dict[str, int]]:
    if not BASELINE_PATH.exists():
        return {}
    return json.loads(BASELINE_PATH.read_text())["counts"]


def compare(current: dict[str, dict[str, int]], baseline: dict[str, dict[str, int]]) -> tuple[list[str], list[str]]:
    regressions, improvements = [], []
    for path in sorted(set(current) | set(baseline)):
        cur, base = current.get(path, {}), baseline.get(path, {})
        for rule in sorted(set(cur) | set(base)):
            now, then = cur.get(rule, 0), base.get(rule, 0)
            if now > then:
                regressions.append(f"{path}: {rule}: {then} -> {now}")
            elif now < then:
                improvements.append(f"{path}: {rule}: {then} -> {now}")
    return regressions, improvements


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="rewrite the baseline from this run")
    parser.add_argument("--stats", action="store_true", help="print a breakdown by rule and exit")
    parser.add_argument("targets", nargs="*", help="paths to check (default: the whole project)")
    args = parser.parse_args()

    current = tally(run_pyright(args.targets))
    total = total_of(current)

    if args.stats:
        by_rule: collections.Counter[str] = collections.Counter()
        for rules in current.values():
            by_rule.update(rules)
        for rule, count in by_rule.most_common():
            print(f"{count:7d}  {rule}")
        print(f"{total:7d}  TOTAL, across {len(current)} files")
        return 0

    if args.targets:
        # A partial run cannot distinguish "this file improved" from "this file was not checked".
        raise SystemExit("--update and the baseline comparison require a full run; drop the paths")

    baseline = load_baseline()
    baseline_total = total_of(baseline)
    regressions, improvements = compare(current, baseline)

    if args.update:
        if baseline and total > baseline_total:
            print(f"refusing: baseline would grow, {baseline_total} -> {total}", file=sys.stderr)
            return 1
        BASELINE_PATH.write_text(json.dumps({"total": total, "counts": current}, indent=1, sort_keys=True) + "\n")
        print(f"baseline updated: {baseline_total} -> {total}")
        return 0

    for line in improvements:
        print(f"fixed:      {line}")
    for line in regressions:
        print(f"REGRESSED:  {line}")
    print(f"\npyright errors: {total} (baseline {baseline_total})")

    if regressions:
        print(
            f"\n{len(regressions)} (file, rule) pairs regressed. Fix the declaration that causes them; "
            f"if the new error is genuinely unavoidable, say why in the PR and run --update.",
            file=sys.stderr,
        )
        return 1
    if improvements:
        print(f"{len(improvements)} pairs improved -- run --update to lock the gain in.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
