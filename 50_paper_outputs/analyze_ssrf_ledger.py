"""Report case-aware descriptive statistics for an SSRF evidence ledger.

The ledger contains repeated runs over the same underlying cases. This tool
reports row-level counts and a case-resampling descriptive range for the
automatic weak-label rate. The range is not a population
estimate.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

SAFE = "SAFE_FIX"
WEAK = "UNSAFE_PLAUSIBLE"
EXPLICIT_INVALID_RATIONALE_PATTERNS = (
    "syntax error",
    "fatal error",
    "runtime error",
    "undefined",
    "malformed code",
)


def read(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def weak_rate(rows: list[dict]) -> float | None:
    non_invalid = [row for row in rows if row.get("judge_label") in {SAFE, WEAK}]
    if not non_invalid:
        return None
    return sum(row["judge_label"] == WEAK for row in non_invalid) / len(non_invalid)


def has_explicit_invalid_defect(row: dict) -> bool:
    rationale = (row.get("judge_rationale") or "").lower()
    return any(term in rationale for term in EXPLICIT_INVALID_RATIONALE_PATTERNS)


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (
        position - lower
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ledger",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v03_CONDITION_BLIND.jsonl",
    )
    parser.add_argument(
        "--out",
        default="results/experiments/SSRF_LEDGER_CASE_STATS_v05_CONDITION_BLIND.md",
    )
    parser.add_argument("--resamples", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260830)
    args = parser.parse_args()

    rows = read(Path(args.ledger))
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["cve_id"]].append(row)

    labels = Counter(row.get("judge_label") for row in rows if row.get("judge_label"))
    non_invalid = labels[SAFE] + labels[WEAK]
    observed = labels[WEAK] / non_invalid if non_invalid else None
    contradictory_weak = [
        row
        for row in rows
        if row.get("judge_label") == WEAK and has_explicit_invalid_defect(row)
    ]
    sensitivity_denominator = non_invalid - len(contradictory_weak)
    sensitivity_weak = labels[WEAK] - len(contradictory_weak)
    clusters = list(groups.values())
    rng = random.Random(args.seed)
    bootstrap: list[float] = []
    for _ in range(args.resamples):
        sampled = [
            row
            for cluster in (rng.choice(clusters) for _ in clusters)
            for row in cluster
        ]
        value = weak_rate(sampled)
        if value is not None:
            bootstrap.append(value)

    lines = [
        "# Case-Aware SSRF Ledger Statistics",
        "",
        "Statistics are descriptive over repeated runs of the same cases.",
        "The case-resampling range resamples underlying case IDs, not individual rows.",
        "",
        f"- Total run records: {len(rows)}",
        f"- Underlying cases (CVE IDs): {len(groups)}",
        f"- Judged records: {sum(labels.values())}",
        f"- Non-Invalid automatic labels: {non_invalid}",
        f"- Row-level weak-label rate: {observed:.1%}"
        if observed is not None
        else "- Row-level weak-label rate: n/a",
        f"- Weak rationales with explicit Invalid-class defects: "
        f"{len(contradictory_weak)}",
        f"- Sensitivity rate after excluding those contradictions: "
        f"{sensitivity_weak}/{sensitivity_denominator} "
        f"({sensitivity_weak / sensitivity_denominator:.1%})",
        "- Sensitivity-excluded record IDs:",
        *[f"  - `{row['record_id']}`" for row in contradictory_weak],
    ]
    if bootstrap:
        lines.append(
            f"- Case-resampling descriptive 95% range: "
            f"{percentile(bootstrap, 0.025):.1%}--"
            f"{percentile(bootstrap, 0.975):.1%}"
        )
    lines.extend(
        [
            "",
            "| Case | Dataset | Records | Safe | Weak | Invalid | Unjudged |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for case_id in sorted(groups):
        case_rows = groups[case_id]
        local = Counter(row.get("judge_label") for row in case_rows)
        dataset = "/".join(sorted({row["dataset"] for row in case_rows}))
        lines.append(
            f"| {case_id} | {dataset} | {len(case_rows)} | "
            f"{local[SAFE]} | {local[WEAK]} | {local['INVALID']} | "
            f"{local[None]} |"
        )

    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
