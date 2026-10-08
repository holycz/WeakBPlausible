#!/usr/bin/env python3
"""Create a single machine-checkable source for all numbers used in the paper."""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


SAFE = "SAFE_FIX"
WEAK = "UNSAFE_PLAUSIBLE"
INVALID = "INVALID"
EXPLICIT_INVALID_RATIONALE_PATTERNS = (
    "syntax error",
    "fatal error",
    "runtime error",
    "undefined",
    "malformed code",
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def distribution(rows: list[dict]) -> dict[str, int]:
    counts = Counter(row.get("judge_label") for row in rows)
    return {SAFE: counts[SAFE], WEAK: counts[WEAK], INVALID: counts[INVALID]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ledger",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v03_CONDITION_BLIND.jsonl",
    )
    parser.add_argument(
        "--gpt56",
        default="results/experiments/ssrf_condition_blind_gpt56_v01/judged_queue.jsonl",
    )
    parser.add_argument(
        "--comparison",
        default="results/experiments/SSRF_CONDITION_BLIND_JUDGE_COMPARISON_v01/summary.json",
    )
    parser.add_argument(
        "--failure-counts",
        default="results/experiments/SSRF_FAILURE_PATTERN_COUNTS_v03_CONDITION_BLIND.json",
    )
    parser.add_argument(
        "--out",
        default="results/experiments/SSRF_PAPER_NUMBERS_v03_CONDITION_BLIND.json",
    )
    args = parser.parse_args()

    ledger = read_jsonl(Path(args.ledger))
    primary = [row for row in ledger if row.get("status") == "OK"]
    gpt56 = read_jsonl(Path(args.gpt56))
    comparison = json.loads(Path(args.comparison).read_text(encoding="utf-8"))
    failure_counts = json.loads(Path(args.failure_counts).read_text(encoding="utf-8"))

    assert len(ledger) == 128
    assert len(primary) == len(gpt56) == 107
    assert distribution(primary) == {SAFE: 8, WEAK: 98, INVALID: 1}
    assert distribution(gpt56) == {SAFE: 22, WEAK: 71, INVALID: 14}

    status = Counter(row["status"] for row in ledger)
    datasets = Counter(row["dataset"] for row in ledger)
    conditions: dict[str, dict[str, int]] = {}
    for dataset, setting in sorted({(r["dataset"], r["setting"]) for r in ledger}):
        rows = [r for r in ledger if r["dataset"] == dataset and r["setting"] == setting]
        emitted = [r for r in rows if r["status"] == "OK"]
        conditions[f"{dataset}/{setting}"] = {
            "slots": len(rows),
            "emitted": len(emitted),
            "no_write": sum(r["status"] == "NO_WRITE" for r in rows),
            "timeout": sum(r["status"] == "TIMEOUT" for r in rows),
            **distribution(emitted),
        }

    by_case_condition: dict[tuple[str, str], list[dict]] = defaultdict(list)
    by_case: dict[str, list[dict]] = defaultdict(list)
    for row in ledger:
        by_case_condition[(row["cve_id"], row["setting"])].append(row)
        by_case[row["cve_id"]].append(row)
    recurrent = {
        setting: sum(
            sum(r.get("judge_label") == WEAK for r in by_case_condition[(case, setting)]) >= 2
            for case in by_case
        )
        for setting in ("prompt-only", "verifier-guided")
    }
    both_recurrent = sum(
        all(
            sum(r.get("judge_label") == WEAK for r in by_case_condition[(case, setting)]) >= 2
            for setting in ("prompt-only", "verifier-guided")
        )
        for case in by_case
    )
    cases_with_weak = sum(any(r.get("judge_label") == WEAK for r in rows) for rows in by_case.values())
    cases_with_safe = sum(any(r.get("judge_label") == SAFE for r in rows) for rows in by_case.values())

    paired: dict[tuple[str, str, str], dict[str, dict]] = defaultdict(dict)
    for row in ledger:
        paired[(row["dataset"], row["cve_id"], str(row["seed"]))][row["setting"]] = row
    assert len(paired) == 64
    both_emitted = []
    transitions = Counter()
    for pair in paired.values():
        if pair["prompt-only"]["status"] == "OK" and pair["verifier-guided"]["status"] == "OK":
            both_emitted.append(pair)
            transitions[
                f'{pair["prompt-only"]["judge_label"]}->{pair["verifier-guided"]["judge_label"]}'
            ] += 1
    assert len(both_emitted) == 44

    gpt_by_condition: dict[str, dict[str, int]] = {}
    for dataset, setting in sorted({(r["dataset"], r["setting"]) for r in gpt56}):
        rows = [r for r in gpt56 if r["dataset"] == dataset and r["setting"] == setting]
        gpt_by_condition[f"{dataset}/{setting}"] = {"emitted": len(rows), **distribution(rows)}

    primary_counts = distribution(primary)
    gpt_counts = distribution(gpt56)
    contradictory_weak = [
        row
        for row in primary
        if row.get("judge_label") == WEAK
        and any(
            term in (row.get("judge_rationale") or "").lower()
            for term in EXPLICIT_INVALID_RATIONALE_PATTERNS
        )
    ]
    assert len(contradictory_weak) == 7
    payload = {
        "source_ledger": args.ledger,
        "retained_slots": len(ledger),
        "model_invocations_after_retries": 147,
        "datasets": dict(datasets),
        "status": dict(status),
        "primary": {
            "counts": primary_counts,
            "non_invalid": primary_counts[SAFE] + primary_counts[WEAK],
            "weak_among_non_invalid": primary_counts[WEAK] / (primary_counts[SAFE] + primary_counts[WEAK]),
            "rubric_consistency_sensitivity": {
                "excluded_defect_bearing_weak": len(contradictory_weak),
                "weak": primary_counts[WEAK] - len(contradictory_weak),
                "non_invalid": primary_counts[SAFE] + primary_counts[WEAK] - len(contradictory_weak),
                "rate": (primary_counts[WEAK] - len(contradictory_weak))
                / (primary_counts[SAFE] + primary_counts[WEAK] - len(contradictory_weak)),
                "record_ids": [row["record_id"] for row in contradictory_weak],
            },
            "conditions": conditions,
        },
        "rq1": {
            "cases": len(by_case),
            "cases_with_at_least_one_weak": cases_with_weak,
            "cases_with_at_least_two_weak_prompt_only": recurrent["prompt-only"],
            "cases_with_at_least_two_weak_guided": recurrent["verifier-guided"],
            "cases_with_at_least_two_weak_both": both_recurrent,
            "cases_with_safe": cases_with_safe,
            "cases_without_safe": len(by_case) - cases_with_safe,
        },
        "rq2": failure_counts,
        "rq3": {
            "planned_pairs": len(paired),
            "both_emitted_pairs": len(both_emitted),
            "transitions": dict(transitions),
            "prompt_emitted": sum(r["status"] == "OK" and r["setting"] == "prompt-only" for r in ledger),
            "guided_emitted": sum(r["status"] == "OK" and r["setting"] == "verifier-guided" for r in ledger),
        },
        "gpt56_sensitivity": {
            "counts": gpt_counts,
            "non_invalid": gpt_counts[SAFE] + gpt_counts[WEAK],
            "weak_among_non_invalid": gpt_counts[WEAK] / (gpt_counts[SAFE] + gpt_counts[WEAK]),
            "conditions": gpt_by_condition,
            "exact_agreement": comparison["exact_agreement"],
            "safe_vs_non_safe_agreement": comparison["safe_vs_non_safe_agreement"],
            "cohens_kappa": comparison["cohens_kappa"],
            "unique_blind_ids": comparison["unique_blind_ids"],
        },
        "dynamic": {
            "agent": {"PASS": 1, "WEAK": 6, "INVALID": 2, "REGRESSION": 1},
            "reference": {"PASS": 9, "NC": 1},
        },
    }
    Path(args.out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
