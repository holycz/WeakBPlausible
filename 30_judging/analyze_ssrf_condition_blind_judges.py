#!/usr/bin/env python3
"""Analyze the paired condition-blind SSRF judge runs."""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


LABELS = ("SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID")
ORIGINAL = Path("results/experiments/ssrf_condition_blind_original_v01/judged_queue.jsonl")
GPT56 = Path("results/experiments/ssrf_condition_blind_gpt56_v01/judged_queue.jsonl")
OUT = Path("results/experiments/SSRF_CONDITION_BLIND_JUDGE_COMPARISON_v01")


def read(path: Path) -> dict[str, dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return {row["sample_id"]: row for row in rows}


def paired_transitions(rows: dict[str, dict]) -> Counter:
    indexed = {
        (row["dataset"], row["seed"], row["cve_id"], row["setting"]): row["judge_label"]
        for row in rows.values()
    }
    logical = {(row["dataset"], row["seed"], row["cve_id"]) for row in rows.values()}
    transitions = Counter()
    for key in logical:
        prompt = indexed.get((*key, "prompt-only"))
        guided = indexed.get((*key, "verifier-guided"))
        if prompt and guided:
            transitions[(prompt, guided)] += 1
    return transitions


def duplicate_stability(rows: dict[str, dict]) -> tuple[list[list[dict]], list[list[dict]]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows.values():
        groups[row["blind_id"]].append(row)
    repeated = [group for group in groups.values() if len(group) > 1]
    inconsistent = [group for group in repeated if len({row["judge_label"] for row in group}) > 1]
    return repeated, inconsistent


def main() -> None:
    original = read(ORIGINAL)
    gpt56 = read(GPT56)
    if len(original) != 107 or set(original) != set(gpt56):
        raise SystemExit("expected identical sets of 107 samples")
    OUT.mkdir(parents=True, exist_ok=True)

    matrix = {label: Counter() for label in LABELS}
    rows = []
    for sample_id in original:
        left, right = original[sample_id], gpt56[sample_id]
        matrix[left["judge_label"]][right["judge_label"]] += 1
        rows.append({
            "sample_id": sample_id,
            "blind_id": left["blind_id"],
            "dataset": left["dataset"],
            "setting": left["setting"],
            "seed": left["seed"],
            "cve_id": left["cve_id"],
            "original_label": left["judge_label"],
            "gpt56_label": right["judge_label"],
            "agreement": left["judge_label"] == right["judge_label"],
            "original_rationale": left["judge_rationale"],
            "gpt56_rationale": right["judge_rationale"],
            "original_response_id": left["response_id"],
            "gpt56_response_id": right["response_id"],
        })
    with (OUT / "comparison.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    counts = {
        "original": Counter(row["judge_label"] for row in original.values()),
        "gpt56": Counter(row["judge_label"] for row in gpt56.values()),
    }
    observed = sum(row["agreement"] for row in rows) / 107
    expected = sum(counts["original"][label] * counts["gpt56"][label] for label in LABELS) / 107**2
    kappa = (observed - expected) / (1 - expected)
    binary = sum(
        (row["original_label"] == "SAFE_FIX") == (row["gpt56_label"] == "SAFE_FIX")
        for row in rows
    ) / 107
    original_repeated, original_inconsistent = duplicate_stability(original)
    gpt_repeated, gpt_inconsistent = duplicate_stability(gpt56)
    original_transitions = paired_transitions(original)
    gpt_transitions = paired_transitions(gpt56)

    summary = {
        "records": 107,
        "unique_blind_ids": len({row["blind_id"] for row in original.values()}),
        "label_counts": {name: dict(value) for name, value in counts.items()},
        "exact_agreement": observed,
        "cohens_kappa": kappa,
        "safe_vs_non_safe_agreement": binary,
        "matrix": {label: dict(matrix[label]) for label in LABELS},
        "duplicate_groups": len(original_repeated),
        "duplicate_records_beyond_first": sum(len(group) - 1 for group in original_repeated),
        "original_inconsistent_duplicate_groups": len(original_inconsistent),
        "gpt56_inconsistent_duplicate_groups": len(gpt_inconsistent),
        "original_paired_transitions": {f"{a}->{b}": value for (a, b), value in original_transitions.items()},
        "gpt56_paired_transitions": {f"{a}->{b}": value for (a, b), value in gpt_transitions.items()},
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Condition-Blind Judge Comparison",
        "",
        "Both judges received the original rubric, input fields, temperature, token limit, and",
        "one-candidate-per-request protocol. Only the condition-bearing `Sample:` value was replaced",
        "with a deterministic content-derived blind ID. Identical visible inputs therefore share an ID.",
        "",
        "## Label totals",
        "",
        "| Label | Original model | GPT-5.6 |",
        "|---|---:|---:|",
    ]
    lines.extend(f"| {label} | {counts['original'][label]} | {counts['gpt56'][label]} |" for label in LABELS)
    lines.extend([
        "",
        "## Cross-model matrix",
        "",
        "| Original / GPT-5.6 | SAFE_FIX | UNSAFE_PLAUSIBLE | INVALID |",
        "|---|---:|---:|---:|",
    ])
    lines.extend(
        f"| {label} | {matrix[label]['SAFE_FIX']} | {matrix[label]['UNSAFE_PLAUSIBLE']} | {matrix[label]['INVALID']} |"
        for label in LABELS
    )
    lines.extend([
        "",
        f"- Exact three-way agreement: {sum(row['agreement'] for row in rows)}/107 ({observed * 100:.1f}%).",
        f"- Cohen's kappa: {kappa:.3f}.",
        f"- Binary Safe versus non-Safe agreement: {binary * 100:.1f}%.",
        f"- Original Weak/non-Invalid rate: {counts['original']['UNSAFE_PLAUSIBLE']}/{107-counts['original']['INVALID']} ({counts['original']['UNSAFE_PLAUSIBLE']/(107-counts['original']['INVALID'])*100:.1f}%).",
        f"- GPT-5.6 Weak/non-Invalid rate: {counts['gpt56']['UNSAFE_PLAUSIBLE']}/{107-counts['gpt56']['INVALID']} ({counts['gpt56']['UNSAFE_PLAUSIBLE']/(107-counts['gpt56']['INVALID'])*100:.1f}%).",
        f"- Unique blind IDs: {summary['unique_blind_ids']}; this reflects {summary['duplicate_records_beyond_first']} duplicate visible inputs, not hash collisions.",
        f"- Identical-input groups with inconsistent original labels: {len(original_inconsistent)}/{len(original_repeated)}.",
        f"- Identical-input groups with inconsistent GPT-5.6 labels: {len(gpt_inconsistent)}/{len(gpt_repeated)}.",
        "",
        "Neither judge is ground truth. The low kappa is partly driven by the original model's strong",
        "prevalence toward Weak, but the matrix also contains substantive Safe/Invalid disagreements.",
    ])
    (OUT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
