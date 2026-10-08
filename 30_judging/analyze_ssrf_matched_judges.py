#!/usr/bin/env python3
"""Compare the original SSRF judge with a protocol-matched GPT-5.6 judge."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


LABELS = ("SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", default="results/experiments/SSRF_JUDGED_QUEUE_UNIFIED_v01.jsonl")
    parser.add_argument("--second", default="results/experiments/ssrf_gpt56_matched_judge_v01/judged_queue.jsonl")
    parser.add_argument("--out-dir", default="results/experiments/ssrf_gpt56_matched_judge_v01")
    args = parser.parse_args()

    original = {row["sample_id"]: row for row in read_jsonl(Path(args.original))}
    second = {row["sample_id"]: row for row in read_jsonl(Path(args.second))}
    if len(original) != 107 or set(original) != set(second):
        raise SystemExit("judge queues do not contain the same 107 unique samples")

    matrix = {label: Counter() for label in LABELS}
    rows = []
    for sample_id in original:
        first = original[sample_id]
        other = second[sample_id]
        matrix[first["judge_label"]][other["judge_label"]] += 1
        rows.append(
            {
                "sample_id": sample_id,
                "dataset": first["dataset"],
                "setting": first["setting"],
                "seed": first["seed"],
                "cve_id": first["cve_id"],
                "original_label": first["judge_label"],
                "gpt56_label": other["judge_label"],
                "agreement": first["judge_label"] == other["judge_label"],
                "original_rationale": first.get("judge_rationale", ""),
                "gpt56_rationale": other.get("judge_rationale", ""),
                "response_id": other.get("response_id", ""),
                "response_model": other.get("response_model", ""),
                "request_sha256": other.get("request_sha256", ""),
            }
        )

    first_counts = Counter(row["original_label"] for row in rows)
    second_counts = Counter(row["gpt56_label"] for row in rows)
    observed = sum(row["agreement"] for row in rows) / len(rows)
    expected = sum(first_counts[label] * second_counts[label] for label in LABELS) / len(rows) ** 2
    kappa = (observed - expected) / (1 - expected) if expected != 1 else 1.0
    binary = sum(
        (row["original_label"] == "SAFE_FIX") == (row["gpt56_label"] == "SAFE_FIX")
        for row in rows
    ) / len(rows)

    by_case: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_case[row["cve_id"]].append(row)

    patch_groups: dict[str, list[str]] = defaultdict(list)
    for sample_id, row in second.items():
        patch_groups[hashlib.sha256(row["agent_fixed"].encode()).hexdigest()].append(sample_id)
    repeated_groups = [sample_ids for sample_ids in patch_groups.values() if len(sample_ids) > 1]
    original_repeat_disagreement = sum(
        len({original[sample_id]["judge_label"] for sample_id in sample_ids}) > 1
        for sample_ids in repeated_groups
    )
    second_repeat_disagreement = sum(
        len({second[sample_id]["judge_label"] for sample_id in sample_ids}) > 1
        for sample_ids in repeated_groups
    )

    out_dir = Path(args.out_dir)
    with (out_dir / "MATCHED_JUDGE_COMPARISON.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# Protocol-Matched GPT-5.6 Judge Comparison",
        "",
        "GPT-5.6 received the original system prompt and user-prompt format. Each candidate",
        "was sent in a separate `/chat/completions` request with temperature 0, max_tokens 180,",
        "and no tools. Raw responses and request hashes are retained.",
        "",
        "## Label totals",
        "",
        "| Label | Original judge | GPT-5.6 matched judge |",
        "|---|---:|---:|",
    ]
    lines.extend(f"| {label} | {first_counts[label]} | {second_counts[label]} |" for label in LABELS)
    lines.extend([
        "",
        "## Cross-judge matrix",
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
        f"- Returned model identifiers: {dict(Counter(row['response_model'] for row in rows))}.",
        f"- Unique response IDs: {len({row['response_id'] for row in rows})}/107.",
        f"- Unique request hashes: {len({row['request_sha256'] for row in rows})}/107.",
        f"- Weak among GPT-5.6 non-Invalid labels: {second_counts['UNSAFE_PLAUSIBLE']}/{107 - second_counts['INVALID']} ({second_counts['UNSAFE_PLAUSIBLE'] / (107 - second_counts['INVALID']) * 100:.1f}%).",
        f"- Repeated identical-patch groups: {len(repeated_groups)}.",
        f"- Repeated groups with different original-judge labels: {original_repeat_disagreement}.",
        f"- Repeated groups with different GPT-5.6 labels: {second_repeat_disagreement}.",
        "",
        "The original prompt exposes the experimental condition through `Sample:` identifiers",
        "containing `prompt-only` or `verifier-guided`; this matched run preserves that behavior.",
        "It is therefore protocol-matched but not condition-blinded.",
        "",
        "This comparison controls the prompt and request protocol, but neither LLM judge is",
        "ground truth. Repository execution and human/code-level adjudication remain necessary",
        "for resolving disagreements.",
    ])
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"agreement={observed:.6f} kappa={kappa:.6f} binary={binary:.6f}")


if __name__ == "__main__":
    main()
