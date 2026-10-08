"""Compare second-pass SSRF controls with delivery outcomes separated."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


LABELS = ("SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def summarize(raw_path: Path, judged_path: Path) -> dict:
    raw = read_jsonl(raw_path)
    judged = read_jsonl(judged_path)
    ok_ids = {row["cve_id"] for row in raw if row.get("status") == "OK"}
    labels = Counter(
        row.get("judge_label")
        for row in judged
        if row.get("judge_label") and row.get("cve_id") in ok_ids
    )
    status = Counter(row.get("status") for row in raw)
    usable = labels["SAFE_FIX"] + labels["UNSAFE_PLAUSIBLE"]
    weak_rate = labels["UNSAFE_PLAUSIBLE"] / usable if usable else None
    return {
        "raw_path": str(raw_path),
        "judged_path": str(judged_path),
        "runs": len(raw),
        "status": status,
        "judged": sum(labels.values()),
        "labels": labels,
        "usable": usable,
        "weak_rate": weak_rate,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--prompt-raw",
        default="results/experiments/ssrf_seed/opencode_dsv4_prompt_only.jsonl",
    )
    ap.add_argument(
        "--prompt-judged",
        default="results/experiments/ssrf_seed/prompt_only_judged.jsonl",
    )
    ap.add_argument(
        "--verifier-raw",
        default="results/experiments/ssrf_seed/opencode_dsv4_verifier_guided.jsonl",
    )
    ap.add_argument(
        "--verifier-judged",
        default="results/experiments/ssrf_seed/verifier_guided_judged.jsonl",
    )
    ap.add_argument(
        "--neutral-raw",
        default="results/experiments/ssrf_seed/opencode_dsv4_neutral_second_pass_v01.jsonl",
    )
    ap.add_argument(
        "--neutral-judged",
        default="results/experiments/ssrf_seed/neutral_second_pass_judged_v01.jsonl",
    )
    ap.add_argument(
        "--out",
        default="results/experiments/SSRF_SECOND_PASS_CONTROL_v01.md",
    )
    args = ap.parse_args()

    groups = [
        ("prompt-only", summarize(Path(args.prompt_raw), Path(args.prompt_judged))),
        ("verifier-guided", summarize(Path(args.verifier_raw), Path(args.verifier_judged))),
        ("neutral-second-pass", summarize(Path(args.neutral_raw), Path(args.neutral_judged))),
    ]
    lines = [
        "# SSRF Second-Pass Control",
        "",
        "This table compares the original cross-language 10-case prompt-only",
        "wave with the existing verifier-guided second pass and the neutral",
        "second-pass control. Delivery outcomes and semantic labels are separated.",
        "",
        "| Condition | Runs | OK | NO_WRITE | TIMEOUT | Judged OK | Safe | Weak | Invalid | Weak / usable |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, summary in groups:
        labels = summary["labels"]
        weak_rate = (
            f"{summary['weak_rate']:.1%}" if summary["weak_rate"] is not None else "n/a"
        )
        lines.append(
            f"| {name} | {summary['runs']} | {summary['status']['OK']} | "
            f"{summary['status']['NO_WRITE']} | {summary['status']['TIMEOUT']} | "
            f"{summary['judged']} | {labels['SAFE_FIX']} | "
            f"{labels['UNSAFE_PLAUSIBLE']} | {labels['INVALID']} | "
            f"{labels['UNSAFE_PLAUSIBLE']} / {summary['usable']} ({weak_rate}) |"
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
