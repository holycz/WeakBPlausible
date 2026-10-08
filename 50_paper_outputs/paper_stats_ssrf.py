"""Create paper-facing descriptive statistics for the current SSRF pilot.

No labels are inferred here. The script only aggregates labels already present
in the local judge files and reports exact counts plus Wilson intervals.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


LABELS = ("SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID")


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def wilson(successes: int, total: int, z: float = 1.96) -> str:
    if total == 0:
        return "n/a"
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return f"{100 * p:.1f}% [{100 * (center - margin):.1f}, {100 * (center + margin):.1f}]"


def summarize(rows: list[dict]) -> dict[str, int]:
    return {label: Counter(row.get("judge_label") for row in rows)[label] for label in LABELS}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--php-dir", default="results/experiments/php_ssrf_frozen")
    ap.add_argument("--real-dir", default="results/experiments/ssrf_seed")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    php_dir = Path(args.php_dir)
    prompt_files = [
        php_dir / "prompt_only_judged.jsonl",
        php_dir / "prompt_only_seed2_judged.jsonl",
        php_dir / "prompt_only_seed3_judged.jsonl",
    ]
    verifier_files = [
        php_dir / "verifier_guided_judged.jsonl",
        php_dir / "verifier_guided_seed2_judged.jsonl",
        php_dir / "verifier_guided_seed3_judged.jsonl",
    ]
    php_prompt = sum((read_jsonl(path) for path in prompt_files), [])
    php_verifier = sum((read_jsonl(path) for path in verifier_files), [])
    real_prompt = read_jsonl(Path(args.real_dir) / "prompt_only_judged.jsonl")
    real_verifier = read_jsonl(Path(args.real_dir) / "verifier_guided_judged.jsonl")

    lines = [
        "# Paper-Facing SSRF Pilot Statistics",
        "",
        "Generated on 2026-08-29. Counts use existing external-judge labels; "
        "they are provisional until blinded human double-labeling.",
        "",
        "## PHP Frozen Set: 3 Independent Seeds",
        "",
        "| Setting | N | SAFE_FIX | UNSAFE_PLAUSIBLE | INVALID | Non-safe |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, rows in (("Prompt-only", php_prompt), ("Verifier-guided", php_verifier)):
        s = summarize(rows)
        lines.append(
            f"| {name} | {len(rows)} | {s['SAFE_FIX']} | {s['UNSAFE_PLAUSIBLE']} | "
            f"{s['INVALID']} | {len(rows) - s['SAFE_FIX']} |"
        )

    lines.extend(
        [
            "",
            "### Conditional Weak-Repair Rate",
            "",
            "The denominator excludes INVALID outputs, because an invalid/no-patch "
            "output is a different failure mode from a usable but bypassable patch.",
            "",
            "| Setting | Weak / judged usable | Rate (95% Wilson CI) |",
            "|---|---:|---:|",
        ]
    )
    for name, rows in (("Prompt-only", php_prompt), ("Verifier-guided", php_verifier)):
        s = summarize(rows)
        usable = s["SAFE_FIX"] + s["UNSAFE_PLAUSIBLE"]
        lines.append(
            f"| {name} | {s['UNSAFE_PLAUSIBLE']} / {usable} | "
            f"{wilson(s['UNSAFE_PLAUSIBLE'], usable)} |"
        )

    by_case: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for setting, rows in (("Prompt-only", php_prompt), ("Verifier-guided", php_verifier)):
        for row in rows:
            by_case[row["cve_id"]][setting][row.get("judge_label", "UNJUDGED")] += 1
    lines.extend(
        [
            "",
            "### Per-Case Repetition",
            "",
            "| CVE | Setting | N | SAFE | WEAK | INVALID | Runs with >=1 non-safe |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for cve_id in sorted(by_case):
        for setting in ("Prompt-only", "Verifier-guided"):
            counts = by_case[cve_id][setting]
            total = sum(counts.values())
            non_safe = total - counts["SAFE_FIX"]
            lines.append(
                f"| {cve_id} | {setting} | {total} | {counts['SAFE_FIX']} | "
                f"{counts['UNSAFE_PLAUSIBLE']} | {counts['INVALID']} | "
                f"{1 if non_safe else 0} / 3 |"
            )

    lines.extend(
        [
            "",
            "## Real Cross-Language Seed: One Run per Case",
            "",
            "| Setting | N | SAFE_FIX | UNSAFE_PLAUSIBLE | INVALID | Weak among usable |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for name, rows in (("Prompt-only", real_prompt), ("Verifier-guided", real_verifier)):
        s = summarize(rows)
        usable = s["SAFE_FIX"] + s["UNSAFE_PLAUSIBLE"]
        lines.append(
            f"| {name} | {len(rows)} | {s['SAFE_FIX']} | {s['UNSAFE_PLAUSIBLE']} | "
            f"{s['INVALID']} | {s['UNSAFE_PLAUSIBLE']} / {usable} "
            f"({wilson(s['UNSAFE_PLAUSIBLE'], usable)}) |"
        )

    lines.extend(
        [
            "",
            "## Claims Supported Now",
            "",
            "1. On the current four-case PHP pilot, non-safe outcomes recur across "
            "independent runs rather than appearing as a single outlier.",
            "2. Among outputs judged usable, bypassable-looking repairs are common "
            "in both prompt-only and verifier-guided settings.",
            "3. The current prose verifier does not yet establish a security gain; "
            "its effect is better described as changing delivery/failure shape.",
            "4. The ten-case cross-language seed provides external-form evidence that "
            "the phenomenon is not unique to one PHP project, but its one-run-per-case "
            "design cannot establish run-to-run stability.",
            "",
            "## Claims Not Supported Yet",
            "",
            "- prevalence over all coding agents or LLMs;",
            "- superiority or inferiority relative to human developers;",
            "- statistically significant improvement from the verifier;",
            "- final safety labels without blinded human double-labeling.",
        ]
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote statistics -> {out}")


if __name__ == "__main__":
    main()
