"""Paired, case-aware analysis of prompt-only and verifier-guided SSRF runs."""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def outcome(row: dict) -> str:
    if row.get("status") != "OK":
        return row.get("status") or "DELIVERY_FAILURE"
    return row.get("judge_label") or "UNJUDGED"


def exact_two_sided_binomial(b: int, c: int) -> float:
    """Two-sided exact sign/McNemar test for discordant paired outcomes."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(0, min(b, c) + 1)) / (2**n)
    return min(1.0, 2 * tail)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ledger", default="results/experiments/SSRF_EVIDENCE_LEDGER_v02.jsonl")
    ap.add_argument("--out", default="results/experiments/SSRF_PAIRED_ANALYSIS_v01.md")
    args = ap.parse_args()
    rows = read_jsonl(Path(args.ledger))
    keyed = {(r["dataset"], r["cve_id"], str(r["seed"]), r["setting"]): r for r in rows}
    pairs = []
    for dataset, cve, seed, setting in sorted(keyed):
        if setting != "prompt-only":
            continue
        other = keyed.get((dataset, cve, seed, "verifier-guided"))
        if other:
            pairs.append((keyed[(dataset, cve, seed, setting)], other))

    transitions = Counter((outcome(a), outcome(b)) for a, b in pairs)
    # Security success is intentionally strict: delivery succeeded and judge said SAFE_FIX.
    prompt_safe = sum(outcome(a) == "SAFE_FIX" for a, _ in pairs)
    guided_safe = sum(outcome(b) == "SAFE_FIX" for _, b in pairs)
    lost = sum(outcome(a) == "SAFE_FIX" and outcome(b) != "SAFE_FIX" for a, b in pairs)
    gained = sum(outcome(a) != "SAFE_FIX" and outcome(b) == "SAFE_FIX" for a, b in pairs)
    pvalue = exact_two_sided_binomial(lost, gained)
    by_dataset = defaultdict(list)
    for pair in pairs:
        by_dataset[pair[0]["dataset"]].append(pair)

    lines = [
        "# Paired SSRF Repair Analysis", "",
        "Each pair uses the same dataset, CVE, and recorded seed under prompt-only and verifier-guided conditions.",
        "Automatic semantic labels remain provisional.", "",
        f"- Complete pairs: {len(pairs)}",
        f"- Prompt-only SAFE_FIX: {prompt_safe}/{len(pairs)}",
        f"- Verifier-guided SAFE_FIX: {guided_safe}/{len(pairs)}",
        f"- SAFE_FIX lost after guidance: {lost}",
        f"- SAFE_FIX gained after guidance: {gained}",
        f"- Exact paired sign/McNemar p-value: {pvalue:.4f}", "",
        "| Dataset | Pairs | Prompt safe | Guided safe | Prompt delivered | Guided delivered |", "|---|---:|---:|---:|---:|---:|",
    ]
    for dataset, local in sorted(by_dataset.items()):
        lines.append(f"| {dataset} | {len(local)} | {sum(outcome(a) == 'SAFE_FIX' for a, _ in local)} | {sum(outcome(b) == 'SAFE_FIX' for _, b in local)} | {sum(a.get('status') == 'OK' for a, _ in local)} | {sum(b.get('status') == 'OK' for _, b in local)} |")
    lines.extend(["", "## Outcome Transitions", "", "| Prompt-only | Verifier-guided | Count |", "|---|---|---:|"])
    for (before, after), count in sorted(transitions.items()):
        lines.append(f"| {before} | {after} | {count} |")
    lines.extend(["", "The exact test addresses paired SAFE_FIX outcomes only; it does not treat delivery failures or INVALID patches as weak repairs.", ""])
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out}: {len(pairs)} pairs")


if __name__ == "__main__":
    main()
