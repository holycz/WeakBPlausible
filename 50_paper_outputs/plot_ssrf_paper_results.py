#!/usr/bin/env python3
"""Generate the paper outcome figure and rationale-derived failure counts."""
from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path


LABELS = ("SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID")
GROUPS = (
    ("php", "prompt-only", "PHP\nPrompt"),
    ("php", "verifier-guided", "PHP\nGuided"),
    ("cross-language", "prompt-only", "Cross-lang.\nPrompt"),
    ("cross-language", "verifier-guided", "Cross-lang.\nGuided"),
)
FAILURE_PATTERNS = (
    ("DNS / TOCTOU", ("dns", "re-resolv", "rebind", "pinning", "pin ")),
    ("Redirect", ("redirect", "location")),
    ("Address coverage", ("ipv6", "mapped", "link-local", "multicast", "private ip", "loopback")),
    ("URL / parser", ("parse", "normaliz", "encoded", "scheme", "protocol", "userinfo", "host representation")),
    ("Implementation", ("syntax", "fatal error", "runtime error", "malformed code", "undefined", "unsupported", "api", "behavior destruction", "unrelated")),
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", default="results/experiments/SSRF_EVIDENCE_LEDGER_v03_CONDITION_BLIND.jsonl")
    parser.add_argument("--figure", default="paper/figures/ssrf_outcomes.pdf")
    parser.add_argument("--counts", default="results/experiments/SSRF_FAILURE_PATTERN_COUNTS_v03_CONDITION_BLIND.json")
    args = parser.parse_args()

    rows = read_jsonl(Path(args.ledger))
    emitted = [row for row in rows if row.get("status") == "OK"]
    grouped = {
        (dataset, setting): Counter(
            row.get("judge_label") for row in emitted
            if row.get("dataset") == dataset and row.get("setting") == setting
        )
        for dataset, setting, _ in GROUPS
    }

    colors = {"SAFE_FIX": "#009E73", "UNSAFE_PLAUSIBLE": "#E69F00", "INVALID": "#777777"}
    names = {"SAFE_FIX": "Safe", "UNSAFE_PLAUSIBLE": "Weak", "INVALID": "Invalid"}
    figure_path = Path(args.figure)
    figure_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path = figure_path.with_suffix(".svg")
    width, height = 492, 295
    left, top, plot_h, bar_w = 58, 38, 190, 58
    xs = [82, 184, 298, 400]
    scale = plot_h / 40
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<g font-family="Times New Roman,Times,serif" font-size="12" fill="#111">',
    ]
    for tick in range(0, 41, 10):
        y = top + plot_h - tick * scale
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="475" y2="{y:.1f}" stroke="#dddddd" stroke-width="1"/>')
        parts.append(f'<text x="50" y="{y + 4:.1f}" text-anchor="end">{tick}</text>')
    parts.append(f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#222"/>')
    parts.append(f'<line x1="{left}" y1="{top + plot_h}" x2="475" y2="{top + plot_h}" stroke="#222"/>')
    for x, (dataset, setting, display) in zip(xs, GROUPS):
        bottom = top + plot_h
        for label in LABELS:
            value = grouped[(dataset, setting)][label]
            h = value * scale
            bottom -= h
            if value:
                parts.append(f'<rect x="{x}" y="{bottom:.1f}" width="{bar_w}" height="{h:.1f}" fill="{colors[label]}" stroke="white"/>')
                parts.append(f'<text x="{x + bar_w / 2}" y="{bottom + h / 2 + 4:.1f}" text-anchor="middle">{value}</text>')
        first, second = display.split("\n")
        parts.append(f'<text x="{x + bar_w / 2}" y="248" text-anchor="middle">{first}</text>')
        parts.append(f'<text x="{x + bar_w / 2}" y="263" text-anchor="middle">{second}</text>')
    parts.append('<text x="15" y="145" text-anchor="middle" transform="rotate(-90 15 145)">Emitted candidate patches</text>')
    legend_x = 64
    for label in LABELS:
        parts.append(f'<rect x="{legend_x}" y="10" width="13" height="9" fill="{colors[label]}"/>')
        parts.append(f'<text x="{legend_x + 18}" y="19">{names[label]}</text>')
        legend_x += {"SAFE_FIX": 76, "UNSAFE_PLAUSIBLE": 82, "INVALID": 88}[label]
    parts.extend(['</g>', '</svg>'])
    svg_path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    subprocess.run(["rsvg-convert", "-f", "pdf", "-o", str(figure_path), str(svg_path)], check=True)

    weak = [row for row in emitted if row.get("judge_label") == "UNSAFE_PLAUSIBLE"]
    counts = Counter()
    unmatched = []
    for row in weak:
        rationale = (row.get("judge_rationale") or "").lower()
        matched = False
        for category, terms in FAILURE_PATTERNS:
            if any(term in rationale for term in terms):
                counts[category] += 1
                matched = True
        if not matched:
            unmatched.append(row["record_id"])
    payload = {
        "source": args.ledger,
        "weak_records": len(weak),
        "coding": "multi-label keyword coding of automatic-judge rationales",
        "patterns": {name: list(terms) for name, terms in FAILURE_PATTERNS},
        "counts": dict(counts),
        "unmatched_record_ids": unmatched,
    }
    counts_path = Path(args.counts)
    counts_path.parent.mkdir(parents=True, exist_ok=True)
    counts_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
