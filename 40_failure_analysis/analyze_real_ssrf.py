"""Aggregate real PatchEval SSRF repair runs without re-judging them.

This report is descriptive only. It keeps the external judge labels as-is and
does not treat the constructed controls or heuristic audits as human labels.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


LABELS = ("SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID")


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def label(row: dict) -> str:
    return row.get("judge_label") or "UNJUDGED"


def label_counts(rows: list[dict]) -> dict[str, int]:
    counts = Counter(label(row) for row in rows)
    return {key: counts.get(key, 0) for key in (*LABELS, "UNJUDGED")}


def markdown_table(headers: list[str], rows: list[list[object]]) -> str:
    out = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    out.extend("| " + " | ".join(str(value) for value in row) + " |" for row in rows)
    return "\n".join(out)


def transition(prompt: dict[str, dict], verifier: dict[str, dict]) -> Counter:
    result: Counter = Counter()
    for cve_id in sorted(set(prompt) & set(verifier)):
        result[(label(prompt[cve_id]), label(verifier[cve_id]))] += 1
    return result


def signals(code: str) -> dict[str, bool]:
    text = code or ""
    low = text.lower()
    return {
        "dns_or_hostname_resolution": bool(
            re.search(r"dns|gethostbyname|getaddrinfo|lookupip|lookuphost|resolve", low)
        ),
        "private_ip_or_special_range": bool(
            re.search(
                r"private|loopback|link.?local|127\.0\.0\.1|169\.254|::1|fc00|fd00|"
                r"inet_pton|netmask|isipforbidden",
                low,
            )
        ),
        "redirect_control": bool(
            re.search(r"redirect|location|follow.?redirect|max.?redirect|same.?origin", low)
        ),
        "pinning_or_resolved_target": bool(
            re.search(r"pin(n|ed|ing)|resolved.?ip|target.?ip|approved.?ip|dialcontext", low)
        ),
        "protocol_restriction": bool(
            re.search(r"https?:|https?['\"]|protocol|scheme|cross.?protocol|http.?only", low)
        ),
        "raw_network_sink": bool(
            re.search(
                r"fetch\s*\(|curl_exec|file_get_contents|http\.newrequest|"
                r"stream_socket_client|fsockopen|undici\.request|http\.get",
                low,
            )
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--prompt",
        default="results/experiments/ssrf_seed/prompt_only_judged.jsonl",
    )
    ap.add_argument(
        "--verifier",
        default="results/experiments/ssrf_seed/verifier_guided_judged.jsonl",
    )
    ap.add_argument("--seed", default="data/interim/patcheval_ssrf_v01.jsonl")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    prompt_rows = read_jsonl(Path(args.prompt))
    verifier_rows = read_jsonl(Path(args.verifier))
    seed = {row["cve_id"]: row for row in read_jsonl(Path(args.seed))}
    for row in [*prompt_rows, *verifier_rows]:
        metadata = seed.get(row["cve_id"], {})
        row.setdefault("repo", metadata.get("repo", "Unknown"))
        row.setdefault("language", metadata.get("language", "Unknown"))
    prompt = {row["cve_id"]: row for row in prompt_rows}
    verifier = {row["cve_id"]: row for row in verifier_rows}

    lines = [
        "# Real SSRF Agent Run Analysis",
        "",
        "Dataset: 10 PatchEval-Verified CWE-918 cases.",
        "",
        "Labels are copied from the existing judge outputs. This report is not a "
        "human-review result and does not include the synthetic mutation controls.",
        "",
        "## Overall",
        "",
        markdown_table(
            ["Variant", "Total", *LABELS, "Other"],
            [
                [
                    "Prompt-only",
                    len(prompt_rows),
                    *[label_counts(prompt_rows)[key] for key in LABELS],
                    label_counts(prompt_rows)["UNJUDGED"],
                ],
                [
                    "Verifier-guided",
                    len(verifier_rows),
                    *[label_counts(verifier_rows)[key] for key in LABELS],
                    label_counts(verifier_rows)["UNJUDGED"],
                ],
            ],
        ),
        "",
        "Among judged outputs only (excluding INVALID), the UNSAFE_PLAUSIBLE "
        "share is 5/8 = 62.5% for Prompt-only and 3/4 = 75.0% for "
        "Verifier-guided. These are descriptive rates from the existing "
        "external-judge labels, not final human-review estimates.",
        "",
        "## Per-CVE Labels",
        "",
        markdown_table(
            ["CVE", "Language", "Prompt-only", "Verifier-guided"],
            [
                [
                    cve_id,
                    (prompt.get(cve_id) or verifier[cve_id]).get("language", "?"),
                    label(prompt[cve_id]) if cve_id in prompt else "MISSING",
                    label(verifier[cve_id]) if cve_id in verifier else "MISSING",
                ]
                for cve_id in sorted(set(prompt) | set(verifier))
            ],
        ),
        "",
        "## Transition Matrix",
        "",
        markdown_table(
            ["Prompt-only -> Verifier-guided", "Count"],
            [
                [f"{src} -> {dst}", transition(prompt, verifier).get((src, dst), 0)]
                for src in (*LABELS, "UNJUDGED")
                for dst in (*LABELS, "UNJUDGED")
                if transition(prompt, verifier).get((src, dst), 0)
            ],
        ),
    ]

    for variant, rows in (("Prompt-only", prompt_rows), ("Verifier-guided", verifier_rows)):
        by_language: dict[str, list[dict]] = defaultdict(list)
        by_repo: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            by_language[row.get("language", "Unknown")].append(row)
            by_repo[row.get("repo", "Unknown").rstrip("/").split("/")[-1]].append(row)
        lines.extend(
            [
                "",
                f"## {variant} Stratification",
                "",
                "### Language",
                "",
                markdown_table(
                    ["Language", "N", *LABELS],
                    [
                        [key, len(value), *[label_counts(value)[item] for item in LABELS]]
                        for key, value in sorted(by_language.items())
                    ],
                ),
                "",
                "### Repository",
                "",
                markdown_table(
                    ["Repository", "N", *LABELS],
                    [
                        [key, len(value), *[label_counts(value)[item] for item in LABELS]]
                        for key, value in sorted(by_repo.items())
                    ],
                ),
            ]
        )
        by_label: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            by_label[label(row)].append(row)
        lines.extend(
            [
                "",
                "### Candidate-Code Signals by Label",
                "",
                "Lexical signals are diagnostic only; they do not establish safety.",
                "",
                markdown_table(
                    ["Label", "N", *signals("").keys()],
                    [
                        [
                            key,
                            len(value),
                            *[
                                f"{sum(signals(item.get('agent_fixed', '')).get(signal, False) for item in value) / len(value):.2f}"
                                if value
                                else "0.00"
                                for signal in signals("").keys()
                            ],
                        ]
                        for key, value in sorted(by_label.items())
                    ],
                ),
            ]
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote report -> {out}")


if __name__ == "__main__":
    main()
