"""Aggregate PHP SSRF frozen-run outcomes and transparent repair audits.

This script deliberately does not assign SAFE_FIX. It reports delivery
failures and syntactic/lexical SSRF risk signals that can be checked without
an external judge or a PHP runtime.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


def audit(code: str) -> dict[str, bool]:
    text = code or ""
    low = text.lower()
    has_sink = bool(
        re.search(
            r"(file_get_contents|copy|curl_exec|fsockopen|stream_socket_client)"
            r"\s*\(",
            low,
        )
    )
    raw_url_sink = bool(
        re.search(
            r"(file_get_contents|copy|curl_init|fsockopen|stream_socket_client)"
            r"\s*\(\s*\$?(url|path|host)\b",
            low,
        )
    )
    resolves = bool(
        re.search(
            r"(dns_get_record|gethostbyname|gethostbynamel|getaddrinfo|resolve)",
            low,
        )
    )
    loops_records = bool(
        re.search(r"\b(foreach|for(each)?|while)\s*\([^)]*(records|addresses|ips)", low)
    )
    pins_ip = bool(
        re.search(
            r"(pinnedurl|resolved.?ip|target.?ip|connect(ed)?\s+to.*ip|"
            r"inet_pton|stream_socket_client\s*\(\s*['\"](?:ssl|tcp)://)",
            low,
        )
    )
    disables_redirect = bool(
        re.search(r"(follow_location\s*[=:]\s*0|max_redirects\s*[=:]\s*0)", low)
    )
    mentions_dns_recheck = bool(
        re.search(r"(re[- ]?resolve|resolve.*again|recheck|dns_get_record.*dns_get_record)", low)
    )
    malformed_numeric_token = bool(re.search(r"\b\d+[A-Za-z_][A-Za-z0-9_]*\b", text))
    return {
        "has_code": bool(text.strip()),
        "has_remote_sink": has_sink,
        "raw_url_or_host_sink": raw_url_sink,
        "has_dns_resolution": resolves,
        "iterates_resolved_records": loops_records,
        "pins_or_connects_to_ip": pins_ip,
        "disables_redirect": disables_redirect,
        "mentions_dns_recheck": mentions_dns_recheck,
        "malformed_numeric_token": malformed_numeric_token,
    }


def load_rows(paths: list[Path]) -> list[dict]:
    rows = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                row["_source"] = path.name
                rows.append(row)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--inputs",
        nargs="+",
        default=[
            "results/experiments/php_ssrf_frozen/verifier_v2_seed1.jsonl",
            "results/experiments/php_ssrf_frozen/verifier_v2_seed2.jsonl",
            "results/experiments/php_ssrf_frozen/verifier_v2_seed3.jsonl",
        ],
    )
    ap.add_argument(
        "--judged",
        nargs="*",
        default=[
            "results/experiments/php_ssrf_frozen/verifier_v2_seed2_judged.jsonl",
            "results/experiments/php_ssrf_frozen/verifier_v2_seed3_judged.jsonl",
        ],
    )
    ap.add_argument("--out", default="results/experiments/php_ssrf_frozen/V2_AGGREGATE.md")
    args = ap.parse_args()

    rows = load_rows([Path(p) for p in args.inputs])
    judged = {}
    for row in load_rows([Path(p) for p in args.judged] if args.judged else []):
        judged[(row["_source"], row["cve_id"])] = row.get("judge_label")

    status = Counter(row.get("status", "UNKNOWN") for row in rows)
    labels = Counter()
    by_case = defaultdict(list)
    audits = []
    for row in rows:
        label = judged.get((row["_source"].replace(".jsonl", "_judged.jsonl"), row["cve_id"]))
        if label is None and row.get("status") in {"TIMEOUT", "NO_WRITE"}:
            label = "INVALID_DELIVERY"
        if label:
            labels[label] += 1
        a = audit(row.get("agent_fixed") or "")
        audits.append(a)
        by_case[row["cve_id"]].append((row["_source"], row.get("status"), label, a))

    def count_true(key: str) -> int:
        return sum(1 for a in audits if a[key])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# PHP SSRF Frozen Experiment: Verifier v2 Aggregate",
        "",
        "Date: 2026-08-29",
        "",
        "This report combines three verifier-v2 seeds (12 attempts). The local "
        "audit is diagnostic only; it does not prove exploitability or SAFE_FIX.",
        "",
        "## Delivery",
        "",
        "| Status | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| {key} | {status[key]} |" for key in ("OK", "NO_WRITE", "TIMEOUT"))
    lines.extend(
        [
            "",
            "## Available External-Judge Labels",
            "",
            "Seed 1 was not sent to the external endpoint because the environment "
            "blocked transmission of source code and patches. Seeds 2 and 3 were "
            "already labeled before the stop signal.",
            "",
            "| Label | Count |",
            "|---|---:|",
        ]
    )
    lines.extend(f"| {key} | {labels[key]} |" for key in ("SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID"))
    lines.extend(
        [
            "",
            "## Transparent Local Signals",
            "",
            "| Signal | Count / 12 |",
            "|---|---:|",
            f"| contains a code output | {count_true('has_code')} |",
            f"| contains a remote network sink | {count_true('has_remote_sink')} |",
            f"| passes raw URL/host/path to a sink | {count_true('raw_url_or_host_sink')} |",
            f"| performs DNS/address resolution | {count_true('has_dns_resolution')} |",
            f"| iterates resolved records | {count_true('iterates_resolved_records')} |",
            f"| pins/connects to an IP signal | {count_true('pins_or_connects_to_ip')} |",
            f"| disables redirects | {count_true('disables_redirect')} |",
            f"| mentions DNS recheck | {count_true('mentions_dns_recheck')} |",
            f"| contains malformed numeric token signal | {count_true('malformed_numeric_token')} |",
            "",
            "## Per-Case Delivery",
            "",
            "| Case | OK | NO_WRITE | TIMEOUT |",
            "|---|---:|---:|---:|",
        ]
    )
    for case in sorted(by_case):
        c = Counter(status for _, status, _, _ in by_case[case])
        lines.append(f"| {case} | {c['OK']} | {c['NO_WRITE']} | {c['TIMEOUT']} |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The v2 contract increased the amount of security-specific guidance, "
            "but did not make repair reliably deliverable: only "
            f"{status['OK']}/12 attempts wrote a patch, while "
            f"{status['TIMEOUT'] + status['NO_WRITE']}/12 failed to produce one. "
            "Among emitted patches, the local signals still show recurring "
            "single-resolution or raw-host request risks. This supports an "
            "exploratory negative result for prose-only verifier guidance, not "
            "a claim that the verifier improves security.",
            "",
            "The next enhancement should be executable, case-specific regression "
            "tests and human double-labeling, rather than longer prose prompts.",
            "",
        ]
    )
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
