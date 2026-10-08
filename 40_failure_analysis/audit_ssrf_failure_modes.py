"""Emit transparent lexical risk signals for SSRF repair candidates.

Signals are diagnostic and may overlap. They do not prove exploitability or
replace executable tests and human review.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


PATTERNS = {
    "scheme_allowlist_signal_absent": [r"https?", r"scheme.{0,100}(allow|reject|block|invalid|throw|return)"],
    "dns_resolution_signal_absent": [r"dns_get_record|gethostbyname|gethostbynamel|getaddrinfo|lookup(host)?|resolve[46]?\s*\("],
    "all_address_iteration_signal_absent": [r"foreach|for\s*\(|for\s+.*range|\.every\s*\(|all\s*\("],
    "ipv6_defense_signal_absent": [r"ipv6|inet_pton|::1|fc00|fd00|fe80|ipv4.?mapped|is6"],
    "private_range_defense_signal_absent": [r"private|loopback|link.?local|no_priv_range|127\.0\.0\.1|169\.254|192\.168|10\.0\.0"],
    "redirect_control_signal_absent": [r"redirect|follow_location|max_redirects|checkredirect|beforeRedirect"],
    "connection_pinning_signal_absent": [r"pin(ned)?|resolved.?ip|target.?ip|connect.{0,80}(ip|address)|dial(context)?\s*\("],
}


def signals(code: str) -> dict[str, bool]:
    flags = {name: not any(re.search(p, code, re.I | re.S) for p in pats) for name, pats in PATTERNS.items()}
    flags["raw_url_sink"] = bool(re.search(r"(?:file_get_contents|copy|curl_init|fetch|requests?\.(?:get|post)|http\.Get|axios\.(?:get|post))\s*\(\s*\$?(?:url|uri|path)\b", code, re.I))
    flags["malformed_numeric_token"] = bool(re.search(r"\b(?!0[xXbBoO])\d+[A-WYZa-wyz_][A-Za-z0-9_]*\b", code))
    return flags


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ledger", default="results/experiments/SSRF_EVIDENCE_LEDGER_v02.jsonl")
    ap.add_argument("--jsonl", default="results/experiments/SSRF_FAILURE_MODES_v01.jsonl")
    ap.add_argument("--report", default="results/experiments/SSRF_FAILURE_MODES_v01.md")
    args = ap.parse_args()
    rows = [json.loads(x) for x in Path(args.ledger).read_text(encoding="utf-8").splitlines() if x.strip()]
    candidates = [r for r in rows if r.get("status") == "OK" and r.get("agent_fixed")]
    audited = [{"record_id": r["record_id"], "dataset": r["dataset"], "setting": r["setting"], "seed": r["seed"], "cve_id": r["cve_id"], "language": r["language"], "judge_label": r.get("judge_label"), "signals": signals(r["agent_fixed"])} for r in candidates]
    out = Path(args.jsonl)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in audited), encoding="utf-8")
    counts = Counter(k for r in audited for k, v in r["signals"].items() if v)
    lines = ["# SSRF Repair Static Risk Signals", "", f"Audited candidates: {len(audited)}.", "Signals may overlap and are lexical diagnostics, not proof of exploitability.", "An absent signal is relevant only when that defense is applicable to the case's request path.", "", "| Signal | Candidates | Rate |", "|---|---:|---:|"]
    for key in PATTERNS | {"raw_url_sink": [], "malformed_numeric_token": []}:
        lines.append(f"| `{key}` | {counts[key]} | {counts[key] / len(audited):.1%} |")
    lines.extend(["", "Interpret absence-based signals conservatively: a matching token indicates that a defense was mentioned, not that it was correctly implemented.", ""])
    Path(args.report).write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out} and {args.report}: {len(audited)} candidates")


if __name__ == "__main__":
    main()
