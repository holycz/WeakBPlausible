"""Run transparent heuristic audits over PHP SSRF repair outputs.

This is not a sound verifier and does not replace human review or execution.
It exposes patch features that are useful for diagnosing weak repairs.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def audit(code: str) -> dict:
    text = code or ""
    low = text.lower()
    return {
        "has_code": bool(text.strip()),
        "has_remote_sink": bool(re.search(r"(file_get_contents|curl_exec|fsockopen|stream_socket_client|->request)\s*\(", text)),
        "has_dns_resolution": bool(re.search(r"(dns_get_record|gethostbyname|gethostbynamel|getaddrinfo)", low)),
        "has_multiple_dns_or_recheck": bool(re.search(r"(re[- ]?resolve|resolve.*again|dns_get_record.*dns_get_record)", low)),
        "mentions_private_or_loopback": bool(re.search(r"(private|loopback|link[- ]local|127\.0\.0\.1|169\.254|::1|fc00|fd00)", low)),
        "mentions_ipv6": bool(re.search(r"(ipv6|inet_pton|ipv4[- ]mapped|::ffff)", low)),
        "mentions_redirect": "redirect" in low or "location" in low,
        "mentions_allowlist": "allowlist" in low or "allow list" in low or "whitelist" in low,
        "mentions_pin_or_fixed_ip": bool(re.search(r"(pinned|pinning|fixed ip|resolved ip|target ip)", low)),
        "suspicious_identifiers": sorted(set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*[A-Z][A-Za-z0-9_]*\b", text))),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for inp_name in args.inp:
            inp = Path(inp_name)
            for line in inp.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                fixed = row.get("agent_fixed") or ""
                row["heuristic_audit"] = audit(fixed)
                row["audit_source"] = inp_name
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote audits -> {out}")


if __name__ == "__main__":
    main()
