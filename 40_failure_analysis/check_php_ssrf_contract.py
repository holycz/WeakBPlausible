"""Deterministic, case-aware contract checks for PHP SSRF repair snippets.

This is a conservative static checker. It is not a PHP parser, does not prove
exploitability, and reports UNKNOWN when a property cannot be established from
source text alone.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def has_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.I | re.S) for pattern in patterns)


def check_common(code: str) -> dict[str, str]:
    text = code or ""
    low = text.lower()
    result: dict[str, str] = {}
    has_direct_socket = has_any(
        text, [r"fsockopen\s*\(", r"stream_socket_client\s*\("]
    )
    has_redirect_capable_sink = has_any(
        text,
        [
            r"file_get_contents\s*\(",
            r"copy\s*\(",
            r"curl_exec\s*\(",
            r"->(?:get|request|send)\s*\(",
        ],
    )

    result["has_code"] = "PASS" if text.strip() else "FAIL"
    result["http_https_only"] = (
        "PASS"
        if has_any(
            text,
            [
                r"in_array\s*\([^;]*(?:http|https)",
                r"scheme[^;\n]*(?:http|https)[^;\n]*(?:return|throw|exception)",
                r"starts_with\s*\([^;]*(?:http|https)",
                r"\^https\?[:'\"/]",
                r"case\s+['\"]https?['\"]",
            ],
        )
        else "FAIL"
    )
    result["resolves_dns"] = (
        "PASS"
        if has_any(text, [r"dns_get_record\s*\(", r"gethostbyname\s*\(", r"getaddrinfo"])
        else "FAIL"
    )
    result["iterates_records"] = (
        "PASS"
        if has_any(
            text,
            [
                r"foreach\s*\([^)]*(?:record|address|ip|resolved)",
                r"for\s*\([^)]*(?:record|address|ip|resolved)",
            ],
        )
        else "FAIL"
    )
    result["blocks_ipv4_ranges"] = (
        "PASS"
        if has_any(
            text,
            [
                r"FILTER_FLAG_NO_PRIV_RANGE",
                r"127\.0\.0\.1|169\.254|192\.168|172\.\s*16|224\.0\.0|first\s*[><=].*224",
                r"is_private_ipv4|isprivateipv4|blocked.*ipv4",
            ],
        )
        else "FAIL"
    )
    result["blocks_ipv6_ranges"] = (
        "PASS"
        if has_any(
            text,
            [
                r"FILTER_FLAG_IPV6",
                r"inet_pton\s*\(",
                r"::1|fc00|fd00|fe80|ff00|ipv4[-_ ]mapped",
                r"is_private_ipv6|isprivateipv6|blocked.*ipv6",
            ],
        )
        else "FAIL"
    )
    redirect_control = has_any(
        text,
        [
            r"follow_location\s*[=:]\s*0",
            r"max_redirects\s*[=:]\s*0",
            r"(?:redirect|location).*(?:same.?origin|revalid|reject|allowlist)",
        ],
    )
    # Raw sockets do not implement HTTP redirects at this layer. For a
    # redirect-capable downloader, explicit control is required.
    if redirect_control or (has_direct_socket and not has_redirect_capable_sink):
        result["redirect_policy"] = "PASS"
    elif has_redirect_capable_sink:
        result["redirect_policy"] = "FAIL"
    else:
        result["redirect_policy"] = "UNKNOWN"
    result["ip_pinning_signal"] = (
        "PASS"
        if has_any(
            text,
            [
                r"pinned_url|pinnedurl|resolved_ip|target_ip|approved.*ip",
                r"(?:fsockopen|stream_socket_client|curl_exec|copy)\s*\([^;]*(?:\$ip|\$address|\$target)",
            ],
        )
        else "FAIL"
    )
    result["raw_url_sink"] = (
        "FAIL"
        if has_any(
            text,
            [
                r"file_get_contents\s*\(\s*\$url\b",
                r"file_get_contents\s*\(\s*\$path\b",
                r"copy\s*\(\s*\$url\b",
                r"curl_init\s*\(\s*\$url\b",
                r"->get\s*\(\s*\$url\b",
                r"->request\s*\([^,\n]*\$url\b",
            ],
        )
        else "PASS"
    )
    result["malformed_numeric_token"] = (
        "FAIL" if re.search(r"\b\d+[A-Za-z_][A-Za-z0-9_]*\b", text) else "PASS"
    )

    # A source-only checker cannot establish PHP syntax or semantic API validity.
    result["php_syntax"] = "UNKNOWN"
    result["api_compatibility"] = "UNKNOWN"
    return result


def check_case(cve_id: str, code: str) -> dict[str, str]:
    result = check_common(code)
    text = code or ""
    if cve_id == "CVE-2026-55599":
        result["approved_ip_reaches_socket"] = (
            "PASS"
            if has_any(text, [r"fsockopen\s*\(\s*\$target", r"stream_socket_client\s*\("])
            and has_any(text, [r"\$ip\s*=", r"\$ips\s*=", r"\$target"])
            else "FAIL"
        )
    elif cve_id == "CVE-2026-48555":
        result["approved_ip_reaches_downloader"] = (
            "PASS"
            if has_any(text, [r"pinned_url", r"pinnedUrl", r"copy\s*\(\s*\$pinned"])
            else "FAIL"
        )
        result["original_host_preserved"] = (
            "PASS" if has_any(text, [r"Host:", r"host_header", r"peer_name"]) else "FAIL"
        )
    elif cve_id == "CVE-2025-54370":
        result["non_http_schemes_rejected"] = (
            "PASS"
            if has_any(text, [r"only.*http", r"^https\?", r"Invalid protocol", r"scheme"])
            else "FAIL"
        )
    elif cve_id == "CVE-2026-52840":
        result["validation_before_connection"] = (
            "PASS"
            if text.find("validate") >= 0 and text.find("test_connection") >= 0
            and text.find("validate") < text.find("test_connection")
            else "FAIL"
        )
        result["provider_save_preserved"] = (
            "PASS" if has_any(text, [r"providers_model", r"->save\s*\("]) else "FAIL"
        )
    return result


def status(checks: dict[str, str]) -> str:
    if any(value == "FAIL" for value in checks.values()):
        return "FAIL"
    if any(value == "UNKNOWN" for value in checks.values()):
        return "UNKNOWN"
    return "PASS"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for name in args.inp:
            path = Path(name)
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                checks = check_case(row["cve_id"], row.get("agent_fixed") or "")
                result = {
                    "source": name,
                    "cve_id": row["cve_id"],
                    "agent_status": row.get("status"),
                    "contract_status": status(checks),
                    "checks": checks,
                }
                fh.write(json.dumps(result, ensure_ascii=False) + "\n")
    print(f"wrote contract checks -> {out}")


if __name__ == "__main__":
    main()
