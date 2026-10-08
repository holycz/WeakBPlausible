"""Build a real PatchEval-Verified CWE-918 subset for SSRF experiments."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


EXTENSIONS = {
    "CVE-2023-28155": "js",
    "CVE-2022-35949": "js",
    "CVE-2025-23221": "ts",
    "CVE-2020-28360": "js",
    "CVE-2023-24623": "js",
    "CVE-2022-24825": "go",
    "CVE-2024-0243": "py",
    "CVE-2023-5122": "go",
    "CVE-2022-29188": "go",
    "CVE-2022-2900": "js",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--input",
        default="data/raw/patcheval_verified/patcheval_verified.json",
    )
    ap.add_argument(
        "--output",
        default="data/interim/patcheval_ssrf_v01.jsonl",
    )
    args = ap.parse_args()

    records = json.loads(Path(args.input).read_text(encoding="utf-8"))
    selected = []
    for item in records:
        cwes = item.get("cwe_info") or {}
        if "CWE-918" not in cwes:
            continue
        cve_id = item["cve_id"]
        vul = (item.get("vul_func") or [{}])[0]
        fix = (item.get("fix_func") or [{}])[0]
        selected.append(
            {
                "cve_id": cve_id,
                "language": item.get("programming_language") or "Unknown",
                "extension": EXTENSIONS.get(cve_id, "txt"),
                "repo": item.get("repo", ""),
                "description": item.get("cve_description", ""),
                "cwe": ["CWE-918"],
                "source": item.get("patch_url", ""),
                "vuln_code": vul.get("snippet", ""),
                "reference_fix": fix.get("snippet", ""),
            }
        )

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for row in selected:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(selected)} SSRF cases -> {out}")


if __name__ == "__main__":
    main()
