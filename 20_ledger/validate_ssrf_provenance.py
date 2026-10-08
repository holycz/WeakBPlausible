"""Audit SSRF case provenance completeness for the curated datasets.

The script does not invent missing provenance. It reports which expected
metadata fields are absent so the paper can describe provenance limits
precisely.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


EXPECTED_PHP_FIELDS = ("source_url", "affected_versions", "reference_fix")
EXPECTED_CROSS_FIELDS = ("source_url", "affected_versions", "reference_fix")


def read(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def audit(rows: list[dict], fields: tuple[str, ...]) -> dict[str, int]:
    counts = Counter()
    for field in fields:
        counts[field] = sum(1 for row in rows if not str(row.get(field, "")).strip())
    return dict(counts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--php-manifest",
        default="data/interim/php_ssrf_frozen_v01.jsonl",
    )
    parser.add_argument(
        "--cross-language",
        default="data/interim/patcheval_ssrf_v01.jsonl",
    )
    parser.add_argument(
        "--out",
        default="results/experiments/SSRF_PROVENANCE_AUDIT_v01.md",
    )
    args = parser.parse_args()

    php = read(Path(args.php_manifest))
    cross = read(Path(args.cross_language))

    php_missing = audit(php, EXPECTED_PHP_FIELDS)
    cross_missing = audit(cross, EXPECTED_CROSS_FIELDS)

    lines = [
        "# SSRF Provenance Audit",
        "",
        "This report counts missing provenance metadata in the curated datasets.",
        "It is descriptive and does not fabricate absent source records.",
        "",
        f"- PHP rows: {len(php)}",
        f"- Cross-language rows: {len(cross)}",
        "",
        "## Missing PHP Fields",
        "",
        "| Field | Missing rows |",
        "|---|---:|",
    ]
    for field, count in php_missing.items():
        lines.append(f"| {field} | {count} |")
    lines.extend(
        [
            "",
            "## Missing Cross-Language Fields",
            "",
            "| Field | Missing rows |",
            "|---|---:|",
        ]
    )
    for field, count in cross_missing.items():
        lines.append(f"| {field} | {count} |")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
