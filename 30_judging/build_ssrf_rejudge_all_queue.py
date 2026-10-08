"""Build a unified SSRF judging queue for every emitted candidate patch.

This version does not preserve prior automatic labels. It extracts every
emitted patch from the evidence ledger, backfills the original vulnerable code
and issue statement from the source files / PatchEval seed, and emits one queue
row per logical sample.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def index_rows(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    return {row["cve_id"]: row for row in read_jsonl(path)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--ledger",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v01.jsonl",
    )
    ap.add_argument(
        "--out",
        default="results/experiments/SSRF_JUDGE_QUEUE_UNIFIED_v01.jsonl",
    )
    ap.add_argument(
        "--seed",
        default="data/interim/patcheval_ssrf_v01.jsonl",
    )
    args = ap.parse_args()

    ledger = read_jsonl(Path(args.ledger))
    seed_index = index_rows(Path(args.seed))
    source_cache: dict[str, dict[str, dict]] = {}

    queue: list[dict] = []
    for row in ledger:
        if row.get("status") != "OK" or not row.get("agent_fixed", "").strip():
            continue

        source_file = row.get("source_file", "")
        if source_file and source_file not in source_cache:
            source_cache[source_file] = index_rows(Path(source_file))

        original = dict(seed_index.get(row["cve_id"], {}))
        original.update(source_cache.get(source_file, {}).get(row["cve_id"], {}))
        vuln_code = row.get("vuln_code") or original.get("vuln_code", "")
        description = row.get("description") or original.get("description", "")
        if not vuln_code.strip() or not description.strip():
            raise SystemExit(
                f"missing vulnerable code or description for {row['record_id']}"
            )

        queue.append(
            {
                "sample_id": row["record_id"],
                "record_id": row["record_id"],
                "dataset": row["dataset"],
                "setting": row["setting"],
                "seed": row["seed"],
                "cve_id": row["cve_id"],
                "language": row.get("language", original.get("language", "Unknown")),
                "repo": original.get("repo", row.get("repo", "")),
                "description": description,
                "vuln_code": vuln_code,
                "agent_fixed": row.get("agent_fixed", ""),
                "source_file": source_file,
                "replacement_file": row.get("replacement_file"),
            }
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for row in queue:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(queue)} samples -> {out}")


if __name__ == "__main__":
    main()
