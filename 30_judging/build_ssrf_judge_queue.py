"""Build a semantic-judging queue from merged SSRF runs.

Only emitted patches without an existing semantic label are included. The
logical sample key is dataset/setting/seed/CVE, not CVE alone, because the same
CVE is intentionally repeated across independent seeds.
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


def source_rows(path: Path) -> dict[str, dict]:
    return {row["cve_id"]: row for row in read_jsonl(path)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--merged",
        default="results/experiments/SSRF_MERGED_INDEPENDENT_v01.jsonl",
    )
    ap.add_argument(
        "--out",
        default="results/experiments/SSRF_JUDGE_QUEUE_v02.jsonl",
    )
    ap.add_argument("--seed", default="data/interim/patcheval_ssrf_v01.jsonl")
    args = ap.parse_args()

    merged = read_jsonl(Path(args.merged))
    seed = {row["cve_id"]: row for row in read_jsonl(Path(args.seed))}
    queue: list[dict] = []
    for row in merged:
        if row.get("status") != "OK" or row.get("judge_label"):
            continue
        source = row["source_file"]
        original = seed.get(row["cve_id"], {})
        if not original:
            original = source_rows(Path(source)).get(row["cve_id"], {})
        fixed = row.get("agent_fixed") or ""
        if not fixed.strip():
            continue
        queue.append(
            {
                "sample_id": row["record_id"],
                "dataset": row["dataset"],
                "setting": row["setting"],
                "seed": row["seed"],
                "cve_id": row["cve_id"],
                "language": row.get("language", original.get("language", "Unknown")),
                "repo": original.get("repo", row.get("repo", "")),
                "description": original.get("description", ""),
                "vuln_code": original.get("vuln_code", ""),
                "agent_fixed": fixed,
                "source_file": source,
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
