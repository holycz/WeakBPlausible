"""Convert a repair result JSONL into an SSRF judge queue.

Only emitted candidate patches (`status == OK` with non-empty `agent_fixed`)
are included, so delivery failures remain separate from semantic INVALID
labels.
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
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sample-prefix", default="result")
    ap.add_argument("--dataset", default="cross-language")
    ap.add_argument("--setting", default="neutral-second-pass")
    ap.add_argument("--seed", default="control")
    ap.add_argument("--seed-file", default="data/interim/patcheval_ssrf_v01.jsonl")
    args = ap.parse_args()

    rows = read_jsonl(Path(args.inp))
    seed = index_rows(Path(args.seed_file))
    queue = []
    for row in rows:
        if row.get("status") != "OK" or not row.get("agent_fixed", "").strip():
            continue
        original = seed.get(row["cve_id"], {})
        vuln_code = row.get("vuln_code") or original.get("vuln_code", "")
        description = row.get("description") or original.get("description", "")
        if not vuln_code.strip() or not description.strip():
            raise SystemExit(f"missing vulnerable code or description for {row['cve_id']}")
        queue.append(
            {
                "sample_id": row.get("sample_id") or f"{args.sample_prefix}:{row['cve_id']}",
                "dataset": row.get("dataset", args.dataset),
                "setting": row.get("setting", args.setting),
                "seed": row.get("seed", args.seed),
                "cve_id": row["cve_id"],
                "language": row.get("language", original.get("language", "Unknown")),
                "repo": row.get("repo", original.get("repo", "")),
                "description": description,
                "vuln_code": vuln_code,
                "agent_fixed": row["agent_fixed"],
                "source_file": args.inp,
            }
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for row in queue:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(queue)} judge samples -> {out}")


if __name__ == "__main__":
    main()
