"""Create a case-first SSRF experiment manifest for user-run batches.

The manifest contains one row per planned case-run. It deliberately separates
the broad case-coverage matrix from the smaller cross-agent matrix.
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--php", default="data/interim/php_ssrf_frozen_v01.jsonl")
    ap.add_argument("--cross", default="data/interim/patcheval_ssrf_v01.jsonl")
    ap.add_argument("--out", default="results/experiments/SSRF_EXPERIMENT_MANIFEST_v01.jsonl")
    ap.add_argument("--report", default="results/experiments/SSRF_EXPERIMENT_MANIFEST_v01.md")
    ap.add_argument("--seeds", type=int, default=3)
    args = ap.parse_args()

    php = read_jsonl(Path(args.php))
    cross = read_jsonl(Path(args.cross))
    rows: list[dict] = []

    def add(block: str, cases: list[dict], settings: list[str], systems: list[str]) -> None:
        for system in systems:
            for setting in settings:
                for seed in range(1, args.seeds + 1):
                    for case in cases:
                        rows.append(
                            {
                                "run_id": f"{block}:{system}:{setting}:seed{seed}:{case['cve_id']}",
                                "block": block,
                                "system": system,
                                "setting": setting,
                                "seed": seed,
                                "cve_id": case["cve_id"],
                                "language": case.get("language", "Unknown"),
                                "repo": case.get("repo", ""),
                                "input_file": args.php if block == "php-core" else args.cross,
                                "status": "TODO",
                            }
                        )

    # Broad coverage: current system on every available case.
    add(
        "php-core",
        php,
        ["prompt-only", "prose-verifier", "executable-contract"],
        ["opencode:dsv4-dspark"],
    )
    add(
        "cross-language",
        cross,
        ["prompt-only", "prose-verifier"],
        ["opencode:dsv4-dspark"],
    )
    # Cross-system block is intentionally smaller and selected later by a
    # separate stratified sampler; this manifest records the full candidate pool.
    add(
        "cross-agent-candidate-pool",
        php,
        ["prompt-only", "prose-verifier"],
        ["opencode:dsv4-dspark", "agent2:model2", "agent3:model3"],
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    counts = {}
    for row in rows:
        key = (row["block"], row["system"], row["setting"])
        counts[key] = counts.get(key, 0) + 1
    lines = [
        "# SSRF Experiment Manifest",
        "",
        "Generated from the currently available verified case files.",
        "",
        "| Block | Systems | Settings | Seeds | Cases/run | Planned case-runs |",
        "|---|---|---|---:|---:|---:|",
    ]
    for (block, system, setting), n in sorted(counts.items()):
        cases = n // args.seeds
        lines.append(
            f"| {block} | {system} | {setting} | {args.seeds} | "
            f"{cases // 1} | {n} |"
        )
    lines.extend(
        [
            "",
            "## Important",
            "",
            "- `agent2:model2` and `agent3:model3` are placeholders and must be "
            "replaced with real executable configurations before running.",
            "- The cross-agent candidate pool is not automatically a paper result; "
            "select a stratified subset after the case inventory is finalized.",
            "- Missing source code, missing reference fix, or duplicate CVE entries "
            "must be excluded before execution.",
        ]
    )
    Path(args.report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} planned case-runs -> {out}")
    print(f"wrote report -> {args.report}")


if __name__ == "__main__":
    main()
