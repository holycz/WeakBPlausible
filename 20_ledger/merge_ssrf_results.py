"""Merge the current SSRF runs with explicit independent-run semantics.

The selection policy is intentionally encoded here so reruns cannot silently
inflate the sample size:
* six PHP prompt/verifier seeds are retained;
* the PHP verifier seed-4 rerun replaces only its failed rows;
* four cross-language prompt and verifier waves are retained;
* cross-language prompt r5 and verifier r6 reruns replace only failed rows.

Semantic labels are taken only from judged files for the corresponding source.
Delivery failures never receive a semantic label.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path("results/experiments")


def read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def by_cve(rows: list[dict]) -> dict[str, dict]:
    return {row["cve_id"]: row for row in rows}


def judged_map(path: Path) -> dict[str, str]:
    result = {}
    for row in read(path):
        if row.get("judge_label") and row.get("status") == "OK":
            result[row["cve_id"]] = row["judge_label"]
    return result


def load_wave(
    path: Path,
    dataset: str,
    setting: str,
    seed: str,
    judged: Path | None = None,
    replacement: dict[str, dict] | None = None,
) -> list[dict]:
    label_by_cve = judged_map(judged) if judged else {}
    rows = by_cve(read(path))
    replacement = replacement or {}
    out = []
    for cve_id, row in rows.items():
        chosen = replacement.get(cve_id, row)
        status = chosen.get("status", "UNKNOWN")
        out.append(
            {
                "record_id": f"{dataset}:{setting}:seed{seed}:{cve_id}",
                "dataset": dataset,
                "setting": setting,
                "seed": seed,
                "cve_id": cve_id,
                "language": chosen.get("language", row.get("language", "Unknown")),
                "repo": chosen.get("repo", row.get("repo", "")),
                "status": status,
                "judge_label": (
                    label_by_cve.get(cve_id)
                    if status == "OK"
                    else None
                ),
                "source_file": str(path),
                "replacement_file": (
                    str(replacement[cve_id].get("_replacement_file"))
                    if cve_id in replacement
                    else None
                ),
                "agent_fixed": chosen.get("agent_fixed"),
                "tokens": chosen.get("tokens", 0),
            }
        )
    return out


def failed_replacements(original: Path, rerun: Path) -> dict[str, dict]:
    original_rows = by_cve(read(original))
    result = {}
    for cve_id, row in by_cve(read(rerun)).items():
        if original_rows.get(cve_id, {}).get("status") != "OK":
            copied = dict(row)
            copied["_replacement_file"] = rerun
            result[cve_id] = copied
    return result


def add_wave(
    all_rows: list[dict],
    original: Path,
    dataset: str,
    setting: str,
    seed: str,
    judged: Path | None = None,
    rerun: Path | None = None,
) -> None:
    replacements = (
        failed_replacements(original, rerun) if rerun and rerun.exists() else {}
    )
    # Rerun labels are loaded separately when they replace an original row.
    base_judged = judged
    rows = load_wave(original, dataset, setting, seed, base_judged, replacements)
    rerun_labels = judged_map(
        rerun.with_name(rerun.stem + "_judged.jsonl")
    ) if rerun and rerun.exists() else {}
    for row in rows:
        if row["replacement_file"] and row["status"] == "OK":
            row["judge_label"] = rerun_labels.get(row["cve_id"])
    all_rows.extend(rows)


def build_rows() -> list[dict]:
    rows: list[dict] = []
    php = ROOT / "php_ssrf_frozen"
    ssrf = ROOT / "ssrf_seed"

    for setting, prefix in (("prompt-only", "prompt_only"), ("verifier-guided", "verifier_guided")):
        for seed in range(1, 7):
            name = prefix if seed == 1 else f"{prefix}_seed{seed}"
            original = php / f"{name}.jsonl"
            judged = php / f"{name}_judged.jsonl"
            rerun = (
                php / "verifier_guided_seed4_rerun.jsonl"
                if setting == "verifier-guided" and seed == 4
                else None
            )
            add_wave(
                rows,
                original,
                "php",
                setting,
                str(seed),
                judged if judged.exists() else None,
                rerun,
            )

    add_wave(
        rows,
        ssrf / "opencode_dsv4_prompt_only.jsonl",
        "cross-language",
        "prompt-only",
        "1",
        ssrf / "prompt_only_judged.jsonl",
    )
    for seed in (4, 5, 6):
        original = ssrf / f"real_ssrf_prompt_r{seed}.jsonl"
        rerun = ssrf / "real_ssrf_prompt_r5_rerun.jsonl" if seed == 5 else None
        add_wave(
            rows,
            original,
            "cross-language",
            "prompt-only",
            str(seed),
            None,
            rerun,
        )

    add_wave(
        rows,
        ssrf / "opencode_dsv4_verifier_guided.jsonl",
        "cross-language",
        "verifier-guided",
        "1",
        ssrf / "verifier_guided_judged.jsonl",
    )
    for seed in (4, 5, 6):
        original = ssrf / f"real_ssrf_verifier_r{seed}.jsonl"
        rerun = ssrf / "real_ssrf_verifier_r6_rerun.jsonl" if seed == 6 else None
        add_wave(
            rows,
            original,
            "cross-language",
            "verifier-guided",
            str(seed),
            None,
            rerun,
        )
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out",
        default="results/experiments/SSRF_MERGED_INDEPENDENT_v01.jsonl",
    )
    ap.add_argument(
        "--report",
        default="results/experiments/SSRF_MERGED_INDEPENDENT_v01.md",
    )
    args = ap.parse_args()

    rows = build_rows()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["dataset"], row["setting"])].append(row)
    lines = [
        "# Merged Independent SSRF Results",
        "",
        "Reruns replace only failed rows and are never counted as additional seeds.",
        "Delivery failures are excluded from semantic-label rates.",
        "",
        "| Dataset | Setting | N | OK | NO_WRITE | TIMEOUT | SAFE | WEAK | INVALID label |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key in sorted(grouped):
        group = grouped[key]
        status = Counter(row["status"] for row in group)
        labels = Counter(row["judge_label"] for row in group if row["judge_label"])
        lines.append(
            f"| {key[0]} | {key[1]} | {len(group)} | {status['OK']} | "
            f"{status['NO_WRITE']} | {status['TIMEOUT']} | {labels['SAFE_FIX']} | "
            f"{labels['UNSAFE_PLAUSIBLE']} | {labels['INVALID']} |"
        )
    lines.extend(
        [
            "",
            "## Judged Conditional Weak-Repair Rate",
            "",
            "| Dataset | Setting | Weak / usable | Rate |",
            "|---|---|---:|---:|",
        ]
    )
    for key in sorted(grouped):
        labels = Counter(row["judge_label"] for row in grouped[key] if row["judge_label"])
        usable = labels["SAFE_FIX"] + labels["UNSAFE_PLAUSIBLE"]
        rate = (
            f"{labels['UNSAFE_PLAUSIBLE'] / usable:.1%}"
            if usable
            else "n/a"
        )
        lines.append(
            f"| {key[0]} | {key[1]} | {labels['UNSAFE_PLAUSIBLE']} / {usable} | {rate} |"
        )
    lines.extend(
        [
            "",
            "## Excluded Artifacts",
            "",
            "- smoke tests",
            "- dry-run contract files",
            "- `real_ssrf_prompt_r04.jsonl` environment-failure wave",
            "- full duplicate rerun rows not replacing an original delivery failure",
        ]
    )
    Path(args.report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} merged records -> {out}")
    print(f"wrote report -> {args.report}")


if __name__ == "__main__":
    main()
