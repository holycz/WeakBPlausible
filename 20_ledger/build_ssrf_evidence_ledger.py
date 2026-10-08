"""Build the single auditable evidence ledger for the SSRF study.

The independent-run merge contains the complete 128-run accounting, while
the queue output contains semantic judgments for previously unlabeled runs.
This script joins them by the stable logical sample id and emits one record
per independent case-run.  It never infers a semantic label for a delivery
failure.
"""
from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--merged",
        default="results/experiments/SSRF_MERGED_INDEPENDENT_v01.jsonl",
    )
    parser.add_argument(
        "--queue",
        default="results/experiments/SSRF_JUDGED_QUEUE_v02.jsonl",
    )
    parser.add_argument(
        "--out",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v01.jsonl",
    )
    parser.add_argument(
        "--report",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v01.md",
    )
    parser.add_argument(
        "--manifest",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v01.manifest.json",
    )
    parser.add_argument(
        "--prefer-queue",
        action="store_true",
        help="allow queue judgments to override pre-existing merged labels",
    )
    args = parser.parse_args()

    merged = read_jsonl(Path(args.merged))
    queue = read_jsonl(Path(args.queue))

    merged_by_id: dict[str, dict] = {}
    duplicate_merged: list[str] = []
    for row in merged:
        key = row["record_id"]
        if key in merged_by_id:
            duplicate_merged.append(key)
        merged_by_id[key] = row

    queue_by_id: dict[str, dict] = {}
    duplicate_queue: list[str] = []
    for row in queue:
        key = row["sample_id"]
        if key in queue_by_id:
            duplicate_queue.append(key)
        queue_by_id[key] = row

    unknown_queue = sorted(set(queue_by_id) - set(merged_by_id))
    if duplicate_merged or duplicate_queue or unknown_queue:
        raise SystemExit(
            "ledger integrity failure: "
            f"duplicate_merged={len(duplicate_merged)}, "
            f"duplicate_queue={len(duplicate_queue)}, "
            f"unknown_queue={len(unknown_queue)}"
        )

    ledger: list[dict] = []
    for row in merged:
        key = row["record_id"]
        queued = queue_by_id.get(key)
        status = row.get("status")
        label = row.get("judge_label")
        rationale = row.get("judge_rationale")
        source = "merged_wave_judged" if label else None

        if queued:
            if status != "OK":
                raise SystemExit(f"queue contains non-OK merged run: {key}")
            queued_label = queued.get("judge_label")
            if not queued_label:
                raise SystemExit(f"queue record has no judge_label: {key}")
            if label and label != queued_label and not args.prefer_queue:
                raise SystemExit(f"conflicting labels for {key}: {label} vs {queued_label}")
            label = queued_label
            rationale = queued.get("judge_rationale")
            source = Path(args.queue).stem

        if status != "OK" and label:
            raise SystemExit(f"delivery failure has semantic label: {key}")

        record = dict(row)
        record["judge_label"] = label
        record["judge_rationale"] = rationale
        record["judge_source"] = source
        if queued:
            record["description"] = queued.get("description", "")
            record["vuln_code"] = queued.get("vuln_code", "")
        ledger.append(record)

    labels = Counter(
        row["judge_label"] for row in ledger if row.get("judge_label")
    )
    status_counts = Counter(row.get("status") for row in ledger)
    judged = sum(labels.values())
    usable = labels["SAFE_FIX"] + labels["UNSAFE_PLAUSIBLE"]
    if judged != status_counts["OK"]:
        raise SystemExit(
            f"not all emitted patches are judged: judged={judged}, "
            f"ok={status_counts['OK']}, usable={usable}, "
            f"labels={dict(labels)}"
        )

    output = Path(args.out)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    versioned = output.with_name(f"{output.stem}_{timestamp}{output.suffix}")
    write_jsonl(versioned, ledger)
    shutil.copyfile(versioned, output)

    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in ledger:
        grouped[(row["dataset"], row["setting"])].append(row)

    lines = [
        "# SSRF Evidence Ledger",
        "",
        "This ledger contains one row per independent logical case-run.",
        "Semantic labels are joined by `sample_id == record_id`.",
        "Delivery failures retain no semantic label.",
        "",
        f"- Total independent runs: {len(ledger)}",
        f"- Judged runs: {judged}",
        f"- Usable judged patches: {usable}",
        f"- Weak-repair rate among usable patches: "
        f"{labels['UNSAFE_PLAUSIBLE'] / usable:.1%}",
        "",
        "| Dataset | Setting | N | OK | NO_WRITE | TIMEOUT | Safe | Weak | Invalid |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key in sorted(grouped):
        rows = grouped[key]
        status = Counter(row.get("status") for row in rows)
        local = Counter(row.get("judge_label") for row in rows)
        lines.append(
            f"| {key[0]} | {key[1]} | {len(rows)} | {status['OK']} | "
            f"{status['NO_WRITE']} | {status['TIMEOUT']} | "
            f"{local['SAFE_FIX']} | {local['UNSAFE_PLAUSIBLE']} | "
            f"{local['INVALID']} |"
        )
    lines.extend(
        [
            "",
            "## Label Sources",
            "",
            "| Source | Records |",
            "|---|---:|",
        ]
    )
    for source, count in sorted(
        Counter(row.get("judge_source") or "unjudged_delivery_record"
                for row in ledger).items()
    ):
        lines.append(f"| {source} | {count} |")
    lines.extend(
        [
            "",
            "## Integrity Checks",
            "",
            f"- Unique record ids: {len({row['record_id'] for row in ledger})}",
            f"- Queue records joined: {len(queue_by_id)}",
            f"- Status counts: `{dict(status_counts)}`",
            f"- Label counts: `{dict(labels)}`",
            "- No duplicate logical keys or queue records.",
            "- No semantic label is assigned to `NO_WRITE` or `TIMEOUT`.",
            "",
            "The labels are automatic and provisional; this file is not a "
            "replacement for the planned blinded human review.",
        ]
    )
    Path(args.report).write_text("\n".join(lines) + "\n", encoding="utf-8")

    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": [args.merged, args.queue],
        "outputs": [args.out, str(versioned), args.report],
        "records": len(ledger),
        "judged": judged,
        "labels": dict(labels),
        "status": dict(status_counts),
        "queue_join_key": "sample_id == record_id",
        "label_status": "automatic_provisional",
    }
    Path(args.manifest).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
