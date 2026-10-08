#!/usr/bin/env python3
"""Join condition-blind primary-judge outputs into the retained-slot ledger."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-ledger",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v02.jsonl",
    )
    parser.add_argument(
        "--judged-queue",
        default="results/experiments/ssrf_condition_blind_original_v01/judged_queue.jsonl",
    )
    parser.add_argument(
        "--out",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v03_CONDITION_BLIND.jsonl",
    )
    parser.add_argument(
        "--manifest",
        default="results/experiments/SSRF_EVIDENCE_LEDGER_v03_CONDITION_BLIND.manifest.json",
    )
    args = parser.parse_args()

    base_path = Path(args.base_ledger)
    queue_path = Path(args.judged_queue)
    out_path = Path(args.out)
    manifest_path = Path(args.manifest)

    base = read_jsonl(base_path)
    judged_rows = read_jsonl(queue_path)
    judged = {row["record_id"]: row for row in judged_rows}
    if len(judged) != len(judged_rows):
        raise ValueError("condition-blind queue has duplicate record_id values")

    emitted_ids = {row["record_id"] for row in base if row.get("status") == "OK"}
    if emitted_ids != set(judged):
        missing = sorted(emitted_ids - set(judged))
        extra = sorted(set(judged) - emitted_ids)
        raise ValueError(f"queue/ledger mismatch: missing={missing}, extra={extra}")

    output: list[dict] = []
    copied_fields = (
        "judge_label",
        "judge_rationale",
        "blind_id",
        "judge_model",
        "judge_temperature",
        "judge_max_tokens",
        "judge_tools",
        "judge_condition_blind",
        "request_sha256",
        "response_id",
        "response_model",
    )
    for row in base:
        merged = dict(row)
        if row.get("status") == "OK":
            source = judged[row["record_id"]]
            for field in copied_fields:
                merged[field] = source.get(field)
            merged["judge_source"] = "ssrf_condition_blind_original_v01"
        else:
            for field in copied_fields:
                merged.pop(field, None)
            merged["judge_source"] = "unjudged_delivery_record"
            merged.pop("judge_label", None)
            merged.pop("judge_rationale", None)
        output.append(merged)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in output),
        encoding="utf-8",
    )

    status = Counter(row.get("status") for row in output)
    labels = Counter(row.get("judge_label") for row in output if row.get("judge_label"))
    grouped: dict[str, dict[str, int]] = {}
    for dataset, setting in sorted({(r["dataset"], r["setting"]) for r in output}):
        rows = [r for r in output if r["dataset"] == dataset and r["setting"] == setting]
        key = f"{dataset}/{setting}"
        grouped[key] = {
            "slots": len(rows),
            "OK": sum(r.get("status") == "OK" for r in rows),
            "NO_WRITE": sum(r.get("status") == "NO_WRITE" for r in rows),
            "TIMEOUT": sum(r.get("status") == "TIMEOUT" for r in rows),
            "SAFE_FIX": sum(r.get("judge_label") == "SAFE_FIX" for r in rows),
            "UNSAFE_PLAUSIBLE": sum(r.get("judge_label") == "UNSAFE_PLAUSIBLE" for r in rows),
            "INVALID": sum(r.get("judge_label") == "INVALID" for r in rows),
        }
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_ledger": str(base_path),
        "judged_queue": str(queue_path),
        "output": str(out_path),
        "records": len(output),
        "unique_record_ids": len({row["record_id"] for row in output}),
        "judged": sum(labels.values()),
        "status": dict(status),
        "labels": dict(labels),
        "groups": grouped,
        "join_key": "record_id",
        "label_status": "automatic_condition_blind_primary",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
