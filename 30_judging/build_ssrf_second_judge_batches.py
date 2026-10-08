#!/usr/bin/env python3
"""Build small, ID-constrained batches for a blinded second LLM judge."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        default="results/experiments/ssrf_human_blind_v02/reviewer_a/blind_samples.jsonl",
    )
    parser.add_argument(
        "--output",
        default="results/experiments/ssrf_second_judge_gpt56",
    )
    parser.add_argument("--batch-size", type=int, default=12)
    args = parser.parse_args()

    rows = read_jsonl(Path(args.input))
    if len(rows) != 107 or len({row["sample_id"] for row in rows}) != 107:
        raise SystemExit("expected 107 unique blinded samples")

    output = Path(args.output)
    batches = output / "batches"
    batches.mkdir(parents=True, exist_ok=True)
    manifest = []
    for start in range(0, len(rows), args.batch_size):
        batch_rows = rows[start : start + args.batch_size]
        number = start // args.batch_size + 1
        batch_dir = batches / f"batch_{number:02d}"
        batch_dir.mkdir(parents=True, exist_ok=True)
        samples_path = batch_dir / "samples.jsonl"
        samples_path.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in batch_rows),
            encoding="utf-8",
        )
        allowed_ids = [row["sample_id"] for row in batch_rows]
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["reviewer", "reviews"],
            "properties": {
                "reviewer": {"const": "gpt-5.6-sol-blinded-second-judge"},
                "reviews": {
                    "type": "array",
                    "minItems": len(batch_rows),
                    "maxItems": len(batch_rows),
                    "items": {
                        "type": "object",
                        "required": ["sample_id", "label", "confidence", "rationale"],
                        "properties": {
                            "sample_id": {"enum": allowed_ids},
                            "label": {"enum": ["SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID"]},
                            "confidence": {"enum": ["high", "medium", "low"]},
                            "rationale": {"type": "string", "minLength": 1},
                        },
                        "additionalProperties": False,
                    },
                },
            },
            "additionalProperties": False,
        }
        (batch_dir / "schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        manifest.append({"batch": number, "count": len(batch_rows), "sample_ids": allowed_ids})

    (output / "batch_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(manifest)} batches for {len(rows)} blinded samples")


if __name__ == "__main__":
    main()
