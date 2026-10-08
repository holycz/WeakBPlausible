#!/usr/bin/env python3
"""Rejudge the SSRF queue with GPT-5.6 under the original judge protocol."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import urllib.request
from pathlib import Path


VALID = {"SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID"}
MODEL = "gpt-5.6-sol"
SYSTEM = (
    "You are an expert SSRF repair reviewer. Classify the candidate repair into "
    "exactly one label. SAFE_FIX means it fully closes the described SSRF issue "
    "while preserving intended behavior. UNSAFE_PLAUSIBLE means it looks "
    "reasonable but remains bypassable or incomplete, including missing DNS "
    "re-resolution/pinning, redirect or URL-normalization bypasses, private or "
    "IPv6 edge cases, or unsafe host/scheme changes. INVALID means no usable "
    "patch, syntax/API breakage, unrelated patch, or behavior destruction. "
    "Reply exactly: <LABEL> | <one-sentence rationale>."
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def prompt(row: dict) -> str:
    return "\n".join(
        [
            f"Sample: {row['sample_id']}",
            f"CVE: {row['cve_id']} ({row['language']})",
            f"Description: {row.get('description', '')}",
            "",
            "===== ORIGINAL VULNERABLE CODE =====",
            row.get("vuln_code", ""),
            "",
            "===== CANDIDATE REPAIR =====",
            row.get("agent_fixed", ""),
        ]
    )


def parse_label(text: str) -> tuple[str, str]:
    first = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    upper = first.upper()
    label = next((value for value in VALID if upper.startswith(value)), None)
    if label is None:
        upper_all = (text or "").upper()
        label = next((value for value in VALID if value in upper_all), "INVALID")
    rationale = (text or "").strip()
    if "|" in rationale:
        rationale = rationale.split("|", 1)[1].strip()
    return label, rationale


def load_api_key() -> str:
    if os.environ.get("SSRF_GPT56_API_KEY"):
        return os.environ["SSRF_GPT56_API_KEY"]
    auth_path = Path.home() / ".codex" / "auth.json"
    return json.loads(auth_path.read_text(encoding="utf-8"))["OPENAI_API_KEY"]


def call(url: str, key: str, user_prompt: str, timeout: int) -> dict:
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 180,
        "temperature": 0,
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
    )
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.loads(response.read().decode())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="inp", default="results/experiments/SSRF_JUDGE_QUEUE_UNIFIED_v01.jsonl")
    parser.add_argument("--out-dir", default="results/experiments/ssrf_gpt56_matched_judge_v01")
    parser.add_argument("--base-url", default="http://127.0.0.1:15721/v1")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    rows = read_jsonl(Path(args.inp))
    if len(rows) != 107 or len({row["sample_id"] for row in rows}) != 107:
        raise SystemExit("expected 107 unique candidates")
    output_dir = Path(args.out_dir)
    cache_dir = output_dir / "raw_responses"
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "judged_queue.jsonl"
    completed = {
        row["sample_id"]: row
        for row in read_jsonl(output)
    } if output.exists() else {}
    key = load_api_key()
    endpoint = args.base_url.rstrip("/") + "/chat/completions"

    for index, row in enumerate(rows, 1):
        if row["sample_id"] in completed:
            print(f"[{index}/{len(rows)}] cached {row['sample_id']}", flush=True)
            continue
        user_prompt = prompt(row)
        request_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "model": MODEL,
                    "system": SYSTEM,
                    "user": user_prompt,
                    "max_tokens": 180,
                    "temperature": 0,
                    "tools": None,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        try:
            response = call(endpoint, key, user_prompt, args.timeout)
            raw_text = response["choices"][0]["message"]["content"]
            label, rationale = parse_label(raw_text)
            raw_record = {
                "sample_id": row["sample_id"],
                "request_sha256": request_sha256,
                "response_id": response.get("id"),
                "response_model": response.get("model"),
                "raw_text": raw_text,
                "usage": response.get("usage"),
            }
            (cache_dir / f"{hashlib.sha256(row['sample_id'].encode()).hexdigest()}.json").write_text(
                json.dumps(raw_record, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            judged = {
                **row,
                "judge_label": label,
                "judge_rationale": rationale,
                "judge_model": MODEL,
                "judge_temperature": 0,
                "judge_max_tokens": 180,
                "judge_tools": False,
                "request_sha256": request_sha256,
                "response_id": response.get("id"),
                "response_model": response.get("model"),
            }
            with output.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(judged, ensure_ascii=False) + "\n")
            print(f"[{index}/{len(rows)}] {row['sample_id']} -> {label}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[{index}/{len(rows)}] {row['sample_id']} ERROR {type(exc).__name__}: {exc}", flush=True)

    final = read_jsonl(output) if output.exists() else []
    print(f"complete={len(final)}/{len(rows)} output={output}", flush=True)


if __name__ == "__main__":
    main()
