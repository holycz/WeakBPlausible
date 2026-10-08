#!/usr/bin/env python3
"""Run one SSRF judge with condition-blind, content-derived sample IDs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path


VALID = {"SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID"}
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


def strip_jsonc(text: str) -> str:
    out: list[str] = []
    index = 0
    in_string = False
    escape = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char == "/" and following == "/":
            index = text.find("\n", index)
            if index == -1:
                break
            out.append("\n")
            index += 1
            continue
        if char == "/" and following == "*":
            end = text.find("*/", index + 2)
            index = len(text) if end == -1 else end + 2
            continue
        out.append(char)
        index += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_opencode_provider() -> tuple[str, str]:
    raw = (Path.home() / ".config" / "opencode" / "opencode.json").read_text(encoding="utf-8")
    config = json.loads(strip_jsonc(raw))
    options = config["provider"]["shanxisjy"]["options"]
    return options["baseURL"].rstrip("/"), options["apiKey"]


def load_codex_provider() -> tuple[str, str]:
    key = os.environ.get("SSRF_GPT56_API_KEY")
    if not key:
        key = json.loads((Path.home() / ".codex" / "auth.json").read_text(encoding="utf-8"))["OPENAI_API_KEY"]
    return "http://127.0.0.1:15721/v1", key


def blind_id(row: dict) -> str:
    visible = json.dumps(
        {
            "cve_id": row["cve_id"],
            "language": row["language"],
            "description": row.get("description", ""),
            "vuln_code": row.get("vuln_code", ""),
            "agent_fixed": row.get("agent_fixed", ""),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return "BLIND-" + hashlib.sha256(visible.encode()).hexdigest()[:16]


def prompt(row: dict, sample_id: str) -> str:
    return "\n".join(
        [
            f"Sample: {sample_id}",
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


def call(endpoint: str, key: str, model: str, user_prompt: str, timeout: int) -> dict:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 180,
        "temperature": 0,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
    )
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.loads(response.read().decode())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="inp", default="results/experiments/SSRF_JUDGE_QUEUE_UNIFIED_v01.jsonl")
    parser.add_argument("--judge", choices=("original", "gpt56"), required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--retries", type=int, default=4)
    args = parser.parse_args()

    model = "dsv4-dspark" if args.judge == "original" else "gpt-5.6-sol"
    base_url, key = load_opencode_provider() if args.judge == "original" else load_codex_provider()
    endpoint = base_url.rstrip("/") + "/chat/completions"
    rows = read_jsonl(Path(args.inp))
    if len(rows) != 107 or len({row["sample_id"] for row in rows}) != 107:
        raise SystemExit("expected 107 unique candidate records")

    out_dir = Path(args.out_dir)
    raw_dir = out_dir / "raw_responses"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / "judged_queue.jsonl"
    completed = {row["sample_id"] for row in read_jsonl(output)} if output.exists() else set()

    for index, row in enumerate(rows, 1):
        original_id = row["sample_id"]
        if original_id in completed:
            print(f"[{index}/107] cached {original_id}", flush=True)
            continue
        opaque_id = blind_id(row)
        user_prompt = prompt(row, opaque_id)
        request_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "model": model,
                    "system": SYSTEM,
                    "user": user_prompt,
                    "max_tokens": 180,
                    "temperature": 0,
                    "tools": None,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        response = None
        last_error = None
        for attempt in range(args.retries + 1):
            try:
                response = call(endpoint, key, model, user_prompt, args.timeout)
                break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                if attempt < args.retries:
                    time.sleep(min(2 ** attempt, 8))
        if response is None:
            print(f"[{index}/107] {original_id} ERROR {last_error}", flush=True)
            continue
        raw_text = response["choices"][0]["message"]["content"]
        label, rationale = parse_label(raw_text)
        raw_record = {
            "sample_id": original_id,
            "blind_id": opaque_id,
            "request_sha256": request_sha256,
            "response_id": response.get("id"),
            "response_model": response.get("model"),
            "raw_text": raw_text,
            "usage": response.get("usage"),
        }
        (raw_dir / f"{hashlib.sha256(original_id.encode()).hexdigest()}.json").write_text(
            json.dumps(raw_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        judged = {
            **row,
            "blind_id": opaque_id,
            "judge_label": label,
            "judge_rationale": rationale,
            "judge_model": model,
            "judge_temperature": 0,
            "judge_max_tokens": 180,
            "judge_tools": False,
            "judge_condition_blind": True,
            "request_sha256": request_sha256,
            "response_id": response.get("id"),
            "response_model": response.get("model"),
        }
        with output.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(judged, ensure_ascii=False) + "\n")
        print(f"[{index}/107] {original_id} -> {label}", flush=True)

    final = read_jsonl(output) if output.exists() else []
    print(f"complete={len(final)}/107 output={output}", flush=True)


if __name__ == "__main__":
    main()
