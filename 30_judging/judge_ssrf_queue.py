"""Judge each unique SSRF case-run in a semantic queue.

Unlike the older CVE-keyed judge, this script keys completion and cache entries
by sample_id, so repeated seeds of the same CVE are all evaluated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import urllib.request
from pathlib import Path

VALID = {"SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID"}
MODEL = "dsv4-dspark"

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
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def strip_jsonc(text: str) -> str:
    """Accept common JSONC features used by opencode configs."""
    out: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            i = text.find("\n", i)
            if i == -1:
                break
            out.append("\n")
            i += 1
            continue
        if ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            i = len(text) if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    text = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def extract_provider_raw(text: str) -> tuple[str, str]:
    key_match = re.search(r'"apiKey"\s*:\s*"([^"]+)"', text)
    url_match = re.search(r'"baseURL"\s*:\s*"([^"]+)"', text)
    if not key_match or not url_match:
        raise ValueError("could not extract shanxisjy provider from opencode config")
    return url_match.group(1).rstrip("/") + "/chat/completions", key_match.group(1)


def load_provider(base_url: str | None = None, api_key: str | None = None) -> tuple[str, str]:
    if base_url and api_key:
        return base_url.rstrip("/") + "/chat/completions", api_key

    env_url = os.environ.get("SSRF_JUDGE_BASE_URL")
    env_key = os.environ.get("SSRF_JUDGE_API_KEY")
    if env_url and env_key:
        return env_url.rstrip("/") + "/chat/completions", env_key

    config_path = Path.home().joinpath(".config/opencode/opencode.json")
    raw = config_path.read_text(encoding="utf-8")
    try:
        cfg = json.loads(strip_jsonc(raw))
    except json.JSONDecodeError:
        return extract_provider_raw(raw)
    opt = cfg["provider"]["shanxisjy"]["options"]
    return opt["baseURL"].rstrip("/") + "/chat/completions", opt["apiKey"]


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


def call(url: str, key: str, text: str, timeout: int) -> str:
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": text},
        ],
        "max_tokens": 180,
        "temperature": 0,
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + key,
        },
    )
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        data = json.loads(response.read().decode())
    return data["choices"][0]["message"]["content"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", default="results/experiments/SSRF_JUDGE_QUEUE_v01.jsonl")
    ap.add_argument("--out", default="results/experiments/SSRF_JUDGED_QUEUE_v01.jsonl")
    ap.add_argument("--cache", default="results/experiments/ssrf_seed/judge_cache_queue")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--base-url", default=None, help="OpenAI-compatible base URL ending in /v1")
    ap.add_argument("--api-key", default=None, help="API key; alternatively set SSRF_JUDGE_API_KEY")
    args = ap.parse_args()

    url, key = load_provider(args.base_url, args.api_key)
    rows = read_jsonl(Path(args.inp))
    out = Path(args.out)
    cache_dir = Path(args.cache)
    out.parent.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    done = {
        json.loads(line)["sample_id"]
        for line in out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    } if out.exists() else set()

    for index, row in enumerate(rows, 1):
        if row["sample_id"] in done:
            continue
        text = prompt(row)
        digest = hashlib.sha256(f"{MODEL}\n{row['sample_id']}\n{text}".encode()).hexdigest()
        cache = cache_dir / f"{digest}.json"
        if cache.exists():
            result = json.loads(cache.read_text(encoding="utf-8"))
        else:
            try:
                response = call(url, key, text, args.timeout)
                label, rationale = parse_label(response)
                result = {"judge_label": label, "judge_rationale": rationale}
                cache.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
            except Exception as exc:  # noqa: BLE001
                print(f"[{index}/{len(rows)}] {row['sample_id']} ERROR {exc}", flush=True)
                continue
        judged = {**row, **result}
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(judged, ensure_ascii=False) + "\n")
        print(f"[{index}/{len(rows)}] {row['sample_id']} -> {result['judge_label']}", flush=True)

    print(f"done -> {out}")


if __name__ == "__main__":
    main()
