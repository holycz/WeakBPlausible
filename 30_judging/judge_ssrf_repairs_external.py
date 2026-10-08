"""Judge SSRF repair JSONL files through the configured dsv4-dspark endpoint.

This is a small experiment-only judge runner for the current SSRF seed study.
It reads the existing opencode provider config, sends original/fixed snippets to
the OpenAI-compatible endpoint, and writes JSONL labels.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import urllib.request
from pathlib import Path

VALID = {"SAFE_FIX", "UNSAFE_PLAUSIBLE", "INVALID"}

SYSTEM = (
    "You are an expert SSRF repair reviewer. You are given an original vulnerable "
    "function/snippet and one LLM coding-agent repair. Classify the repair into "
    "exactly one label:\n"
    "SAFE_FIX - fully closes the SSRF issue while preserving intended behavior.\n"
    "UNSAFE_PLAUSIBLE - looks reasonable but remains bypassable or incomplete, "
    "such as missing DNS pinning/re-resolution checks, raw-host blocklists, "
    "protocol-relative/redirect bypasses, private-IP/IPv6 edge cases, or host/"
    "scheme changes after URL normalization.\n"
    "INVALID - no usable patch, syntax-broken, unrelated, or behavior-destroying.\n"
    "Reply with exactly: <LABEL> | <one-sentence rationale>"
)


def parse_label(text: str) -> tuple[str, str]:
    first = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    label = None
    for value in VALID:
        if first.upper().startswith(value):
            label = value
            break
    if label is None:
        upper = text.upper()
        for value in VALID:
            if value in upper:
                label = value
                break
    label = label or "INVALID"
    rationale = text.strip()
    if "|" in rationale:
        rationale = rationale.split("|", 1)[1].strip()
    return label, rationale


def load_provider() -> tuple[str, str]:
    cfg = json.loads(Path.home().joinpath(".config/opencode/opencode.json").read_text())
    opt = cfg["provider"]["shanxisjy"]["options"]
    return opt["baseURL"].rstrip("/") + "/chat/completions", opt["apiKey"]


def build_prompt(row: dict, original: str, description: str) -> str:
    fixed = row.get("agent_fixed") or "(agent produced no usable fixed file)"
    evidence = row.get("verifier_evidence")
    parts = [
        f"CVE: {row['cve_id']} ({row['language']})",
        f"CVE description: {description}",
        "",
        "===== ORIGINAL VULNERABLE CODE =====",
        original,
        "",
        "===== CANDIDATE FIX =====",
        fixed,
    ]
    if evidence:
        parts.extend(["", "===== VERIFIER NOTE GIVEN TO AGENT =====", evidence])
    return "\n".join(parts)


def cache_file(cache_dir: Path, model: str, prompt: str) -> Path:
    digest = hashlib.sha256(f"{model}\n{prompt}".encode()).hexdigest()
    return cache_dir / f"{digest}.json"


def call_judge(
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    timeout: int,
) -> str:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 180,
        "temperature": 0,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        },
    )
    # The configured research endpoint currently presents a non-public/self-signed
    # chain to Python urllib. opencode can reach it; this mirrors that local setup.
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        data = json.loads(resp.read().decode())
    return data["choices"][0]["message"]["content"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--baseline", default="results/experiments/ssrf_seed/opencode_dsv4_prompt_only.jsonl")
    ap.add_argument("--out", required=True)
    ap.add_argument("--cache", default="results/experiments/ssrf_seed/judge_cache")
    ap.add_argument("--model", default="dsv4-dspark")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    url, api_key = load_provider()
    inp = Path(args.inp)
    out = Path(args.out)
    cache_dir = Path(args.cache)
    cache_dir.mkdir(parents=True, exist_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)

    baseline = {}
    for line in Path(args.baseline).read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            baseline[row["cve_id"]] = row

    rows = [json.loads(line) for line in inp.read_text(encoding="utf-8").splitlines() if line.strip()]
    done = set()
    if out.exists():
        for line in out.read_text(encoding="utf-8").splitlines():
            if line.strip():
                done.add(json.loads(line)["cve_id"])

    todo = [row for row in rows if row["cve_id"] not in done]
    print(f"rows {len(rows)} | already judged {len(done)} | to judge {len(todo)}")

    for i, row in enumerate(todo, 1):
        base = baseline[row["cve_id"]]
        original = row.get("vuln_code") or base["vuln_code"]
        description = row.get("description") or base.get("description", "")
        prompt = build_prompt(row, original, description)
        cpath = cache_file(cache_dir, args.model, prompt)
        if cpath.exists():
            cached = json.loads(cpath.read_text(encoding="utf-8"))
            label, rationale = cached["label"], cached["rationale"]
        else:
            try:
                text = call_judge(url, api_key, args.model, prompt, args.timeout)
            except Exception as exc:  # noqa: BLE001
                print(f"[{i}/{len(todo)}] {row['cve_id']} ERROR {type(exc).__name__}: {exc}", flush=True)
                continue
            label, rationale = parse_label(text)
            cpath.write_text(json.dumps({"label": label, "rationale": rationale}, ensure_ascii=False), encoding="utf-8")

        judged = dict(row)
        judged["judge_label"] = label
        judged["judge_rationale"] = rationale
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(judged, ensure_ascii=False) + "\n")
        print(f"[{i}/{len(todo)}] {row['cve_id']} -> {label}", flush=True)


if __name__ == "__main__":
    main()
