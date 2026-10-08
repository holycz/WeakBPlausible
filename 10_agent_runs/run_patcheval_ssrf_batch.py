"""Run independent prompt-only repairs on real PatchEval SSRF cases."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from safe2merge.agent import MODEL, parse_fixed


def load_rows(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def run_one(row: dict, run_tag: str, root: Path, timeout: int) -> dict:
    workdir = root / row["cve_id"]
    workdir.mkdir(parents=True, exist_ok=True)
    ext = row["extension"]
    (workdir / f"vuln.{ext}").write_text(row["vuln_code"], encoding="utf-8")
    prompt = f"""Repair the SSRF vulnerability in vuln.{ext}.

This is independent evaluation run {run_tag}. Do not assume another run's
answer. Inspect the vulnerable function and write the corrected full
function/snippet to fixed.{ext}. Preserve intended behavior and use valid
repository-compatible APIs. Then reply DONE.

CVE: {row['cve_id']}
Repository: {row['repo']}
Vulnerability description:
{row['description']}
"""
    cmd = [
        "opencode",
        "run",
        "--format",
        "json",
        "-m",
        MODEL,
        "--dir",
        str(workdir),
        prompt,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw = proc.stdout
        returncode = proc.returncode
        stderr = proc.stderr
    except subprocess.TimeoutExpired:
        raw = "<<TIMEOUT>>"
        returncode = None
        stderr = ""
    fixed, reply, tokens = parse_fixed(raw)
    return {
        "run_tag": run_tag,
        "cve_id": row["cve_id"],
        "language": row["language"],
        "extension": ext,
        "repo": row["repo"],
        "description": row["description"],
        "vuln_code": row["vuln_code"],
        "agent_fixed": fixed,
        "agent_reply": reply,
        "tokens": tokens,
        "status": (
            "TIMEOUT"
            if raw == "<<TIMEOUT>>"
            else ("OK" if fixed else "NO_WRITE")
        ),
        "returncode": returncode,
        "stderr": stderr,
        "selected_model": MODEL,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", default="data/interim/patcheval_ssrf_v01.jsonl")
    ap.add_argument("--run-tag", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    rows = load_rows(Path(args.input))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    done = set()
    if out.exists():
        for line in out.read_text(encoding="utf-8").splitlines():
            if line.strip():
                done.add(json.loads(line)["cve_id"])

    todo = [row for row in rows if row["cve_id"] not in done]
    print(f"run={args.run_tag} | total={len(rows)} | todo={len(todo)}", flush=True)
    for index, row in enumerate(todo, 1):
        print(
            f"[{index}/{len(todo)}] {row['cve_id']} {row['repo']} ...",
            flush=True,
        )
        result = run_one(row, args.run_tag, root, args.timeout)
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(result, ensure_ascii=False) + "\n")
        print(
            json.dumps(
                {
                    "cve_id": row["cve_id"],
                    "status": result["status"],
                    "tokens": result["tokens"],
                }
            ),
            flush=True,
        )
    print(f"DONE -> {out}", flush=True)


if __name__ == "__main__":
    main()
