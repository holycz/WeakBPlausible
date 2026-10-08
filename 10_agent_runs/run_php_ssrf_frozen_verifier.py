"""Run verifier-guided single-revision repairs on the frozen PHP SSRF mini-set."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from safe2merge.agent import MODEL, _lang_ext, parse_fixed


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def verifier_note(row: dict, draft: str | None = None) -> str:
    cve_id = row["cve_id"]
    if cve_id == "CVE-2026-55599":
        return (
            "Patch contract for this function: (1) parse and allow only http/https; "
            "(2) resolve every A and AAAA record and reject loopback, private, link-local, "
            "multicast, unspecified, and IPv4-mapped IPv6 targets; (3) connect to the "
            "approved resolved IP, not a fresh hostname lookup; (4) preserve the original "
            "Host/SNI semantics; (5) do not follow redirects; (6) use only PHP APIs visible "
            "in the snippet or standard PHP APIs. A prose claim is insufficient: the final "
            "code must be syntactically valid and self-contained."
        )
    if cve_id == "CVE-2026-48555":
        return (
            "Patch contract for this method: preserve only intended http/https behavior; "
            "validate every resolved A/AAAA address before download; reject loopback, private, "
            "link-local, multicast, unspecified, and IPv4-mapped IPv6 targets; disable or "
            "revalidate redirects; prevent DNS rebinding by pinning the approved IP or using "
            "a downloader with an explicit safe transport policy; use valid existing PHP/Laravel "
            "APIs only. Do not invent identifiers or silently turn the method into a no-op."
        )
    if cve_id == "CVE-2025-54370":
        return (
            "Patch contract for this method: do not fetch file, ftp, or s3 schemes; keep only "
            "the intended image behavior; validate all A/AAAA results and reject loopback, "
            "private, link-local, multicast, unspecified, and IPv4-mapped IPv6 addresses; "
            "disable redirects or validate every redirect target; use valid PhpSpreadsheet/PHP "
            "APIs already available. The patch must compile and must not replace one arbitrary "
            "URL fetch with another."
        )
    if cve_id == "CVE-2026-52840":
        return (
            "Patch contract for this controller: accept only a valid CalDAV http/https URL; "
            "resolve and validate every A/AAAA address before test_connection; reject loopback, "
            "private, link-local, multicast, unspecified, and IPv4-mapped IPv6 targets; "
            "disable redirects or enforce same-origin redirect validation; keep the provider "
            "save behavior intact; use existing project helpers and valid PHP syntax only."
        )
    return "Preserve behavior, enforce an explicit outbound policy, and remove every residual URL pivot."


def build_prompt(row: dict, draft: str, evidence: str, ext: str) -> str:
    return f"""You are revising a security fix for {row['cve_id']} ({row['language']}).

You already have a first-pass patch in `draft.{ext}`. Revise it once, minimally,
to close the SSRF issue. Keep the function behavior intact except for the security
boundary.

Deterministic verifier note:
{evidence}

Constraints:
- Do not introduce a broad security framework.
- Do not remove unrelated behavior.
- Do not add extra files.
- Write the corrected full function/snippet to `fixed.{ext}`.
- Before writing, mentally check syntax, identifier definitions, and every return path.
- Do not claim that a check exists unless the code actually implements it.
- Prefer a conservative rejection over an invented helper or unsupported API.
- If the draft is already correct, preserve it but tighten only what the verifier
  specifically points at.

===== VULNERABLE CODE =====
{row['vuln_code']}

===== FIRST PASS DRAFT =====
{draft or '(no usable first-pass fix)'}
"""


def run_one(row: dict, workdir: Path, timeout_sec: int = 300) -> dict:
    ext = _lang_ext(row["language"])
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / f"vuln.{ext}").write_text(row["vuln_code"], encoding="utf-8")
    draft = row.get("draft") or ""
    (workdir / f"draft.{ext}").write_text(draft, encoding="utf-8")
    evidence = verifier_note(row, draft)
    (workdir / "verifier.txt").write_text(evidence, encoding="utf-8")

    prompt = build_prompt(row, draft, evidence, ext)
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
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        raw = proc.stdout
    except subprocess.TimeoutExpired:
        raw = "<<TIMEOUT>>"

    fixed, reply, tokens = parse_fixed(raw)
    return {
        "cve_id": row["cve_id"],
        "language": row["language"],
        "repo": row.get("repo", ""),
        "description": row.get("description", ""),
        "vuln_code": row["vuln_code"],
        "draft": draft,
        "verifier_evidence": evidence,
        "agent_fixed": fixed,
        "agent_reply": reply,
        "tokens": tokens,
        "status": "TIMEOUT" if raw == "<<TIMEOUT>>" else ("OK" if fixed else "NO_WRITE"),
        "selected_model": MODEL,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", default="data/interim/php_ssrf_frozen_v01.jsonl")
    ap.add_argument("--baseline", default="results/experiments/php_ssrf_frozen/prompt_only.jsonl")
    ap.add_argument("--out", default="results/experiments/php_ssrf_frozen/verifier_guided.jsonl")
    ap.add_argument("--root", default="var/agent_work/php_ssrf_frozen/verifier_guided")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    rows = load_rows(Path(args.inp))
    baseline = {}
    base_path = Path(args.baseline)
    if base_path.exists():
        for line in base_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                baseline[row["cve_id"]] = row

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                done.add(json.loads(line)["cve_id"])

    todo = [r for r in rows if r["cve_id"] not in done]
    print(f"rows {len(rows)} | already done {len(done)} | to run {len(todo)}")

    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    for i, row in enumerate(todo, 1):
        base = baseline.get(row["cve_id"], {})
        row["draft"] = base.get("agent_fixed") or ""
        print(f"[{i}/{len(todo)}] {row['cve_id']} ({row['language']}) ...", flush=True)
        res = run_one(row, root / row["cve_id"], timeout_sec=args.timeout)
        with out_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(res, ensure_ascii=False) + "\n")
        print(json.dumps({"cve_id": row["cve_id"], "status": res["status"], "tokens": res["tokens"]}, ensure_ascii=False))

    print(f"DONE -> {out_path}")


if __name__ == "__main__":
    main()
