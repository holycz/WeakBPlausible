"""Run a neutral second-pass repair control for the cross-language SSRF seed.

This mirrors the existing verifier-guided second pass, but does not provide any
security-specific verifier evidence. It only asks for a minimal revision that
preserves behavior and keeps the original repair intent.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from safe2merge.agent import MODEL, _lang_ext, parse_fixed


def load_rows(path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rows[row["cve_id"]] = row
    return rows


def neutral_note(row: dict, draft: str | None = None) -> str:
    return (
        "This is a neutral second-pass control. Revise the draft once, minimally, "
        "to preserve intended behavior and improve clarity or robustness only if "
        "the change is directly necessary for the repair. Do not add any security "
        "verifier evidence, bypass diagnosis, or extra hardening requirements. "
        "If the draft is already acceptable, keep it close to the current shape "
        "and avoid unrelated edits."
    )


def build_prompt(row: dict, draft: str, evidence: str, ext: str) -> str:
    return f"""You are revising a security fix for {row['cve_id']} ({row['language']}).

You already have a first-pass patch in `draft.{ext}`. Revise it once, minimally,
to close the SSRF issue. Keep the function behavior intact except for the security
boundary.

Control note:
{evidence}

Constraints:
- Do not introduce a broad security framework.
- Do not remove unrelated behavior.
- Do not add extra files.
- Write the corrected full function/snippet to `fixed.{ext}`.
- Before writing, mentally check syntax, identifier definitions, and every return path.
- Do not claim that a check exists unless the code actually implements it.
- Prefer a conservative rejection over an invented helper or unsupported API.
- If the draft is already correct, preserve it but tighten only what is directly
  necessary for the repair.

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
    evidence = neutral_note(row, draft)
    (workdir / "control.txt").write_text(evidence, encoding="utf-8")

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
        "control_note": evidence,
        "agent_fixed": fixed,
        "agent_reply": reply,
        "tokens": tokens,
        "status": "TIMEOUT" if raw == "<<TIMEOUT>>" else ("OK" if fixed else "NO_WRITE"),
        "selected_model": MODEL,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", default="data/interim/patcheval_ssrf_v01.jsonl")
    ap.add_argument(
        "--baseline",
        default="results/experiments/ssrf_seed/opencode_dsv4_prompt_only.jsonl",
    )
    ap.add_argument(
        "--out",
        default="results/experiments/ssrf_seed/opencode_dsv4_neutral_second_pass.jsonl",
    )
    ap.add_argument("--root", default="var/agent_work/ssrf_neutral_second_pass")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    from safe2merge.data import load_patcheval_verified

    raw = Path("data/raw")
    samples = [s for s in load_patcheval_verified(raw) if "CWE-918" in s.cwe_ids]
    baseline = load_rows(Path(args.baseline))
    out_path = Path(args.out)
    done = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["cve_id"])
                except Exception:
                    pass

    out_path.parent.mkdir(parents=True, exist_ok=True)
    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)

    todo = [s for s in samples if s.cve_id not in done]
    print(f"ssrf samples {len(samples)} | already done {len(done)} | to run {len(todo)}")

    for i, s in enumerate(todo, 1):
        base = baseline.get(s.cve_id, {})
        draft = base.get("agent_fixed") or ""
        print(f"[{i}/{len(todo)}] {s.cve_id} -> neutral second pass", flush=True)
        res = run_one(
            {
                "cve_id": s.cve_id,
                "language": s.language,
                "repo": base.get("repo", ""),
                "description": s.description,
                "vuln_code": s.original_func,
                "draft": draft,
            },
            root / s.cve_id,
            timeout_sec=args.timeout,
        )
        with out_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(res, ensure_ascii=False) + "\n")
        print(
            json.dumps(
                {
                    "cve_id": res["cve_id"],
                    "status": res["status"],
                    "tokens": res["tokens"],
                    "selected_model": res["selected_model"],
                },
                ensure_ascii=False,
            ),
            flush=True,
        )

    print(f"\nDONE. results in {out_path}")


if __name__ == "__main__":
    main()
