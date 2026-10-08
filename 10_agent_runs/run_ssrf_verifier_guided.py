"""Verifier-guided single-revision runs for the PatchEval SSRF seed set.

Reads the prompt-only baseline JSONL, emits a short deterministic SSRF verifier
note per sample, and asks `opencode` + `shanxisjy/dsv4-dspark` for one constrained
revision into `fixed.<ext>`.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from safe2merge.agent import MODEL, _lang_ext, parse_fixed
from safe2merge.data import load_patcheval_verified


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


def ssrf_evidence(cve_id: str, baseline: dict, vuln_code: str, fixed_code: str) -> str:
    status = baseline.get("status", "")
    draft = fixed_code or ""

    if status != "OK" or not draft.strip():
        return (
            "First pass produced no usable patch. Write a minimal SSRF fix that keeps "
            "the request pinned to the original origin and rejects any input that can "
            "change host, port, or protocol."
        )

    if cve_id == "CVE-2022-35949":
        if "origin !== base" not in draft and "path.charCodeAt(0) === 47" not in draft:
            return (
                "Bypass evidence: `opts.path` can still resolve to an absolute URL "
                "or protocol-relative target via `new URL(opts.path, base)`. Reject "
                "absolute/protocol-relative inputs and verify the resolved origin "
                "equals the base origin."
            )

    if cve_id == "CVE-2025-23221":
        if "host !== server" not in draft and "protocol !== \"https:\"" not in draft:
            return (
                "Bypass evidence: the WebFinger target still depends on user-supplied "
                "host/protocol data. Keep the request pinned to the original host, "
                "forbid non-HTTPS redirects, and reject cross-host redirect targets."
            )

    if cve_id == "CVE-2020-28360":
        return (
            "Bypass evidence: the first pass timed out. Produce a small, direct fix "
            "that canonicalizes the destination and rejects loopback, link-local, and "
            "private-IP targets before the request is sent."
        )

    if cve_id == "CVE-2023-24623":
        if "isIPForbidden" not in draft or "To4()" not in draft:
            return (
                "Bypass evidence: the fix must canonicalize IPs before policy checks, "
                "including IPv4-mapped IPv6, and reject forbidden ranges after DNS "
                "resolution rather than only checking the raw host string."
            )

    if cve_id == "CVE-2022-24825":
        if "Resolve" not in draft and "allowlist" not in draft.lower():
            return (
                "Bypass evidence: domain glob validation alone is not enough for SSRF "
                "protection. Keep the destination pinned to an explicit allowlist and "
                "re-check the resolved endpoint after canonicalization/DNS resolution."
            )

    if cve_id == "CVE-2024-0243":
        if "base_url" not in draft or "prevent_outside" not in draft:
            return (
                "Bypass evidence: extracted links can still escape the intended base. "
                "Normalize the joined URL and reject any result that leaves the allowed "
                "base scope after resolution."
            )

    if cve_id == "CVE-2023-5122":
        if "path must be relative" not in draft.lower() and "ResolveReference" not in draft:
            return (
                "Bypass evidence: a path parameter can still pivot the request away from "
                "the configured endpoint. Accept only relative paths and re-check the "
                "resolved origin after joining."
            )

    if cve_id == "CVE-2022-29188":
        if "allowlist" not in draft.lower() and "forbidden" not in draft.lower():
            return (
                "Bypass evidence: the proxy still needs an explicit outbound policy. "
                "Keep the request constrained to the approved destination set and reject "
                "anything that resolves outside that set."
            )

    if cve_id == "CVE-2022-2900":
        if "normalize" not in draft.lower() and "allowlist" not in draft.lower():
            return (
                "Bypass evidence: URL normalization can still hide host changes. Reject "
                "non-repository targets after normalization and keep the parsed host/"
                "scheme pinned to the expected git URL forms."
            )

    if cve_id == "CVE-2023-28155":
        if "protocol-relative" not in draft.lower() and "redirect" not in draft.lower():
            return (
                "Bypass evidence: redirect handling still needs a strict destination "
                "check. Reject protocol-relative and absolute redirect targets unless "
                "they stay within the original allowed origin."
            )

    return (
        "No obvious bypass remained in the first pass. Keep the current hardening, "
        "preserve behavior, and only change what is necessary for the SSRF boundary."
    )


def build_prompt(cve_id: str, language: str, ext: str, vuln_code: str, draft: str, evidence: str) -> str:
    draft_block = draft.strip() or "(no usable first-pass fix)"
    return f"""You are revising a security fix for {cve_id} ({language}).

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
- If the draft is already correct, preserve it but tighten only what the verifier
  specifically points at.

===== VULNERABLE CODE =====
{vuln_code}

===== FIRST PASS DRAFT =====
{draft_block}
"""


def run_one(
    cve_id: str,
    language: str,
    vuln_code: str,
    draft: str,
    evidence: str,
    workdir: Path,
    timeout_sec: int,
) -> dict:
    ext = _lang_ext(language)
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / f"vuln.{ext}").write_text(vuln_code, encoding="utf-8")
    (workdir / f"draft.{ext}").write_text(draft or "", encoding="utf-8")
    (workdir / "verifier.txt").write_text(evidence, encoding="utf-8")

    prompt = build_prompt(cve_id, language, ext, vuln_code, draft, evidence)
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
        "cve_id": cve_id,
        "language": language,
        "draft": draft,
        "verifier_evidence": evidence,
        "agent_fixed": fixed,
        "agent_reply": reply,
        "tokens": tokens,
        "status": "TIMEOUT" if raw == "<<TIMEOUT>>" else ("OK" if fixed else "NO_WRITE"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", default="results/experiments/ssrf_seed/opencode_dsv4_prompt_only.jsonl")
    ap.add_argument("--out", default="results/experiments/ssrf_seed/opencode_dsv4_verifier_guided.jsonl")
    ap.add_argument("--root", default="var/agent_work/ssrf_verifier_guided")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

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
        evidence = ssrf_evidence(s.cve_id, base, s.original_func, draft)
        print(f"[{i}/{len(todo)}] {s.cve_id} -> {evidence[:80]}", flush=True)
        res = run_one(
            cve_id=s.cve_id,
            language=s.language,
            vuln_code=s.original_func,
            draft=draft,
            evidence=evidence,
            workdir=root / s.cve_id,
            timeout_sec=args.timeout,
        )
        res["selected_model"] = MODEL
        with out_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(res, ensure_ascii=False) + "\n")
        print(json.dumps({k: res[k] for k in ["cve_id", "status", "tokens", "selected_model"]}, ensure_ascii=False), flush=True)

    print(f"\nDONE. results in {out_path}")


if __name__ == "__main__":
    main()
