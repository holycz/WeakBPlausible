"""Run prompt-only repairs on the frozen PHP SSRF mini-set."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from safe2merge.agent import MODEL, generate_fix


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", default="data/interim/php_ssrf_frozen_v01.jsonl")
    ap.add_argument("--out", default="results/experiments/php_ssrf_frozen/prompt_only.jsonl")
    ap.add_argument("--root", default="var/agent_work/php_ssrf_frozen/prompt_only")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    rows = load_rows(Path(args.inp))
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

    for i, r in enumerate(todo, 1):
        print(f"[{i}/{len(todo)}] {r['cve_id']} ({r['language']}) ...", flush=True)
        res = generate_fix(
            cve_id=r["cve_id"],
            vuln_code=r["vuln_code"],
            description=r["description"],
            language=r["language"],
            workdir=root / r["cve_id"],
            timeout_sec=args.timeout,
        )
        res["repo"] = r.get("repo", "")
        res["source"] = r.get("source", "")
        res["cwe"] = r.get("cwe", [])
        res["selected_model"] = MODEL
        with out_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(res, ensure_ascii=False) + "\n")
        print(json.dumps({"cve_id": r["cve_id"], "status": res["status"], "tokens": res["tokens"]}, ensure_ascii=False))

    print(f"DONE -> {out_path}")


if __name__ == "__main__":
    main()
