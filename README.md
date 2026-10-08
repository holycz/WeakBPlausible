# SSRF Repair Study — Reproducible Code

This folder contains the core code that supports the experiments and all headline
numbers in the paper *"Weak but Plausible: Investigating Incomplete SSRF Repairs
by Coding Agents"*. It is organized by the pipeline stage of the study. It does
**not** include the raw run outputs, evidence ledgers, or judge queues (large
data files), which are released separately with the full artifact.

## Pipeline at a glance

```
00_case_data ──► 10_agent_runs ──► 20_ledger ──► 30_judging ──► 50_paper_outputs
      │                │                │               │              ▲
      └────────────────┴────────────────┴───────────────┴──────────────┘
                                          │
                                          └── patcheval_dynamic (executable PoCs, case-level)
```

Every headline count in the paper traces to the 128-row condition-blind evidence
ledger and its judge queues; the dynamic (executable) outcomes trace to the
versioned PatchEval summary. This folder reproduces each stage that generates
those traces.

## Directory contents

### `00_case_data/` — case and manifest construction
- `build_php_ssrf_frozen.py` — the four curated PHP CWE-918 snippets
  (certificate AIA fetch, remote media ingestion, image URL, CalDAV test).
- `build_patcheval_ssrf_seed.py` — the ten cross-language (JS/Go/Python)
  CWE-918 PatchEval-Verified seed.
- `build_ssrf_experiment_manifest.py` — the case-first run manifest
  (case × setting × seed).

### `10_agent_runs/` — coding-agent repair runs
- `run_php_ssrf_frozen_prompt_only.py` — PHP prompt-only baseline.
- `run_php_ssrf_frozen_verifier.py` — PHP guided single-revision runs.
- `run_php_ssrf_contract_guided.py` — PHP deterministic contract-feedback revision.
- `run_ssrf_verifier_guided.py` — cross-language verifier-guided runs.
- `run_ssrf_neutral_second_pass.py` — neutral second-pass control (no security
  verifier evidence).
- `run_patcheval_ssrf_batch.py` — cross-language prompt-only batch repair.

### `20_ledger/` — merge and auditable accounting
- `merge_ssrf_results.py` — independent-run merge with explicit rerun
  semantics (reruns only replace failed rows; never inflate the sample).
- `build_ssrf_evidence_ledger.py` — the single 128-row evidence ledger.
- `build_ssrf_condition_blind_ledger.py` — joins condition-blind primary-judge
  outputs into the retained-slot ledger (v03) used by the paper statistics.
- `validate_ssrf_provenance.py` — audits case provenance metadata.

### `30_judging/` — automatic judgment
- `build_ssrf_result_judge_queue.py` / `build_ssrf_rejudge_all_queue.py` /
  `build_ssrf_judge_queue.py` / `build_ssrf_second_judge_batches.py` — build the
  condition-blind judging queues.
- `judge_ssrf_queue_condition_blind.py` — the primary condition-blind judge
  (same model config as repair, temperature zero, content-derived blind IDs).
- `judge_ssrf_queue_gpt56_matched.py` — the protocol-matched GPT-5.6
  cross-family sensitivity judge.
- `judge_ssrf_queue.py` / `judge_ssrf_repairs_external.py` — earlier judge runners.
- `analyze_ssrf_condition_blind_judges.py` / `analyze_ssrf_matched_judges.py` —
  compare primary vs. GPT-5.6 labels (agreement, kappa).

### `40_failure_analysis/` — RQ2 failure classes and static signals
- `audit_ssrf_failure_modes.py` — lexical SSRF risk-signal audit.
- `audit_php_ssrf_outputs.py`, `check_php_ssrf_contract.py` — source-level
  contract checks and transparent audits.
- `aggregate_php_ssrf_v2.py`, `analyze_real_ssrf.py`,
  `analyze_ssrf_second_pass_control.py` — descriptive aggregation and controls.

### `50_paper_outputs/` — paper statistics, numbers, and figures
- `analyze_ssrf_ledger.py` — RQ1 case-aware resampling and weak-label
  statistics (`--seed 20260830` reproduces the reported descriptive range).
- `analyze_ssrf_paired.py` — RQ3 paired prompt-only vs. guided analysis with an
  exact paired sign/McNemar test.
- `paper_stats_ssrf.py` — descriptive pilot statistics.
- `plot_ssrf_paper_results.py` — generates the paper outcome figure and the
  rationale-derived failure-pattern counts (Table `tab:failures`).
- `summarize_ssrf_paper_numbers.py` — single machine-checkable JSON containing
  every number used in the paper (128 slots, 8/98/1 and 22/71/14 judge counts,
  RQ1/RQ2/RQ3, agreement, dynamic outcomes).

### `patcheval_dynamic/` — executable PatchEval validation (case-level PoCs)
- `run_patcheval_cve_*.sh`, `run_patcheval_go_case.sh` — per-case PoC runners.
- `patcheval_*_test.js` — PoC test programs (e.g. redirect bypass, IPv6 bypass).
- `patcheval_case_prepare.sh`, `probe_patcheval_container.sh`,
  `inspect_patcheval_case.sh` — environment preparation / inspection.
- `patcheval_replace_es_module.py`, `patcheval_replace_from_record.py`,
  `replace_python_function.py` — apply a candidate/reference fix into the case.
- `build_dynamic_case_summary.py` — summary of dynamic outcomes per case.
- `build_patcheval_provenance_manifest.py` — versioned provenance for the
  dynamic summary.

## Run order (to reproduce the headline numbers)

```bash
# 1. build case data + run manifest
python3 upload_code/00_case_data/build_php_ssrf_frozen.py
python3 upload_code/00_case_data/build_patcheval_ssrf_seed.py
python3 upload_code/00_case_data/build_ssrf_experiment_manifest.py

# 2. agent runs (wildcard per case/seed; these call the coding agent)
python3 upload_code/10_agent_runs/run_php_ssrf_frozen_prompt_only.py
python3 upload_code/10_agent_runs/run_php_ssrf_frozen_verifier.py
python3 upload_code/10_agent_runs/run_ssrf_verifier_guided.py
python3 upload_code/10_agent_runs/run_patcheval_ssrf_batch.py
# optional: run_php_ssrf_contract_guided.py, run_ssrf_neutral_second_pass.py

# 3. merge + ledger + condition-blind ledger
python3 upload_code/20_ledger/merge_ssrf_results.py
python3 upload_code/20_ledger/build_ssrf_evidence_ledger.py
python3 upload_code/20_ledger/build_ssrf_condition_blind_ledger.py

# 4. condition-blind judging (primary DeepSeek + GPT-5.6 sensitivity)
python3 upload_code/30_judging/build_ssrf_result_judge_queue.py
python3 upload_code/30_judging/judge_ssrf_queue_condition_blind.py
python3 upload_code/30_judging/judge_ssrf_queue_gpt56_matched.py
python3 upload_code/30_judging/analyze_ssrf_condition_blind_judges.py

# 5. paper statistics, numbers, and figure
python3 upload_code/50_paper_outputs/analyze_ssrf_ledger.py \
  --ledger results/experiments/SSRF_EVIDENCE_LEDGER_v03_CONDITION_BLIND.jsonl \
  --seed 20260830
python3 upload_code/50_paper_outputs/plot_ssrf_paper_results.py
python3 upload_code/50_paper_outputs/summarize_ssrf_paper_numbers.py
```

## Dependencies and notes

- Run scripts depend on the `safe2merge` package (in the repo's `src/`, plus the
  `OpenCode` coding-agent CLI). Those are not bundled here; set up the project
  environment and place the agent CLI on `PATH` before running.
- `10_agent_runs`, `30_judging`, and the PatchEval runners require API/model
  credentials and network access; they are omitted from dry runs.
- Some analysis scripts default to the **final** `v03_CONDITION_BLIND` ledger,
  while a few `40_failure_analysis` scripts still reference the earlier `v02`
  ledger. The paper's RQ2 counts come from `plot_ssrf_paper_results.py`
  (v03). Default paths assume the repo layout (`results/experiments/`).
- `plot_ssrf_paper_results.py` calls `rsvg-convert` to emit the PDF figure.
- Labels are automatic-judge outputs only; they do not establish exploitability,
  prevalence, or causal benefit. Executable PoCs cover only the PatchEval cases.
