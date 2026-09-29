# Empirical Detection of Security Vulnerabilities in LLM-Generated Code

Pipeline implementation for the hybrid static + dynamic analysis study
described in `Topic_2.pdf`. Generates Flask applications from 120 prompts
(40 tasks × 3 prompt styles) across two models (Groq, Gemini), 5 repeats
each (1,200 programs), scans them with Bandit (static) and OWASP ZAP
(dynamic), and merges results into one dataset for statistical analysis.

## Folder layout

```
llm_vuln_study/
├── prompts.csv                  # 120 prompts (40 tasks × 3 styles) — the study input
├── config.py                    # all paths/constants, read by every stage
├── generate_code.py             # Stage 1: call LLMs, save generated programs
├── static_analysis.py           # Stage 2: Bandit (+ optional SonarQube)
├── dynamic_analysis.py          # Stage 3: Docker + OWASP ZAP baseline scan
├── classify_vulnerabilities.py  # OWASP category lookup tables
├── merge_results.py             # Stage 4: merge into master_dataset.csv
├── run_pipeline.py              # orchestrator — runs all stages in order
├── analysis.ipynb               # Stage 5: statistics + plots (exploratory)
├── requirements.txt
└── data/
    ├── generated/<program_id>/  # app.py, meta.json, Dockerfile per program
    ├── static_reports/          # <program_id>.json (Bandit)
    ├── dynamic_reports/         # <program_id>.json (ZAP)
    └── master/master_dataset.csv
```

`program_id` format: `<task_id>_<model>_<prompt_type>_<generation_index>`
e.g. `P001_groq_basic_1`.

## Setup

```bash
pip install -r requirements.txt

export GROQ_API_KEY=gsk_...        # https://console.groq.com
export GEMINI_API_KEY=AI...        # https://aistudio.google.com

# Optional overrides — sensible defaults are already set in config.py
export GROQ_MODEL_NAME=llama-3.3-70b-versatile
export GEMINI_MODEL_NAME=gemini-2.5-flash
```

You also need Docker installed (for Stage 3) and, for Stage 2's optional
SonarQube pass, a running SonarQube server with `sonar-scanner` on PATH.

## Before running: model calls are already wired up

`generate_code.py` implements `call_groq()` and `call_gemini()` directly
against the Groq and Gemini APIs — just set the two API keys above and
you're ready to run Stage 1. If you want to swap in different Groq- or
Gemini-hosted model names (e.g. a smaller/cheaper Groq model), change
`GROQ_MODEL_NAME` / `GEMINI_MODEL_NAME` rather than editing the code.

## Running the pipeline

Run stages individually the first time, so you can inspect output before
moving on:

```bash
python generate_code.py          # Stage 1 — writes data/generated/
python static_analysis.py        # Stage 2 — writes data/static_reports/
python dynamic_analysis.py       # Stage 3 — writes data/dynamic_reports/
python merge_results.py          # Stage 4 — writes data/master/master_dataset.csv
jupyter notebook analysis.ipynb  # Stage 5 — stats + plots
```

Or run everything at once (and resume from a given stage if it crashes
partway through):

```bash
python run_pipeline.py
python run_pipeline.py --from static   # resume, skipping generation
```

Every stage is resumable: re-running a stage skips programs that already
have output on disk (`--force` re-runs everything regardless).

## Notes on the design

- **Generation temperature is left at each provider's default**, not
  lowered — the study wants natural sampling variance across the 5
  repeats per prompt, not artificially deterministic output.
- **A program with no static or dynamic report** (e.g. it crashed on
  boot, or generation failed) is recorded in the master dataset with
  `has_static_report` / `has_dynamic_report` set to `False`. These count
  as zero vulnerabilities in the totals, which will understate the
  vulnerability rate if left unexamined — check `generation_log.csv` and
  filter or explicitly account for failed programs before running your
  statistical tests.
- **OWASP category mappings** in `classify_vulnerabilities.py` are
  starting points, not exhaustive. Skim `data/static_reports/*.json` and
  `data/dynamic_reports/*.json` after a real run and extend the lookup
  tables for any test IDs / alert names you see that map to
  "Other / Unclassified".
