"""
Stage 1 — Code generation.

Reads prompts.csv (task_id, prompt_type, prompt_text, ...), sends each
prompt to each model GENERATIONS_PER_PROMPT times, and saves every
resulting program to disk as its own folder:

    data/generated/<program_id>/
        app.py            (or additional files, if the model returns a project)
        meta.json          (task_id, model, prompt_type, generation_index, raw response)

program_id format: <task_id>_<model>_<prompt_type>_<gen_index>
    e.g. P001_groq_basic_1

Resumability: generation_log.csv records every completed program_id, so
re-running this script skips anything already generated instead of
re-spending API calls.

Models used: Groq (call_groq) and Gemini (call_gemini). Set GROQ_API_KEY
and GEMINI_API_KEY as environment variables before running.
"""

import csv
import json
import re
import sys
import time
from pathlib import Path

import config


# ---------------------------------------------------------------------------
# Model call functions — implement these against your actual providers
# ---------------------------------------------------------------------------

def call_groq(prompt_text: str) -> str:
    """
    Call the Groq API (OpenAI-compatible chat completions) and return the
    raw text response. Requires: pip install groq
    """
    if not config.GROQ_API_KEY:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Export it before running this script."
        )

    from groq import Groq

    client = Groq(api_key=config.GROQ_API_KEY)
    response = client.chat.completions.create(
        model=config.GROQ_MODEL_NAME,
        messages=[{"role": "user", "content": prompt_text}],
        temperature=1.0,   # keep default-ish temperature — you WANT natural
                           # variance across the 5 repeats, not artificially
                           # low randomness
    )
    return response.choices[0].message.content


def call_gemini(prompt_text: str) -> str:
    """
    Call the Gemini API and return the raw text response.
    Requires: pip install google-genai
    (the older `google-generativeai` package is deprecated — do not use it)
    """
    if not config.GEMINI_API_KEY:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Export it before running this script."
        )

    from google import genai
    from google.genai import types

    

    client = genai.Client(api_key=config.GEMINI_API_KEY)
    chat = client.chats.create(model=config.GEMINI_MODEL_NAME, config=types.GenerateContentConfig(temperature=1.0))
    response = chat.send_message(prompt_text)
    return response.text


MODEL_CALLERS = {
    "groq": call_groq,
    "gemini": call_gemini,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CODE_BLOCK_RE = re.compile(r"```([\w+-]*)\s*\n(.*?)```", re.DOTALL)

def extract_code(raw_response: str) -> str:
    matches = CODE_BLOCK_RE.findall(raw_response)
    if not matches:
        return raw_response.strip()
    python_blocks = [code for lang, code in matches if lang.lower() in ("python", "py")]
    candidates = python_blocks if python_blocks else [code for _, code in matches]
    best = max(candidates, key=len)
    return best.strip()
 
def load_prompts(csv_path: Path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_completed_ids(log_path: Path) -> set:
    if not log_path.exists():
        return set()
    with open(log_path, newline="", encoding="utf-8") as f:
        return {row["program_id"] for row in csv.DictReader(f)}


def append_log(log_path: Path, row: dict):
    file_exists = log_path.exists()
    with open(log_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["program_id", "status", "timestamp"])
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


# ---------------------------------------------------------------------------
# Main generation loop
# ---------------------------------------------------------------------------

def generate_all(retry_failures: bool = False, limit_tasks: int = None, generations_override: int = None):
    prompts = load_prompts(config.PROMPTS_CSV)
    completed = load_completed_ids(config.GENERATION_LOG)
 
    if limit_tasks is not None:
        # Keep whole task groups together (all 3 prompt styles for a task_id),
        # not an arbitrary row cut, so a limited run still exercises every
        # prompt_type at least once.
        seen_task_ids = []
        for row in prompts:
            if row["task_id"] not in seen_task_ids:
                seen_task_ids.append(row["task_id"])
            if len(seen_task_ids) >= limit_tasks:
                break
        prompts = [r for r in prompts if r["task_id"] in seen_task_ids]
 
    generations_per_prompt = generations_override if generations_override is not None else config.GENERATIONS_PER_PROMPT
 
    total_jobs = len(prompts) * len(config.MODELS) * generations_per_prompt
    done = 0
 
    for prompt_row in prompts:
        task_id = prompt_row["task_id"]
        prompt_type = prompt_row["prompt_type"].lower()
        prompt_text = prompt_row["prompt_text"]
 
        for model in config.MODELS:
            for gen_index in range(1, generations_per_prompt + 1):
                program_id = f"{task_id}_{model}_{prompt_type}_{gen_index}"
                done += 1
 
                if program_id in completed and not retry_failures:
                    print(f"[{done}/{total_jobs}] skip (already done): {program_id}")
                    continue
 
                print(f"[{done}/{total_jobs}] generating: {program_id}")
 
                program_dir = config.GENERATED_DIR / program_id
                program_dir.mkdir(parents=True, exist_ok=True)
 
                try:
                    raw_response = MODEL_CALLERS[model](prompt_text)
                    code = extract_code(raw_response)
 
                    (program_dir / "app.py").write_text(code, encoding="utf-8")
                    (program_dir / "meta.json").write_text(
                        json.dumps(
                            {
                                "program_id": program_id,
                                "task_id": task_id,
                                "model": model,
                                "prompt_type": prompt_row["prompt_type"],
                                "generation_index": gen_index,
                                "prompt_text": prompt_text,
                                "raw_response": raw_response,
                            },
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
 
                    append_log(
                        config.GENERATION_LOG,
                        {"program_id": program_id, "status": "success", "timestamp": time.time()},
                    )
 
                except Exception as exc:  # noqa: BLE001 — log and keep going
                    print(f"    FAILED: {program_id} ({exc})", file=sys.stderr)
                    append_log(
                        config.GENERATION_LOG,
                        {"program_id": program_id, "status": f"error: {exc}", "timestamp": time.time()},
                    )
 
                # Be polite to rate limits between calls.
                time.sleep(1)
 
    print(f"\nDone. {done} jobs processed. See {config.GENERATION_LOG} for the full log.")
 

if __name__ == "__main__":
    import argparse
 
    parser = argparse.ArgumentParser(description="Generate LLM code samples from prompts.csv")
    parser.add_argument(
        "--retry-failures",
        action="store_true",
        help="Re-attempt program_ids that previously failed or were skipped.",
    )
    parser.add_argument(
        "--limit-tasks",
        type=int,
        default=None,
        help="Only use the first N tasks from prompts.csv (all 3 prompt styles kept). "
             "For smoke-testing, e.g. --limit-tasks 1",
    )
    parser.add_argument(
        "--generations",
        type=int,
        default=None,
        help="Override GENERATIONS_PER_PROMPT for this run only, without touching config.py. "
             "For smoke-testing, e.g. --generations 1",
    )
    args = parser.parse_args()
    generate_all(
        retry_failures=args.retry_failures,
        limit_tasks=args.limit_tasks,
        generations_override=args.generations,
    )