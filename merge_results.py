"""
Stage 5 — Merge static + dynamic results into one master dataset.

Reads every program's generation metadata (meta.json), static report,
and dynamic report, and writes one row per program to
data/master/master_dataset.csv — the single source of truth that the
statistics notebook reads from.

Columns:
    program_id, task_id, task_type, model, prompt_type, generation_index,
    static_vuln_count, static_high, static_medium, static_low,
    dynamic_vuln_count, dynamic_high, dynamic_medium, dynamic_low,
    total_vuln_count, owasp_categories (JSON string of category->count)

Usage:
    python merge_results.py
"""

import csv
import json

import config
from classify_vulnerabilities import classify_bandit_report, classify_zap_report


def load_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def merge_category_counts(a: dict, b: dict) -> dict:
    merged = dict(a)
    for k, v in b.items():
        merged[k] = merged.get(k, 0) + v
    return merged


def build_master_dataset():
    program_dirs = sorted(p for p in config.GENERATED_DIR.iterdir() if p.is_dir())
    rows = []

    for program_dir in program_dirs:
        program_id = program_dir.name

        meta_path = program_dir / "meta.json"
        meta = load_json(meta_path)
        if meta is None:
            print(f"skip {program_id}: no meta.json (generation may have failed)")
            continue

        static_report = load_json(config.STATIC_REPORTS_DIR / f"{program_id}.json")
        dynamic_report = load_json(config.DYNAMIC_REPORTS_DIR / f"{program_id}.json")

        static_summary = (static_report or {}).get("summary", {})
        dynamic_summary = (dynamic_report or {}).get("summary", {})

        static_severity = static_summary.get("severity_counts", {})
        dynamic_risk = dynamic_summary.get("risk_counts", {})

        static_categories = classify_bandit_report(static_summary) if static_summary else {}
        dynamic_categories = classify_zap_report(dynamic_summary) if dynamic_summary else {}
        combined_categories = merge_category_counts(static_categories, dynamic_categories)

        static_count = static_summary.get("vulnerability_count", 0)
        dynamic_count = dynamic_summary.get("active_vulnerability_count", 0)

        rows.append({
            "program_id": program_id,
            "task_id": meta["task_id"],
            "model": meta["model"],
            "prompt_type": meta["prompt_type"],
            "generation_index": meta["generation_index"],
            "static_vuln_count": static_count,
            "static_high": static_severity.get("HIGH", 0),
            "static_medium": static_severity.get("MEDIUM", 0),
            "static_low": static_severity.get("LOW", 0),
            "dynamic_vuln_count": dynamic_count,
            "dynamic_high": dynamic_risk.get("High", 0),
            "dynamic_medium": dynamic_risk.get("Medium", 0),
            "dynamic_low": dynamic_risk.get("Low", 0),
            "total_vuln_count": static_count + dynamic_count,
            "owasp_categories": json.dumps(combined_categories),
            "has_static_report": static_report is not None,
            "has_dynamic_report": dynamic_report is not None,
        })

    fieldnames = [
        "program_id", "task_id", "model", "prompt_type", "generation_index",
        "static_vuln_count", "static_high", "static_medium", "static_low",
        "dynamic_vuln_count", "dynamic_high", "dynamic_medium", "dynamic_low",
        "total_vuln_count", "owasp_categories",
        "has_static_report", "has_dynamic_report",
    ]

    with open(config.MASTER_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {config.MASTER_CSV}")

    missing_static = sum(1 for r in rows if not r["has_static_report"])
    missing_dynamic = sum(1 for r in rows if not r["has_dynamic_report"])
    if missing_static or missing_dynamic:
        print(
            f"NOTE: {missing_static} programs missing a static report, "
            f"{missing_dynamic} missing a dynamic report. "
            f"These count as 0 vulns in that column — check before drawing conclusions."
        )


if __name__ == "__main__":
    build_master_dataset()
