"""
Orchestrator — runs the full pipeline stage by stage.

Each stage reads/writes disk (see config.py), so this is just a
convenience wrapper. You can equally well run each stage script
individually, which is recommended the first time through so you can
inspect intermediate output before moving on.

Usage:
    python run_pipeline.py                 # run every stage
    python run_pipeline.py --from static    # resume from a given stage
"""

import argparse

import dynamic_analysis
import generate_code
import merge_results
import static_analysis

STAGES = ["generate", "static", "dynamic", "merge"]


def main(start_from: str):
    start_index = STAGES.index(start_from)

    if start_index <= STAGES.index("generate"):
        print("=== Stage 1: code generation ===")
        generate_code.generate_all()

    if start_index <= STAGES.index("static"):
        print("=== Stage 2: static analysis ===")
        static_analysis.scan_all()

    if start_index <= STAGES.index("dynamic"):
        print("=== Stage 3: dynamic analysis ===")
        dynamic_analysis.analyze_all()

    if start_index <= STAGES.index("merge"):
        print("=== Stage 4: merge into master dataset ===")
        merge_results.build_master_dataset()

    print("\nPipeline complete. Open analysis.ipynb for statistics and plots.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the full LLM vulnerability study pipeline")
    parser.add_argument("--from", dest="start_from", choices=STAGES, default="generate")
    args = parser.parse_args()
    main(args.start_from)
