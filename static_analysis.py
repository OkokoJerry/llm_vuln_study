"""
Stage 2 — Static analysis.

Runs Bandit against every generated program folder and saves the raw
JSON report to data/static_reports/<program_id>.json.

SonarQube is optional and treated as a second, independent pass — see
run_sonarqube() below. Bandit alone is enough to get the pipeline
working end-to-end; add SonarQube once the core flow is validated.

Usage:
    python static_analysis.py                 # run Bandit on everything not yet scanned
    python static_analysis.py --tool sonarqube # also run SonarQube
    python static_analysis.py --force          # re-scan everything
"""

import json
import subprocess
import sys
from pathlib import Path

import config


def run_bandit(program_dir: Path) -> dict:
    """
    Run Bandit on a single program folder and return the parsed JSON report.
    Bandit exits non-zero when it finds issues, which is expected —
    only a genuine crash (missing executable, bad JSON) should raise.
    """
    result = subprocess.run(
        ["bandit", "-r", str(program_dir), "-f", "json"],
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        raise RuntimeError(f"Bandit produced no output for {program_dir}: {result.stderr}")

    return json.loads(result.stdout)


def run_sonarqube(program_dir: Path, project_key: str) -> None:
    """
    Trigger a SonarQube scan for a single program. Requires a running
    SonarQube server and sonar-scanner on PATH, plus a sonar-project.properties
    file per project (written here on the fly).

    SonarQube results are pulled separately via its web API after scanning
    (see fetch_sonarqube_results, left as a TODO since it depends on your
    server URL/auth token).
    """
    props_path = program_dir / "sonar-project.properties"
    props_path.write_text(
        f"sonar.projectKey={project_key}\n"
        f"sonar.sources=.\n"
        f"sonar.host.url=http://localhost:9000\n",
        encoding="utf-8",
    )

    subprocess.run(["sonar-scanner"], cwd=str(program_dir), check=True)

    # TODO: fetch results via SonarQube web API, e.g.:
    #   GET http://localhost:9000/api/issues/search?componentKeys=<project_key>
    # and save them alongside the Bandit report.


def summarize_bandit(report: dict) -> dict:
    """Reduce a full Bandit report to the metrics the study design calls for."""
    results = report.get("results", [])
    severity_counts = {level: 0 for level in config.BANDIT_SEVERITY_LEVELS}
    vuln_types = {}

    for issue in results:
        sev = issue.get("issue_severity", "UNDEFINED")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        test_id = issue.get("test_id", "UNKNOWN")
        vuln_types[test_id] = vuln_types.get(test_id, 0) + 1

    return {
        "vulnerability_count": len(results),
        "severity_counts": severity_counts,
        "vulnerability_types": vuln_types,
    }


def scan_all(force: bool = False, tool: str = "bandit"):
    program_dirs = sorted(p for p in config.GENERATED_DIR.iterdir() if p.is_dir())

    if not program_dirs:
        print(f"No generated programs found in {config.GENERATED_DIR}. Run generate_code.py first.")
        return

    for i, program_dir in enumerate(program_dirs, start=1):
        program_id = program_dir.name
        report_path = config.STATIC_REPORTS_DIR / f"{program_id}.json"

        if report_path.exists() and not force:
            print(f"[{i}/{len(program_dirs)}] skip (already scanned): {program_id}")
            continue

        print(f"[{i}/{len(program_dirs)}] scanning: {program_id}")

        try:
            raw_report = run_bandit(program_dir)
            summary = summarize_bandit(raw_report)

            report_path.write_text(
                json.dumps({"program_id": program_id, "raw": raw_report, "summary": summary}, indent=2),
                encoding="utf-8",
            )

            if tool == "sonarqube":
                run_sonarqube(program_dir, project_key=program_id)

        except Exception as exc:  # noqa: BLE001 — log and keep going
            print(f"    FAILED: {program_id} ({exc})", file=sys.stderr)
            report_path.write_text(
                json.dumps({"program_id": program_id, "error": str(exc)}, indent=2),
                encoding="utf-8",
            )

    print(f"\nDone. Reports written to {config.STATIC_REPORTS_DIR}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run static analysis over generated programs")
    parser.add_argument("--tool", choices=["bandit", "sonarqube"], default="bandit")
    parser.add_argument("--force", action="store_true", help="Re-scan programs that already have a report")
    args = parser.parse_args()
    scan_all(force=args.force, tool=args.tool)