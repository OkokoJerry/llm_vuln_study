"""
Stage 3 — Dynamic analysis.

For each generated program:
    1. Write a minimal Dockerfile into its folder (if not already present).
    2. Build an isolated image and run it on a shared Docker network,
       mapping a host port to config.APP_INTERNAL_PORT (for host-side
       readiness polling) AND making it reachable by container name on
       config.DOCKER_NETWORK (for the ZAP scan itself).
    3. Run the OWASP ZAP baseline scan — also as a container on the same
       network — against the app container's Docker DNS name.
    4. Save the ZAP JSON report to data/dynamic_reports/<program_id>.json.
    5. Tear the container down, whether or not the scan succeeded.

Targeting the app by container name on a shared user-defined bridge
network (rather than `--network host`) is what makes this work
identically on Linux, macOS, and Windows — `--network host` is a
Linux-only Docker feature and silently fails to reach anything on
Docker Desktop for Mac/Windows.

This stage is the slowest and most failure-prone part of the pipeline
(a generated app may not even boot), so every step is wrapped so one
bad program can't take down the whole run, and progress is resumable
via existing report files.

Requirements on the host running this script:
    - Docker installed and the current user able to run it
    - Internet access to pull `python:3.11-slim` and
      `owasp/zap2docker-stable` the first time this runs

Usage:
    python dynamic_analysis.py
    python dynamic_analysis.py --force
"""

import json
import shutil
import socket
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

import config

# Common dependencies generated login/upload/API apps tend to need. Only
# used when the generated program folder doesn't already ship its own
# requirements.txt — installing a fixed superset up front is far cheaper
# than discovering missing packages one failed container build at a time.
FALLBACK_REQUIREMENTS = [
    "flask",
    "werkzeug",
    "flask-login",
    "flask-wtf",
    "bcrypt",
    "requests",
]

DEFAULT_DOCKERFILE = """\
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE {port}
ENV APP_BIND_HOST={bind_host}
CMD ["python", "app.py"]
"""


def find_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def ensure_dockerfile(program_dir: Path):
    dockerfile_path = program_dir / "Dockerfile"
    if not dockerfile_path.exists():
        dockerfile_path.write_text(
            DEFAULT_DOCKERFILE.format(
                port=config.APP_INTERNAL_PORT, bind_host=config.APP_BIND_HOST
            ),
            encoding="utf-8",
        )

    requirements_path = program_dir / "requirements.txt"
    if not requirements_path.exists():
        requirements_path.write_text(
            "\n".join(FALLBACK_REQUIREMENTS) + "\n", encoding="utf-8"
        )


def ensure_docker_network():
    """Create the shared bridge network used by app + ZAP containers, if needed."""
    result = subprocess.run(
        ["docker", "network", "inspect", config.DOCKER_NETWORK],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        subprocess.run(
            ["docker", "network", "create", config.DOCKER_NETWORK],
            check=True, capture_output=True, text=True,
        )


def build_image(program_dir: Path, image_tag: str):
    subprocess.run(
        ["docker", "build", "-t", image_tag, str(program_dir)],
        check=True,
        capture_output=True,
        text=True,
        timeout=config.DOCKER_BUILD_TIMEOUT,
    )


def run_container(image_tag: str, container_name: str, host_port: int) -> None:
    subprocess.run(
        [
            "docker", "run", "-d",
            "--name", container_name,
            "--network", config.DOCKER_NETWORK,
            "-p", f"{host_port}:{config.APP_INTERNAL_PORT}",
            image_tag,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=config.DOCKER_RUN_TIMEOUT,
    )


def wait_for_app(host_port: int, timeout: int = 30) -> bool:
    """Poll the container's mapped host port until it accepts connections or times out."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with closing(socket.create_connection(("localhost", host_port), timeout=2)):
                return True
        except OSError:
            time.sleep(1)
    return False


def run_zap_baseline(container_name: str, report_path: Path):
    """
    Run the ZAP baseline scan via its official Docker image, attached to the
    same user-defined network as the app container, targeting the app by
    its Docker DNS name (container_name). This works the same way on
    Linux, macOS, and Windows, unlike `--network host`.
    """
    target = config.ZAP_TARGET_TEMPLATE.format(container_name=container_name)

    subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", config.DOCKER_NETWORK,
            "-v", f"{report_path.parent}:/zap/wrk/:rw",
            "owasp/zap2docker-stable",
            "zap-baseline.py",
            "-t", target,
            "-J", report_path.name,   # JSON report, written into the mounted volume
        ],
        check=False,   # zap-baseline.py exits non-zero when it finds alerts — expected
        capture_output=True,
        text=True,
        timeout=config.ZAP_TIMEOUT_SECONDS,
    )


def cleanup_container(container_name: str):
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True)


def summarize_zap(report: dict) -> dict:
    """Reduce a ZAP JSON report to the metrics the study design calls for."""
    alerts = []
    for site in report.get("site", []):
        alerts.extend(site.get("alerts", []))

    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    attack_types = {}

    for alert in alerts:
        risk = alert.get("riskdesc", "").split(" ")[0]
        if risk in risk_counts:
            risk_counts[risk] += 1
        name = alert.get("name", "Unknown")
        attack_types[name] = attack_types.get(name, 0) + 1

    return {
        "active_vulnerability_count": len(alerts),
        "risk_counts": risk_counts,
        "attack_types": attack_types,
    }


def check_docker_available():
    """
    Fail fast with a clear message if `docker` isn't on PATH or the
    daemon isn't reachable, instead of letting the first real Docker
    call inside the per-program loop raise a confusing FileNotFoundError
    (e.g. Windows' `[WinError 2] The system cannot find the file
    specified`) or hang.
    """
    if shutil.which("docker") is None:
        print(
            "ERROR: 'docker' was not found on PATH.\n"
            "  - Confirm Docker Desktop is installed.\n"
            "  - If you just installed it, close and reopen your terminal "
            "(PATH is only refreshed for new terminal sessions).\n"
            "  - Check with: where docker   (Windows)  /  which docker   (Mac/Linux)",
            file=sys.stderr,
        )
        sys.exit(1)

    result = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if result.returncode != 0:
        print(
            "ERROR: 'docker' is on PATH but the Docker daemon isn't reachable.\n"
            "  - Make sure Docker Desktop is actually running (check for the "
            "whale icon in your system tray/menu bar), not just installed.\n"
            f"  - docker info said: {result.stderr.strip()}",
            file=sys.stderr,
        )
        sys.exit(1)


def analyze_all(force: bool = False):
    check_docker_available()
    ensure_docker_network()

    program_dirs = sorted(p for p in config.GENERATED_DIR.iterdir() if p.is_dir())

    if not program_dirs:
        print(f"No generated programs found in {config.GENERATED_DIR}. Run generate_code.py first.")
        return

    for i, program_dir in enumerate(program_dirs, start=1):
        program_id = program_dir.name
        report_path = config.DYNAMIC_REPORTS_DIR / f"{program_id}.json"

        if report_path.exists() and not force:
            print(f"[{i}/{len(program_dirs)}] skip (already scanned): {program_id}")
            continue

        print(f"[{i}/{len(program_dirs)}] dynamic scan: {program_id}")

        image_tag = f"{config.DOCKER_IMAGE_PREFIX}-{program_id}".lower()
        container_name = f"{image_tag}-run"
        host_port = find_free_port()
        raw_report_tmp = report_path.parent / f"{program_id}_raw.json"

        try:
            ensure_dockerfile(program_dir)
            build_image(program_dir, image_tag)
            run_container(image_tag, container_name, host_port)

            if not wait_for_app(host_port, timeout=config.APP_STARTUP_TIMEOUT):
                raise RuntimeError("app did not become reachable within timeout")

            run_zap_baseline(container_name, raw_report_tmp)

            raw_report = json.loads(raw_report_tmp.read_text(encoding="utf-8"))
            summary = summarize_zap(raw_report)

            report_path.write_text(
                json.dumps({"program_id": program_id, "raw": raw_report, "summary": summary}, indent=2),
                encoding="utf-8",
            )

        except Exception as exc:  # noqa: BLE001 — log and keep going
            print(f"    FAILED: {program_id} ({exc})", file=sys.stderr)
            report_path.write_text(
                json.dumps({"program_id": program_id, "error": str(exc)}, indent=2),
                encoding="utf-8",
            )

        finally:
            cleanup_container(container_name)
            subprocess.run(["docker", "rmi", "-f", image_tag], capture_output=True, text=True)
            if raw_report_tmp.exists():
                raw_report_tmp.unlink()

    print(f"\nDone. Reports written to {config.DYNAMIC_REPORTS_DIR}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run dynamic (ZAP) analysis over generated programs")
    parser.add_argument("--force", action="store_true", help="Re-scan programs that already have a report")
    args = parser.parse_args()
    analyze_all(force=args.force)