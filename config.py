"""
Central configuration for the LLM-generated-code vulnerability study.

All stage scripts import paths and constants from here so the folder
layout only has to be defined once.
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Folder layout
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent

PROMPTS_CSV = PROJECT_ROOT / "prompts.csv"

DATA_DIR = PROJECT_ROOT / "data"
GENERATED_DIR = DATA_DIR / "generated"          # one folder per generated program
STATIC_REPORTS_DIR = DATA_DIR / "static_reports"
DYNAMIC_REPORTS_DIR = DATA_DIR / "dynamic_reports"
MASTER_DIR = DATA_DIR / "master"

MASTER_CSV = MASTER_DIR / "master_dataset.csv"
GENERATION_LOG = DATA_DIR / "generation_log.csv"   # tracks progress/resumability

for d in (GENERATED_DIR, STATIC_REPORTS_DIR, DYNAMIC_REPORTS_DIR, MASTER_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Study design constants
# ---------------------------------------------------------------------------
MODELS = ["groq", "gemini"]            # keys used consistently across all scripts
GENERATIONS_PER_PROMPT = 5             # repeats to control for randomness

# ---------------------------------------------------------------------------
# LLM API configuration (read from environment — never hardcode keys)
# ---------------------------------------------------------------------------

# Groq — https://console.groq.com (fast hosted inference; pick any model
# Groq serves, e.g. a Llama or Mixtral variant)
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
GROQ_MODEL_NAME = os.environ.get("GROQ_MODEL_NAME", "llama-3.3-70b-versatile")

# Gemini — https://aistudio.google.com (Google's hosted API)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL_NAME = os.environ.get("GEMINI_MODEL_NAME", "gemini-3.6-flash")

# ---------------------------------------------------------------------------
# Dynamic analysis configuration (Docker-isolated — every generated app AND
# the ZAP scanner itself run as containers; nothing runs natively on the
# host). Both containers are attached to DOCKER_NETWORK so ZAP can reach the
# app via Docker's internal DNS (by container name) regardless of platform.
# This avoids the Linux-only `--network host` mode, which does not exist on
# Docker Desktop for macOS/Windows.
# ---------------------------------------------------------------------------
DOCKER_IMAGE_PREFIX = "llm-vuln-study"     # prefix for built image tags
DOCKER_NETWORK = "llm-vuln-study-net"      # shared user-defined bridge network
DOCKER_BUILD_TIMEOUT = 120                 # seconds — abort a hung `docker build`
DOCKER_RUN_TIMEOUT = 30                    # seconds — abort a hung `docker run -d`

# Host used INSIDE the container by the generated Flask app. Must be
# 0.0.0.0 (not 127.0.0.1) or the app is unreachable from outside its own
# container even with a port mapping in place. The container itself is
# still only reachable via the Docker network / the single mapped host
# port, so this does not expose the app publicly.
APP_BIND_HOST = "0.0.0.0"
APP_INTERNAL_PORT = 5000               # fixed port — safe since programs run
                                        # one at a time, never concurrently
APP_STARTUP_TIMEOUT = 30               # seconds to wait for an app to boot

# ZAP is run via the official `owasp/zap2docker-stable` image, attached to
# DOCKER_NETWORK, targeting the app container by its Docker DNS name (the
# container_name passed to `docker run`) rather than by host port — this is
# what makes the scan work identically on Linux, macOS, and Windows.
ZAP_TARGET_TEMPLATE = "http://{container_name}:" + str(APP_INTERNAL_PORT)
ZAP_SPIDER_TIMEOUT = 120
ZAP_PASSIVE_SCAN_TIMEOUT = 120
ZAP_TIMEOUT_SECONDS = ZAP_SPIDER_TIMEOUT + ZAP_PASSIVE_SCAN_TIMEOUT + 30  # + buffer

# ---------------------------------------------------------------------------
# Static analysis configuration
# ---------------------------------------------------------------------------
BANDIT_SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH"]