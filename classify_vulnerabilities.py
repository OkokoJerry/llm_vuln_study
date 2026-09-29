"""
Stage 4 — Vulnerability classification.

Maps raw Bandit test IDs and ZAP alert names to the OWASP-style
categories used in the paper (Injection, Broken authentication,
Sensitive data exposure, Security misconfiguration, Cross-site
scripting, ...). Both mappings are intentionally simple lookup tables
so they're easy to audit and extend — this is a place where you should
expect to add entries as you see what your models actually produce.
"""

# ---------------------------------------------------------------------------
# Bandit test_id -> OWASP category
# (see https://bandit.readthedocs.io/en/latest/plugins/index.html for the
#  full list of test IDs; extend this as new ones show up in your reports)
# ---------------------------------------------------------------------------
BANDIT_CATEGORY_MAP = {
    "B608": "Injection",                       # hardcoded SQL expressions
    "B610": "Injection",                       # Django extra() SQL injection
    "B611": "Injection",                       # Django RawSQL
    "B201": "Security misconfiguration",       # flask debug=True
    "B105": "Broken authentication",           # hardcoded password string
    "B106": "Broken authentication",           # hardcoded password funcarg
    "B107": "Broken authentication",           # hardcoded password default
    "B303": "Sensitive data exposure",         # insecure hash function (MD5/SHA1)
    "B304": "Sensitive data exposure",         # insecure cipher
    "B305": "Sensitive data exposure",         # insecure cipher mode
    "B324": "Sensitive data exposure",         # insecure hashlib usage
    "B301": "Security misconfiguration",       # unsafe pickle usage
    "B403": "Security misconfiguration",       # unsafe import (pickle etc.)
    "B506": "Security misconfiguration",       # unsafe YAML load
    "B602": "Security misconfiguration",       # subprocess with shell=True
    "B701": "Cross-site scripting",            # Jinja2 autoescape disabled
}

# ---------------------------------------------------------------------------
# ZAP alert name (substring match) -> OWASP category
# ---------------------------------------------------------------------------
ZAP_CATEGORY_KEYWORDS = [
    ("sql injection", "Injection"),
    ("cross site scripting", "Cross-site scripting"),
    ("xss", "Cross-site scripting"),
    ("authentication", "Broken authentication"),
    ("session", "Broken authentication"),
    ("password", "Sensitive data exposure"),
    ("information disclosure", "Sensitive data exposure"),
    ("sensitive", "Sensitive data exposure"),
    ("header", "Security misconfiguration"),
    ("csp", "Security misconfiguration"),
    ("misconfiguration", "Security misconfiguration"),
]

UNCLASSIFIED = "Other / Unclassified"


def classify_bandit_test(test_id: str) -> str:
    return BANDIT_CATEGORY_MAP.get(test_id, UNCLASSIFIED)


def classify_zap_alert(alert_name: str) -> str:
    name_lower = alert_name.lower()
    for keyword, category in ZAP_CATEGORY_KEYWORDS:
        if keyword in name_lower:
            return category
    return UNCLASSIFIED


def classify_bandit_report(bandit_summary: dict) -> dict:
    """Turn {test_id: count} into {owasp_category: count}."""
    category_counts = {}
    for test_id, count in bandit_summary.get("vulnerability_types", {}).items():
        category = classify_bandit_test(test_id)
        category_counts[category] = category_counts.get(category, 0) + count
    return category_counts


def classify_zap_report(zap_summary: dict) -> dict:
    """Turn {alert_name: count} into {owasp_category: count}."""
    category_counts = {}
    for alert_name, count in zap_summary.get("attack_types", {}).items():
        category = classify_zap_alert(alert_name)
        category_counts[category] = category_counts.get(category, 0) + count
    return category_counts
