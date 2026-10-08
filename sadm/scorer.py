"""Transparent risk scoring. Every point added is recorded as a human-readable reason."""
import re

BASE_POINTS = {"SHADOW": 40, "ZOMBIE": 30, "ORPHAN": 10, "DOCUMENTED": 0, "NOISE": 0}
BASE_REASON = {
    "SHADOW": "Endpoint observed in traffic but absent from OpenAPI specification",
    "ZOMBIE": "Endpoint marked deprecated in spec but still called in traffic",
    "ORPHAN": "Endpoint documented in spec but never observed in traffic",
    "DOCUMENTED": "Endpoint documented in spec and observed in traffic",
    "NOISE": "Only ever returned HTTP 404 (scanner/probe noise, not scored)",
}
SENSITIVE = ("admin", "internal", "debug", "backup", "export", "config", "token", "secret")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
POINTS = {"sensitive": 25, "write": 10, "unauth_shadow_2xx": 20}


def severity(score: int) -> str:
    return "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def sensitive_word(path: str) -> str | None:
    """First sensitive keyword found as a whole token ('/users/v1/_debug' -> 'debug')."""
    tokens = set(re.split(r"[^a-z0-9]+", path.lower()))
    return next((w for w in SENSITIVE if w in tokens), None)


def score(f: dict) -> tuple[int, list[str]]:
    """Apply the assignment rules to one finding; return (capped score, reasons)."""
    cls = f["classification"]
    total, reasons = BASE_POINTS[cls], [BASE_REASON[cls]]
    if cls == "NOISE":
        return 0, reasons
    word = sensitive_word(f["endpoint"])
    if word:
        total += POINTS["sensitive"]
        reasons.append(f"Sensitive path keyword: {word}")
    if f["method"] in WRITE_METHODS:
        total += POINTS["write"]
        reasons.append(f"Write method: {f['method']}")
    if cls == "SHADOW" and f["unauth_2xx"]:
        total += POINTS["unauth_shadow_2xx"]
        reasons.append("2xx response without authorization")
    if f.get("auth_gap"):  # stretch goal: informational, adds no points
        reasons.append("Spec requires authentication but a 2xx response was served without it (auth gap)")
    return min(total, 100), reasons
