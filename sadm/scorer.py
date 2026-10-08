"""Assignment-aligned risk scoring."""
import re

BASE_POINTS = {"SHADOW": 40, "ZOMBIE": 30, "ORPHAN": 10, "DOCUMENTED": 0, "NOISE": 0}
BASE_REASON = {
    "SHADOW": "Endpoint observed in traffic but absent from OpenAPI specification",
    "ZOMBIE": "Endpoint marked deprecated in spec but still called in traffic",
    "ORPHAN": "Endpoint documented in spec but never observed in traffic",
    "DOCUMENTED": "Endpoint documented in spec and observed in traffic",
    "NOISE": "Unknown endpoint only returned non-application 404/5xx responses (noise)",
}
SENSITIVE = ("admin", "internal", "debug", "backup", "export", "config", "token", "secret")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

POINTS = {"sensitive": 25, "write": 10, "unauth_shadow_2xx": 20}


def severity(score: int) -> str:
    return "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def sensitive_word(path: str) -> str | None:
    tokens = set(re.split(r"[^a-z0-9]+", path.lower()))
    return next((word for word in SENSITIVE if word in tokens), None)


def score(finding: dict) -> tuple[int, list[str]]:
    """Return assignment score (capped at 100) and auditable reasons."""
    classification = finding["classification"]
    total = BASE_POINTS[classification]
    reasons = [BASE_REASON[classification]]

    if classification == "NOISE":
        return 0, reasons

    word = sensitive_word(finding["endpoint"])
    if word:
        total += POINTS["sensitive"]
        reasons.append(f"Sensitive path keyword: {word}")

    if finding["method"] in WRITE_METHODS:
        total += POINTS["write"]
        reasons.append(f"Write method: {finding['method']}")

    if classification == "SHADOW" and finding["unauth_2xx"]:
        total += POINTS["unauth_shadow_2xx"]
        reasons.append("2xx response without authorization")

    if finding.get("auth_gap"):
        reasons.append("Spec requires authentication but traffic included a 2xx response without it (auth gap)")

    return min(total, 100), reasons
