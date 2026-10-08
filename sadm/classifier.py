"""Endpoint matching and passive classification."""
from sadm.normalizer import normalize_path

SHADOW, ZOMBIE, ORPHAN, DOCUMENTED, NOISE = (
    "SHADOW", "ZOMBIE", "ORPHAN", "DOCUMENTED", "NOISE"
)
# A 5xx gateway response does not prove that an unknown route exists.
NOISE_STATUSES = frozenset({404, 502, 503, 504})


def _segment_matches(template: str, actual: str) -> bool:
    if template.startswith("{") and template.endswith("}"):
        # Avoid treating VAmPI's /_debug-style route as a username parameter.
        return not actual.startswith("_")
    return template == actual


def match_spec(method: str, path: str, spec_ops: dict) -> tuple[str, str] | None:
    """Match a normalized traffic path to an OpenAPI operation."""
    parts = path.split("/")
    candidates = []
    for key in spec_ops:
        spec_method, template = key
        if spec_method != method:
            continue
        template_parts = template.split("/")
        if len(template_parts) != len(parts):
            continue
        if all(_segment_matches(a, b) for a, b in zip(template_parts, parts)):
            static_count = sum(not part.startswith("{") for part in template_parts)
            candidates.append((static_count, key))
    return max(candidates)[1] if candidates else None


def classify(spec_ops: dict, records: list[dict], bases: list[str]) -> list[dict]:
    """Classify observed and unobserved OpenAPI operations."""
    seen = {}
    for record in records:
        normalized = normalize_path(record["path"], bases)
        key = match_spec(record["method"], normalized, spec_ops) or (
            record["method"], normalized
        )
        entry = seen.setdefault(
            key, {"statuses": set(), "count": 0, "unauth_2xx": False}
        )
        entry["statuses"].add(record["status"])
        entry["count"] += 1
        entry["unauth_2xx"] |= 200 <= record["status"] < 300 and not record["has_auth"]

    findings = []
    for key, entry in seen.items():
        if key in spec_ops:
            classification = ZOMBIE if spec_ops[key]["deprecated"] else DOCUMENTED
            auth_gap = spec_ops[key].get("auth", False) and entry["unauth_2xx"]
        else:
            classification = (
                NOISE
                if entry["statuses"] and entry["statuses"].issubset(NOISE_STATUSES)
                else SHADOW
            )
            auth_gap = False
        findings.append({
            "method": key[0],
            "endpoint": key[1],
            "classification": classification,
            "auth_gap": auth_gap,
            **entry,
        })

    for key in spec_ops.keys() - seen.keys():
        findings.append({
            "method": key[0],
            "endpoint": key[1],
            "classification": ORPHAN,
            "auth_gap": False,
            "statuses": set(),
            "count": 0,
            "unauth_2xx": False,
        })
    return findings
