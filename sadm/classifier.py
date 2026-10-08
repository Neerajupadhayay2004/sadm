"""Compare spec operations with observed traffic and classify each endpoint."""
from sadm.normalizer import normalize_path

SHADOW, ZOMBIE, ORPHAN, DOCUMENTED, NOISE = "SHADOW", "ZOMBIE", "ORPHAN", "DOCUMENTED", "NOISE"

# Status codes that carry NOISE semantics: unknown-path endpoint did not produce an
# application-level answer (404 = not found, 502/503/504 = gateway cannot reach upstream).
# These mean "nothing answered", not "the endpoint exists and serves traffic".
_NOISE_STATUSES = frozenset({404, 502, 503, 504})


def _seg_match(tpl: str, seg: str) -> bool:
    if tpl.startswith("{") and tpl.endswith("}"):
        # A real parameter value is not a '_private'-style name: '_debug' is a route, not a username.
        return not seg.startswith("_")
    return tpl == seg


def match_spec(method: str, path: str, spec_ops: dict) -> tuple[str, str] | None:
    """Find the spec operation for a normalised traffic path. Static routes beat templates."""
    segs = path.split("/")
    best = None
    for (m, tpl) in spec_ops:
        t = tpl.split("/")
        if m != method or len(t) != len(segs) or not all(_seg_match(a, b) for a, b in zip(t, segs)):
            continue
        static = sum(1 for s in t if not s.startswith("{"))
        if best is None or static > best[0]:
            best = (static, (m, tpl))
    return best[1] if best else None


def classify(spec_ops: dict, records: list[dict], bases: list[str]) -> list[dict]:
    """Return one entry per endpoint: key, classification and observed traffic facts."""
    seen: dict[tuple[str, str], dict] = {}
    for r in records:
        norm = normalize_path(r["path"], bases)
        key = match_spec(r["method"], norm, spec_ops) or (r["method"], norm)
        e = seen.setdefault(key, {"statuses": set(), "count": 0, "unauth_2xx": False})
        e["statuses"].add(r["status"])
        e["count"] += 1
        e["unauth_2xx"] |= 200 <= r["status"] < 300 and not r["has_auth"]

    out = []
    for key, e in seen.items():
        if key in spec_ops:
            cls = ZOMBIE if spec_ops[key]["deprecated"] else DOCUMENTED
        else:
            cls = NOISE if (e["statuses"] and e["statuses"].issubset(_NOISE_STATUSES)) else SHADOW
        gap = key in spec_ops and spec_ops[key].get("auth", False) and e["unauth_2xx"]
        out.append({"method": key[0], "endpoint": key[1], "classification": cls, "auth_gap": gap, **e})
    for key in spec_ops.keys() - seen.keys():
        out.append({"method": key[0], "endpoint": key[1], "classification": ORPHAN,
                    "auth_gap": False, "statuses": set(), "count": 0, "unauth_2xx": False})
    return out
