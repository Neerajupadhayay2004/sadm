"""Path normalisation: turn dynamic segments into {id} placeholders."""
import re
from urllib.parse import urlsplit

NUMERIC = re.compile(r"^\d+$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def strip_base(path: str, bases: list[str]) -> str:
    """Drop query string and the longest matching server base path (e.g. /api/v1)."""
    path = urlsplit(path).path or "/"
    for base in sorted(bases, key=len, reverse=True):
        if base and (path == base or path.startswith(base + "/")):
            return path[len(base):] or "/"
    return path


def normalize_path(path: str, bases: list[str] | None = None) -> str:
    """/api/v1/users/4821?x=1 -> /users/{id}. Whole segments only: 'v1' or 'user42' stay as-is."""
    path = strip_base(path, bases or [])
    segs = ["{id}" if NUMERIC.match(s) or UUID.match(s) else s for s in path.split("/")]
    out = "/".join(segs).rstrip("/")
    return out or "/"
