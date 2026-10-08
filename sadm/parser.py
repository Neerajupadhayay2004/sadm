"""Loaders for the OpenAPI 3.x spec (YAML/JSON) and JSON-lines access logs."""
import json
from pathlib import Path
from urllib.parse import urlsplit

import yaml

METHODS = {"get", "put", "post", "delete", "patch", "head", "options"}


class SpecError(ValueError):
    pass


def load_spec(path: str) -> tuple[dict[tuple[str, str], dict], list[str]]:
    """Return ({(METHOD, path_template): {"deprecated": bool, "auth": bool}}, [server base paths])."""
    try:
        text = Path(path).read_text(encoding="utf-8")
        doc = json.loads(text) if path.lower().endswith(".json") else yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise SpecError(f"cannot read spec {path}: {exc}") from exc
    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith("3."):
        raise SpecError("not an OpenAPI 3.x document (missing 'openapi: 3.x')")
    bases = []
    for srv in doc.get("servers") or []:
        base = urlsplit(str(srv.get("url", ""))).path.rstrip("/")
        if base and base not in bases:
            bases.append(base)
    global_auth = bool(doc.get("security"))
    ops = {}
    for tpl, item in (doc.get("paths") or {}).items():
        for method, op in (item or {}).items():
            if method.lower() in METHODS:
                op = op or {}
                ops[(method.upper(), tpl.rstrip("/") or "/")] = {
                    "deprecated": bool(op.get("deprecated", False)),
                    # operation-level `security` overrides the global one; [] means "no auth"
                    "auth": bool(op["security"]) if "security" in op else global_auth}
    return ops, bases


def read_logs(path: str) -> tuple[list[dict], list[str]]:
    """Read JSONL logs. Malformed lines are skipped and reported, never fatal."""
    records, errors = [], []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SpecError(f"cannot read logs {path}: {exc}") from exc
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            if not isinstance(rec, dict):
                raise ValueError("line is not a JSON object")
            records.append({
                "method": str(rec["method"]).upper(),
                "path": str(rec["path"]),
                "status": int(rec["status"]),
                "has_auth": bool(rec.get("has_auth", False)),
            })
        except KeyError as exc:
            errors.append(f"line {n}: missing field {exc}")
        except (ValueError, TypeError) as exc:
            errors.append(f"line {n}: {exc}")
    return records, errors
