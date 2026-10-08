"""OpenAPI 3.x and JSONL access-log loaders."""
import json
from pathlib import Path
from urllib.parse import urlsplit

import yaml

METHODS = {"get", "put", "post", "delete", "patch", "head", "options"}


class SpecError(ValueError):
    """Raised when an input file cannot be loaded or validated."""


def _server_bases(doc: dict) -> list[str]:
    bases = []
    for server in doc.get("servers") or []:
        if not isinstance(server, dict):
            continue
        base = urlsplit(str(server.get("url", ""))).path.rstrip("/")
        if base and base not in bases:
            bases.append(base)
    return bases


def load_spec(path: str) -> tuple[dict[tuple[str, str], dict], list[str]]:
    """Load OpenAPI 3.x operations and server base paths."""
    try:
        source = Path(path)
        raw = source.read_text(encoding="utf-8")
        doc = json.loads(raw) if source.suffix.lower() == ".json" else yaml.safe_load(raw)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise SpecError(f"cannot read spec {path}: {exc}") from exc

    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith("3."):
        raise SpecError("not an OpenAPI 3.x document (missing openapi: 3.x)")

    global_auth = bool(doc.get("security"))
    operations = {}
    for template, path_item in (doc.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in METHODS:
                continue
            operation = operation or {}
            operations[(method.upper(), template.rstrip("/") or "/")] = {
                "deprecated": bool(operation.get("deprecated", False)),
                "auth": bool(operation["security"]) if "security" in operation else global_auth,
            }
    return operations, _server_bases(doc)


def read_logs(path: str) -> tuple[list[dict], list[str]]:
    """Read JSON-lines records; malformed lines become warnings, not crashes."""
    records, errors = [], []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SpecError(f"cannot read logs {path}: {exc}") from exc

    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("line is not a JSON object")
            method = item["method"]
            path_value = item["path"]
            status = item["status"]
            has_auth = item.get("has_auth", False)
            if not isinstance(method, str) or not method.strip():
                raise ValueError("method must be a non-empty string")
            if not isinstance(path_value, str) or not path_value:
                raise ValueError("path must be a non-empty string")
            if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                raise ValueError("status must be an integer from 100 to 599")
            if not isinstance(has_auth, bool):
                raise ValueError("has_auth must be boolean")
            records.append({
                "method": method.upper(),
                "path": path_value,
                "status": status,
                "has_auth": has_auth,
            })
        except KeyError as exc:
            errors.append(f"line {number}: missing field {exc}")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"line {number}: {exc}")
    return records, errors
