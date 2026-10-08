"""Stretch goals: auth-gap detection and baseline comparison."""
import json

from sadm.cli import main
from sadm.parser import load_spec

SPEC = """
openapi: 3.0.0
security: []
paths:
  /me:
    get: {security: [{bearerAuth: []}]}
  /open:
    get: {}
  /closed:
    get: {}
"""


def test_spec_auth_flags(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(SPEC)
    ops, _ = load_spec(str(p))
    assert ops[("GET", "/me")]["auth"] is True
    assert ops[("GET", "/open")]["auth"] is False


def test_global_security_applies_unless_overridden(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("openapi: 3.0.0\nsecurity: [{k: []}]\npaths:\n  /a: {get: {}}\n  /b: {get: {security: []}}\n")
    ops, _ = load_spec(str(p))
    assert ops[("GET", "/a")]["auth"] is True and ops[("GET", "/b")]["auth"] is False


def _scan(tmp_path, lines, name="r.json", extra=()):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)
    logs = tmp_path / (name + ".jsonl")
    logs.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    out = tmp_path / name
    assert main(["--spec", str(spec), "--logs", str(logs), "--output", str(out), *extra]) == 0
    return json.loads(out.read_text())


def rec(path, status=200, auth=False):
    return {"method": "GET", "path": path, "status": status, "has_auth": auth}


def test_auth_gap_flagged_without_changing_score(tmp_path):
    rep = _scan(tmp_path, [rec("/me"), rec("/open")])
    me = next(f for f in rep["findings"] if f["endpoint"] == "/me")
    assert me["auth_gap"] is True and me["score"] == 0
    assert any("auth gap" in r for r in me["reasons"])
    assert rep["summary"]["auth_gap"] == 1


def test_no_gap_when_401_or_authenticated(tmp_path):
    assert _scan(tmp_path, [rec("/me", 401)])["summary"]["auth_gap"] == 0
    assert _scan(tmp_path, [rec("/me", 200, True)])["summary"]["auth_gap"] == 0


def test_baseline_comparison(tmp_path, capsys):
    _scan(tmp_path, [rec("/me", 401), rec("/open")], name="base.json")
    capsys.readouterr()
    _scan(tmp_path, [rec("/me", 200), rec("/open"), rec("/debug")], name="cur.json",
          extra=("--baseline", str(tmp_path / "base.json")))
    out = capsys.readouterr().out
    assert "/debug" in out and "baseline: absent" in out and "difference(s)" in out


def test_bad_baseline_returns_error(tmp_path, capsys):
    spec = tmp_path / "s.yaml"
    spec.write_text(SPEC)
    logs = tmp_path / "l.jsonl"
    logs.write_text("")
    assert main(["--spec", str(spec), "--logs", str(logs), "--output", str(tmp_path / "o.json"),
                 "--baseline", str(tmp_path / "missing.json")]) == 2
