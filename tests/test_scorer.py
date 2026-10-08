import json

import pytest

from sadm.cli import build_findings, build_report, main
from sadm.scorer import score, severity


def f(cls, endpoint="/x", method="GET", unauth=False):
    return {"classification": cls, "endpoint": endpoint, "method": method, "unauth_2xx": unauth}


def test_base_points():
    assert score(f("SHADOW"))[0] == 40
    assert score(f("ZOMBIE"))[0] == 30
    assert score(f("ORPHAN"))[0] == 10
    assert score(f("DOCUMENTED"))[0] == 0


def test_sensitive_keyword():
    pts, reasons = score(f("DOCUMENTED", "/users/v1/_debug"))
    assert pts == 25 and "Sensitive path keyword: debug" in reasons
    assert score(f("DOCUMENTED", "/backup/export"))[0] == 25   # counted once
    assert score(f("DOCUMENTED", "/administrators"))[0] == 0    # whole-token match only


@pytest.mark.parametrize("m,pts", [("POST", 10), ("PUT", 10), ("PATCH", 10), ("DELETE", 10), ("GET", 0)])
def test_write_methods(m, pts):
    assert score(f("DOCUMENTED", method=m))[0] == pts


def test_unauth_2xx_shadow_bonus():
    assert score(f("SHADOW", unauth=True))[0] == 60
    assert score(f("SHADOW", unauth=False))[0] == 40
    assert score(f("ZOMBIE", unauth=True))[0] == 30   # bonus is shadow-only


def test_full_example_matches_assignment():
    pts, reasons = score(f("SHADOW", "/admin/debug", "POST", True))
    assert pts == 95 and len(reasons) == 4


def test_cap_at_100():
    # SHADOW 40 + sensitive 25 + write 10 + unauth 20 = 95 (below cap); ZOMBIE can't exceed either,
    # so force the cap through a hypothetical oversized base to prove min() is applied.
    import sadm.scorer as s
    old = s.BASE_POINTS["SHADOW"]
    s.BASE_POINTS["SHADOW"] = 90
    try:
        assert score(f("SHADOW", "/admin", "POST", True))[0] == 100
    finally:
        s.BASE_POINTS["SHADOW"] = old


@pytest.mark.parametrize("n,sev", [(0, "LOW"), (29, "LOW"), (30, "MEDIUM"), (59, "MEDIUM"),
                                    (60, "HIGH"), (100, "HIGH")])
def test_severity(n, sev):
    assert severity(n) == sev


def test_noise_not_scored_even_if_sensitive():
    assert score(f("NOISE", "/admin/debug", "POST", True))[0] == 0


def test_report_sorted_and_summary(tmp_path):
    spec = tmp_path / "s.yaml"
    spec.write_text("openapi: 3.0.0\npaths:\n  /a:\n    get: {deprecated: true}\n  /b:\n    get: {}\n")
    logs = tmp_path / "l.jsonl"
    logs.write_text('{"method":"GET","path":"/a","status":200,"has_auth":true}\n'
                    '{"method":"POST","path":"/admin/debug","status":200,"has_auth":false}\n'
                    '{"method":"GET","path":"/zzz","status":404,"has_auth":false}\n')
    out = tmp_path / "r.json"
    assert main(["--spec", str(spec), "--logs", str(logs), "--output", str(out)]) == 0
    rep = json.loads(out.read_text())
    scores = [x["score"] for x in rep["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert rep["summary"] == {"total": 4, "shadow": 1, "zombie": 1, "orphan": 1, "documented": 0, "noise": 1, "auth_gap": 0}
    assert rep["findings"][0]["endpoint"] == "/admin/debug"


def test_cli_bad_spec_returns_error(tmp_path, capsys):
    logs = tmp_path / "l.jsonl"
    logs.write_text("")
    assert main(["--spec", str(tmp_path / "nope.yaml"), "--logs", str(logs)]) == 2
    assert "error:" in capsys.readouterr().err
