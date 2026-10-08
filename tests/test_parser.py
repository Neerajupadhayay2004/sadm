import json

import pytest

from sadm.parser import SpecError, load_spec, read_logs

SPEC = """
openapi: 3.0.3
servers:
  - url: http://localhost:5000/api/v1
paths:
  /users/{id}:
    get: {responses: {"200": {description: OK}}}
  /users/old:
    get: {deprecated: true, responses: {"200": {description: OK}}}
    post: {responses: {"200": {description: OK}}}
"""


def test_load_yaml_spec(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(SPEC)
    ops, bases = load_spec(str(p))
    assert bases == ["/api/v1"]
    assert ops[("GET", "/users/{id}")]["deprecated"] is False
    assert ops[("GET", "/users/old")]["deprecated"] is True
    assert ("POST", "/users/old") in ops


def test_load_json_spec(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"openapi": "3.1.0", "paths": {"/a": {"get": {}}}}))
    ops, bases = load_spec(str(p))
    assert ("GET", "/a") in ops and bases == []


def test_rejects_non_openapi3(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("swagger: '2.0'\npaths: {}\n")
    with pytest.raises(SpecError):
        load_spec(str(p))


def test_read_logs_skips_malformed(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"method":"get","path":"/a","status":200,"has_auth":true}\n'
                 "not json\n"
                 '{"method":"GET","status":200}\n'
                 "\n"
                 '{"method":"POST","path":"/b","status":"x"}\n')
    recs, errs = read_logs(str(p))
    assert recs == [{"method": "GET", "path": "/a", "status": 200, "has_auth": True}]
    assert len(errs) == 3 and errs[0].startswith("line 2")


def test_missing_log_file():
    with pytest.raises(SpecError):
        read_logs("/nonexistent/file.jsonl")

def test_rejects_invalid_log_field_types(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text(
        '{"method":"GET","path":"/a","status":200,"has_auth":"false"}\n'
        '{"method":"GET","path":"/b","status":700,"has_auth":false}\n'
        '{"method":"GET","path":"/c","status":200,"has_auth":false}\n'
    )
    recs, errs = read_logs(str(p))
    assert recs == [{"method": "GET", "path": "/c", "status": 200, "has_auth": False}]
    assert len(errs) == 2
