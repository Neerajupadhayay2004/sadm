from sadm.classifier import classify, match_spec

SPEC = {
    ("GET", "/users/{id}"): {"deprecated": False},
    ("GET", "/users/old"): {"deprecated": True},
    ("GET", "/orders/{id}"): {"deprecated": False},
    ("GET", "/users/v1/{username}"): {"deprecated": False},
}
BASES = ["/api/v1"]


def rec(method, path, status=200, auth=True):
    return {"method": method, "path": path, "status": status, "has_auth": auth}


def run(*records):
    return {(f["method"], f["endpoint"]): f["classification"] for f in classify(SPEC, list(records), BASES)}


def test_documented_with_base_path_and_ids():
    res = run(rec("GET", "/api/v1/users/4821"), rec("GET", "/users/9217"))
    assert res[("GET", "/users/{id}")] == "DOCUMENTED"


def test_shadow():
    assert run(rec("POST", "/admin/debug"))[("POST", "/admin/debug")] == "SHADOW"


def test_zombie():
    assert run(rec("GET", "/users/old"))[("GET", "/users/old")] == "ZOMBIE"


def test_orphan():
    assert run(rec("GET", "/users/1"))[("GET", "/orders/{id}")] == "ORPHAN"


def test_noise_only_404():
    assert run(rec("GET", "/wp-login.php", 404))[("GET", "/wp-login.php")] == "NOISE"


def test_noise_only_502():
    # Gateway cannot reach upstream — same operational semantics as 404 for NOISE.
    assert run(rec("GET", "/wp-login.php", 502))[("GET", "/wp-login.php")] == "NOISE"


def test_noise_only_503_or_504():
    assert run(rec("GET", "/.env", 503))[("GET", "/.env")] == "NOISE"
    assert run(rec("GET", "/phpmyadmin", 504))[("GET", "/phpmyadmin")] == "NOISE"


def test_noise_mixed_404_502_503_504():
    res = run(
        rec("GET", "/probe", 404),
        rec("GET", "/probe", 502),
        rec("GET", "/probe", 503),
        rec("GET", "/probe", 504),
    )
    assert res[("GET", "/probe")] == "NOISE"


def test_mixed_502_and_200_is_shadow():
    # Real endpoint answering sometimes with 2xx → not noise, it's SHADOW.
    res = run(rec("GET", "/hidden", 502), rec("GET", "/hidden", 200))
    assert res[("GET", "/hidden")] == "SHADOW"


def test_mixed_502_and_401_is_shadow():
    # 401 is application-level; the endpoint actually exists.
    res = run(rec("GET", "/secret", 502), rec("GET", "/secret", 401))
    assert res[("GET", "/secret")] == "SHADOW"


def test_mixed_404_and_200_is_shadow():
    res = run(rec("GET", "/hidden", 404), rec("GET", "/hidden", 200))
    assert res[("GET", "/hidden")] == "SHADOW"


def test_static_route_beats_template():
    assert match_spec("GET", "/users/old", SPEC) == ("GET", "/users/old")


def test_underscore_debug_edge_case_is_not_a_username():
    assert match_spec("GET", "/users/v1/alice", SPEC) == ("GET", "/users/v1/{username}")
    assert match_spec("GET", "/users/v1/_debug", SPEC) is None
    assert run(rec("GET", "/users/v1/_debug"))[("GET", "/users/v1/_debug")] == "SHADOW"


def test_method_matters():
    assert run(rec("DELETE", "/users/1"))[("DELETE", "/users/{id}")] == "SHADOW"
