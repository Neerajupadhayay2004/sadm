import pytest

from sadm.normalizer import normalize_path


@pytest.mark.parametrize("raw", ["/users/4821", "/users/9217", "/users/1234"])
def test_numeric_ids(raw):
    assert normalize_path(raw) == "/users/{id}"


def test_uuid():
    assert normalize_path("/users/550e8400-e29b-41d4-a716-446655440000") == "/users/{id}"
    assert normalize_path("/users/550E8400-E29B-41D4-A716-446655440000/x") == "/users/{id}/x"


def test_static_segments_untouched():
    assert normalize_path("/api/v1/users") == "/api/v1/users"
    assert normalize_path("/users/user42") == "/users/user42"
    assert normalize_path("/v2/health") == "/v2/health"


def test_base_path_and_query_stripped():
    assert normalize_path("/api/v1/users/4821?token=abc", ["/api/v1"]) == "/users/{id}"
    assert normalize_path("/api/v1", ["/api/v1"]) == "/"
    assert normalize_path("/api/v10/users", ["/api/v1"]) == "/api/v10/users"


def test_trailing_slash():
    assert normalize_path("/users/1/") == "/users/{id}"
