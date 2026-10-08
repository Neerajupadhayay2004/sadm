"""Generate safe, repeatable traffic against the local SADM VAmPI gateway only."""
import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

DEFAULT_BASE = "http://127.0.0.1:18080"
LOCAL_HOSTS = {"127.0.0.1", "localhost"}


def validate_target(base: str) -> None:
    parsed = urlsplit(base)
    if parsed.scheme != "http" or parsed.hostname not in LOCAL_HOSTS:
        raise SystemExit("refusing to send traffic: target must be local HTTP")


def wait_for_ready(base: str, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    last = "not reachable"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/", timeout=3) as response:
                if response.status not in {502, 503, 504}:
                    return
                last = str(response.status)
        except urllib.error.HTTPError as exc:
            if exc.code not in {502, 503, 504}:
                return
            last = str(exc.code)
        except (OSError, urllib.error.URLError) as exc:
            last = type(exc).__name__
        time.sleep(1)
    raise SystemExit(f"gateway was not ready within {timeout}s (last={last})")


def call(base: str, method: str, path: str, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            try:
                return response.status, json.loads(raw or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return response.status, {}
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE
    validate_target(base)
    wait_for_ready(base)

    username = "sadm" + secrets.token_hex(3)
    password = secrets.token_urlsafe(12)

    call(base, "GET", "/createdb")
    call(base, "GET", "/")
    call(base, "POST", "/users/v1/register", {
        "username": username, "password": password, "email": f"{username}@example.test"
    })
    _, login = call(base, "POST", "/users/v1/login", {
        "username": username, "password": password
    })
    token = login.get("auth_token")

    call(base, "GET", "/me", token=token)
    call(base, "GET", "/users/v1")
    call(base, "GET", "/users/v1/_debug")
    call(base, "GET", f"/users/v1/{username}")
    call(base, "PUT", f"/users/v1/{username}/email", {"email": f"{username}@example.org"}, token=token)
    call(base, "GET", "/books/v1")
    call(base, "POST", "/books/v1", {"book_title": "sadm-" + secrets.token_hex(2), "secret": "x"}, token=token)

    # Auth-required endpoints probed without a token.
    call(base, "GET", "/me")
    call(base, "PUT", f"/users/v1/{username}/email", {"email": "x@example.test"})
    call(base, "POST", "/books/v1", {"book_title": "sadm-anon", "secret": "x"})

    # Deliberate 404-only probes: these must become NOISE.
    for path in ("/does-not-exist", "/.env", "/wp-login.php", "/phpmyadmin", "/admin"):
        call(base, "GET", path)
    call(base, "POST", "/admin/debug")

    # Numeric and UUID normalization cases.
    for item in ("4821", "9217", "1234", "550e8400-e29b-41d4-a716-446655440000"):
        call(base, "GET", f"/users/{item}")

    print(f"traffic generated through {base}")


if __name__ == "__main__":
    main()
