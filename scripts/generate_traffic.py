"""Send test traffic through the LOCAL gateway only (default http://127.0.0.1:18080).

A throw-away user with a random password is created at runtime; nothing secret is stored or printed.
"""
import json
import secrets
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18080"
if not BASE.startswith(("http://127.0.0.1", "http://localhost")):
    sys.exit("refusing to send traffic to a non-local target")


def wait_for_ready(timeout_s: float = 60.0, interval_s: float = 1.0) -> None:
    """Wait for the gateway to return an application-level response (not 502/503/504)."""
    deadline = time.time() + timeout_s
    last_status = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(BASE + "/", method="GET",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status not in (502, 503, 504):
                    print(f"[ready] gateway {BASE} reached (status={resp.status})", file=sys.stderr)
                    return
                last_status = resp.status
        except urllib.error.HTTPError as exc:
            if exc.code not in (502, 503, 504):
                print(f"[ready] gateway {BASE} reached (status={exc.code})", file=sys.stderr)
                return
            last_status = exc.code
        except (urllib.error.URLError, OSError) as exc:
            last_status = f"err:{type(exc).__name__}"
        time.sleep(interval_s)
    sys.exit(f"gateway {BASE} never became ready within {timeout_s:g}s (last status/code: {last_status})")


def call(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            try:
                parsed = json.loads(raw or b"{}")
            except Exception:
                # Non-JSON response (e.g. nginx 502 HTML, or a foreign server on the port).
                parsed = {}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        return exc.code, {}


user, pwd = "sadm" + secrets.token_hex(3), secrets.token_urlsafe(12)
wait_for_ready()
call("GET", "/createdb")                                              # undocumented -> SHADOW
call("GET", "/")                                                      # documented
call("POST", "/users/v1/register", {"username": user, "password": pwd, "email": f"{user}@example.test"})
_, login = call("POST", "/users/v1/login", {"username": user, "password": pwd})
tok = login.get("auth_token")
call("GET", "/me", token=tok)
call("GET", "/users/v1")                                              # deprecated in edited spec -> ZOMBIE
call("GET", "/users/v1/_debug")                                       # undocumented edge case -> SHADOW
call("GET", f"/users/v1/{user}")
call("PUT", f"/users/v1/{user}/email", {"email": f"{user}@example.org"}, token=tok)
call("GET", "/books/v1")
call("POST", "/books/v1", {"book_title": "sadm-" + secrets.token_hex(2), "secret": "x"}, token=tok)
call("GET", "/books/v1/does-not-matter")
call("GET", "/me")                                                    # spec needs login -> auth-gap probe
call("PUT", f"/users/v1/{user}/email", {"email": "x@example.test"})   # spec needs login -> auth-gap probe
call("POST", "/books/v1", {"book_title": "sadm-anon", "secret": "x"})  # spec needs login -> auth-gap probe
# NOT called on purpose: PUT /users/v1/{username}/password, DELETE /users/v1/{username} -> ORPHAN
for p in ("/does-not-exist", "/.env", "/wp-login.php", "/phpmyadmin", "/admin"):   # scanner noise
    call("GET", p)
call("POST", "/admin/debug", {})                                      # 404 only -> NOISE, not SHADOW
for i in (4821, 9217, 1234):                                          # numeric IDs -> /users/{id}
    call("GET", f"/users/{i}")
call("GET", "/users/550e8400-e29b-41d4-a716-446655440000")            # UUID -> /users/{id}
print("traffic sent")
