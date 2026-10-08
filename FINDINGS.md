# SADM Findings – VAmPI (local test)

**Target:** VAmPI, vulnerable mode, local Docker/localhost only, behind an nginx JSON-logging gateway.
**Inputs:** `examples/vampi-openapi.yaml` (edited copy) + `examples/access.jsonl` (25 real requests; secure-mode capture: `examples/access.secure.jsonl`).
**Result:** 21 endpoints – 2 SHADOW, 1 ZOMBIE, 2 ORPHAN, 9 DOCUMENTED, 7 NOISE (`reports/findings.json`).

> Important context: the spec was **edited by us** to diverge from the live API. VAmPI's *original* spec documents
> `/users/v1/_debug` and `/createdb`, so these shadow/zombie/orphan results are **test artifacts of the exercise**,
> not production discoveries. Whether the *underlying behaviour* is a real weakness is assessed separately below.

## Findings

| Endpoint | Method | Class | Score | Sev. |
|---|---|---|---|---|
| `/users/v1/_debug` | GET | SHADOW | 85 | HIGH |
| `/createdb` | GET | SHADOW | 60 | HIGH |
| `/users/v1` | GET | ZOMBIE | 30 | MEDIUM |
| `/users/v1/{username}` | DELETE | ORPHAN | 20 | LOW |
| `/users/v1/{username}/password` | PUT | ORPHAN | 20 | LOW |

**Shadow – `GET /users/v1/_debug` (85 = 40 shadow + 25 "debug" + 20 unauthenticated 2xx).** Served HTTP 200 with no
Authorization header and is absent from the edited spec. *Real issue (in this lab app):* a direct check showed the
response lists every user with fields including `password` and `admin` – an intentional VAmPI vulnerability
(sensitive data exposure, no authentication). The *shadow* label is an artifact of our spec edit; the *exposure* is real
for VAmPI. Remediation: remove the route from non-dev builds, or require admin auth and never return credentials.

**Shadow – `GET /createdb` (60 = 40 + 20).** Unauthenticated 200, not in the spec. It (re)initialises the database,
so a state-changing action sits behind GET with no auth. Real design weakness in VAmPI (also intentional); the
scorer under-rates it because it is a GET with no sensitive keyword – a known limit of the fixed rules.
Remediation: disable outside setup, require auth, use POST.

**Zombie – `GET /users/v1` (30).** Deprecated in our edit and still called (200, no auth). *Test artifact* – VAmPI
does not really deprecate it. In a real estate this pattern means a retired route is still live; it returns usernames
and emails without login. Remediation: set a sunset date, return 410/redirect, require auth meanwhile.

**Orphan – `DELETE /users/v1/{username}` and `PUT /users/v1/{username}/password` (20 each = 10 + 10 write).**
Documented but our traffic never called them – *expected artifact*; they are real VAmPI functions we simply skipped.
In production, an orphan write endpoint deserves review: confirm it is unused, then remove or restrict it.

**Noise (7, score 0).** `/.env`, `/wp-login.php`, `/phpmyadmin`, `/admin`, `/does-not-exist`, `POST /admin/debug`,
and `/users/{id}` (4 requests: 3 numeric IDs + 1 UUID, all normalised to one entry, all 404). They only ever returned 404,
so they are scanner-style noise, not shadow APIs – even `POST /admin/debug`, whose name would otherwise score high.
Re-check if any of these ever returns non-404.

**Documented (9).** Normal traffic matched the spec. Four write endpoints score 10 (LOW) purely from the write-method
rule (`register`, `login`, `POST /books/v1`, `PUT …/email`) – a rule effect, not a defect. `GET /books/v1/does-not-matter`
returned 401 (not 404), so it correctly stays DOCUMENTED.

## Edge case: `/users/v1/_debug`

**Caught: yes.** `/users/v1/{username}` is in the spec, so a naive template matcher would treat `_debug` as a username and
call it DOCUMENTED (a miss). SADM refuses to match a `{param}` to a value starting with `_`, so the route is classified
SHADOW, and the keyword rule (`_` is a word separator) adds +25 for "debug". Trade-off: a real username beginning with
`_` would be misclassified as shadow – acceptable for a security tool, since it errs towards a review.

## Stretch goals

**Auth gap.** The spec marks `GET /me`, `PUT /users/v1/{username}/email` and `POST /books/v1` as requiring login. We called
each without a token (and once with). The unauthenticated calls returned **401**, so SADM reports `auth_gap=0`: no
endpoint that should need a login worked without one in either mode. (`GET /users/v1`, `/createdb` and `/users/v1/_debug`
*do* work without login, but the spec does not claim they need it, so they are reported by other rules, not as auth gaps.)

**Vulnerable vs secure mode.** Running the identical traffic against VAmPI with `vulnerable=0` and scanning with
`--baseline` gave **no differences**: same endpoints, classifications, scores and status codes, including `/users/v1/_debug`
still answering 200. This is a limit of gateway-metadata analysis, not proof that the modes behave alike: VAmPI's
differences (e.g. which fields are returned, injection, mass assignment) are inside request/response bodies, which SADM
deliberately never logs. Treat SADM as an inventory tool; use a DAST scanner or code review for those flaws.
