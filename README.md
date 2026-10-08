# SADM – Shadow API Discovery Module

A small, **passive** Python CLI (~250 lines of core code, one dependency: PyYAML) that compares an
**OpenAPI 3.x spec** with **JSON-lines gateway logs** to find APIs the organisation doesn't know about.
It never sends traffic; it only reads two files.

## Shadow / Zombie / Orphan

| Type | Meaning | Example |
|---|---|---|
| **SHADOW** | Serves traffic but is in no spec | debug route, forgotten internal tool |
| **ZOMBIE** | Marked `deprecated` but still called | `/v1/` still alive next to `/v2/` |
| **ORPHAN** | In the spec, never called | extra attack surface, no business value |
| **DOCUMENTED** | In the spec, called, not deprecated | healthy |
| **NOISE** | Unknown path that **only ever returned 404** | scanner probes (`/.env`, `/wp-login.php`) |

## Workflow

```
VAmPI (127.0.0.1 only) <- nginx gateway -> logs/sadm_access.jsonl --+
                                                                    +--> sadm --> console table + report.json
examples/vampi-openapi.yaml (edited spec) --------------------------+
```
Ports: vulnerable gateway on **127.0.0.1:18080**, secure gateway on **127.0.0.1:18081**
(chosen to avoid clashes with common :8080 dev servers).

`parser.py` (spec + logs) → `normalizer.py` (`/users/4821` → `/users/{id}`, strips base path/query) →
`classifier.py` (match & classify) → `scorer.py` (risk points + reasons) → `cli.py` (table + JSON).

## Install & run

Requires Python 3.11+.

```bash
pip install -r requirements.txt
python -m sadm --spec examples/vampi-openapi.yaml --logs examples/access.jsonl --output reports/findings.json
pytest                      # 51 tests
```

Options: `--spec` (.yaml/.yml/.json), `--logs` (JSONL), `--output` (default `report.json`),
`--baseline other_report.json` (diff this scan against another report, e.g. secure vs vulnerable mode).
Exit code `2` on unreadable spec/logs; malformed log lines are skipped and listed as warnings on stderr.

## Test environment (VAmPI, local only)

Needs Docker. VAmPI has **no published port**; only the nginx gateway is exposed, bound to `127.0.0.1:18080` (vulnerable) and `127.0.0.1:18081` (secure).

```bash
mkdir -p logs/vulnerable logs/secure
docker compose up -d --build                         # VAmPI vulnerable (:18080) + secure (:18081), each behind nginx
python scripts/generate_traffic.py http://127.0.0.1:18080   # refuses non-local targets, waits for gateway ready
python scripts/generate_traffic.py http://127.0.0.1:18081
python -m sadm --spec examples/vampi-openapi.yaml --logs logs/vulnerable/sadm_access.jsonl --output reports/findings.json
python -m sadm --spec examples/vampi-openapi.yaml --logs logs/secure/sadm_access.jsonl \
       --output reports/findings.secure.json --baseline reports/findings.json
docker compose down                                  # shut it down when finished
```

The gateway logs exactly `{"method","path","status","has_auth"}`. `path` excludes the query string and
`has_auth` is only a boolean – the Authorization value, bodies and passwords are never logged.

`examples/vampi-openapi.yaml` is generated from VAmPI's original spec (`examples/vampi-openapi.original.yaml`) by
`scripts/make_edited_spec.py`: it removes `/users/v1/_debug` and `/createdb` (→ SHADOW), deprecates `GET /users/v1`
(→ ZOMBIE) and leaves `PUT …/password` and `DELETE /users/v1/{username}` documented but never called (→ ORPHAN).
`examples/access.jsonl` (vulnerable mode) and `examples/access.secure.jsonl` (secure mode) are real captures from
running VAmPI behind nginx with the traffic script (25 requests each).

## Classification logic

1. Strip query string and the server base path (`servers[].url`, e.g. `/api/v1`), replace whole numeric / UUID
   segments with `{id}`.
2. Match `(METHOD, path)` against spec templates (`{param}` matches any segment; static routes beat templates).
   Parameter segments starting with `_` do **not** match, so `/users/v1/_debug` is not mistaken for a username
   under `/users/v1/{username}`.
3. Not in spec → `NOISE` if every status was 404, else `SHADOW`. In spec → `ZOMBIE` if deprecated, else `DOCUMENTED`.
   In spec, never seen → `ORPHAN`.

## Auth gap (stretch goal)

If the spec says an operation needs authentication (`security` on the operation, or global `security`; an
operation-level `security: []` means public) **and** traffic shows a 2xx with `has_auth=false`, the finding gets
`"auth_gap": true`, an extra reason, and shows `AUTH-GAP` in the console. It is a flag only – it adds **no points**, so
the assignment's scoring stays exact.

## Vulnerable vs secure mode (stretch goal)

`--baseline` prints every endpoint whose classification, score or observed status codes differ between two reports.

## Risk scoring (added up, capped at 100)

| Rule | Points |
|---|---|
| SHADOW / ZOMBIE / ORPHAN | +40 / +30 / +10 |
| Sensitive word in path (admin, internal, debug, backup, export, config, token, secret) – counted once, whole word | +25 |
| Write method (POST, PUT, PATCH, DELETE) | +10 |
| SHADOW that returned 2xx with `has_auth=false` | +20 |

Severity: **HIGH** ≥ 60, **MEDIUM** 30–59, **LOW** < 30. NOISE is always 0. Every point appears as a line in the
finding's `reasons`. Constants live at the top of `sadm/scorer.py`.

## Example output

```
Endpoint                          Method  Type        Score  Severity  Flags
--------------------------------------------------------------------------------
/users/v1/_debug                  GET     SHADOW      85     HIGH
/createdb                         GET     SHADOW      60     HIGH
/users/v1                         GET     ZOMBIE      30     MEDIUM
/users/v1/{username}              DELETE  ORPHAN      20     LOW
/users/v1/{username}/password     PUT     ORPHAN      20     LOW
...
total=21  shadow=2  zombie=1  orphan=2  documented=9  noise=7  auth_gap=0
```

JSON report: `{"summary": {...}, "findings": [{"endpoint","method","classification","score","severity","reasons","requests","statuses"}]}`
sorted by score (desc, then endpoint/method for deterministic output).

## Security notes

- SADM is read-only/passive. Never expose VAmPI beyond localhost; it is deliberately vulnerable.
- No credentials in the repo: the traffic script creates a throw-away user with a random password at runtime.
- Logs/reports contain no query strings, tokens, passwords or bodies.

## Limitations

Method+path matching only (no parameter type or server-host checks); one spec at a time; only whole numeric/UUID
segments are generalised (slugs/hashes are not); `_`-prefix rule is a heuristic; SADM sees only method/path/status/auth, so
behaviour inside responses (e.g. leaked fields, mass assignment) is invisible to it.

## 3D dashboard

Open `dashboard/index.html` in a browser (needs internet once for three.js from cdnjs). It embeds the sample report;
use **Load report.json** to view your own. Each bar is one endpoint (height = score, colour = type). Type in the search
box (e.g. `debug`, `post`, `zombie`) to filter bars and the list; click a bar or row for reasons. Drag to rotate.
`dashboard/template.html` + the report JSON regenerate it.
