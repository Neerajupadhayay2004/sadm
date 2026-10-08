# Debug Session: docker-gateway-runtime-fail — closed

- session_id: `docker-gateway-runtime-fail`
- project_root: `/home/neeraj/Downloads/sadm`
- evidence_dir: `/tmp/sadm-debug-docker-gateway-runtime-fail`
- env_file: `/tmp/sadm-debug-docker-gateway-runtime-fail/docker-gateway-runtime-fail.env`
- debug_server: started on `http://127.0.0.1:7777`, accepted POST /event probes (200), stopped after post-fix verification
- progress_status: **closed / fixed**

## Symptom recap (from user paste)
1. `docker compose up -d --build` → `sadm-gateway-1` fails: **Bind for 0.0.0.0:8080 failed: port is already allocated**. `gateway-secure-1` on :8081 Started OK.
2. zsh parse errors when pasting comment lines — benign copy-paste UX issue.
3. `python scripts/generate_traffic.py http://127.0.0.1:8080` → `json.JSONDecodeError: Expecting value: line 1 column 1 (char 0)` on `GET /`.
4. Traffic script claimed `traffic sent` on the :8081 invocation; `logs/vulnerable/sadm_access.jsonl` absent.
5. `reports/findings.secure.json` scan → every endpoint status `[502]`; scanner paths elevated from NOISE → SHADOW (`noise=0 shadow=9`).

## Final evidence-gated hypothesis table
| # | Hypothesis | Status | Evidence source | Confirmed-by |
|---|---|---|---|---|
| H1 | Another process holds TCP :8080 | **CONFIRMED** | `ss -tlnp` + `curl -i :8080` + `docker ps` | `0.0.0.0:8080` LISTEN; served **Werkzeug/3.1.8 `Sarva BlackArch Attack Dashboard` HTML 200**; unrelated app. docker ps listed `threatintel-platform-main-nginx-1` in Restarting (that stack's other listeners). |
| H2 | `depends_on` default (start only) ≠ VAmPI app ready → 502 until :5000 listens | **CONFIRMED** | `logs/secure/sadm_access.jsonl` first captured run | 25/25 log lines had `status: 502` (Counter({502: 25})). Second captured run produced valid 200/401/404s — purely a timing race against Flask/VAmPI WSGI startup. |
| H3 | `call()` blindly `json.loads()` on success-path 2xx bodies; 200+HTML crashes script | **CONFIRMED** | User traceback line 24 + curl :8080 | Port 8080 returned `200 OK`, `Content-Type: text/html`, 4014 bytes of HTML dashboard. `json.loads(html)` → exactly the crash in user paste. |
| H4 | NOISE rule requires *exactly {404}* → 502/503/504 only-unknown paths become false-positive SHADOW | **CONFIRMED** | pre-fix run vs `logs/secure/sadm_access.jsonl` + pre-fix `test_noise_only_404` only coverage | Pre-fix 502 scan: `shadow=9 noise=0`; Post-fix 502 scan (same log!): `shadow=0 noise=9`. Backward compat verified via `test_full_example_matches_assignment` + `test_noise_only_404` still pass. |
| H5 | Missing `logs/vulnerable/sadm_access.jsonl` = side-effect of failed gateway container (no nginx ran) | **CONFIRMED** | `ls -la logs/vulnerable` vs `logs/secure` | `logs/vulnerable/` directory empty (0 files beyond dir); `logs/secure/` has `sadm_access.jsonl` (1766 bytes) because gateway-secure did start. |

## Fixes applied (minimal scope)
| ID | File | Change | Tests added |
|---|---|---|---|
| F1 | `docker-compose.yml` | Ports 8080/8081 → **18080/18081** on `127.0.0.1`. Added `vampi` / `vampi-secure` healthchecks (wget :5000/). Gateway `depends_on.condition: service_healthy`. | none (infra) |
| F2 | `sadm/classifier.py` | `_NOISE_STATUSES = frozenset({404, 502, 503, 504})`; NOISE predicate = statuses non-empty and subset of NOISE_STATUSES. Mixed 2xx/4xx still SHADOW. | +6: `test_noise_only_502`, `test_noise_only_503_or_504`, `test_noise_mixed_404_502_503_504`, `test_mixed_502_and_200_is_shadow`, `test_mixed_502_and_401_is_shadow` (+ preserved original `test_noise_only_404`) |
| F3 | `scripts/generate_traffic.py` | (a) Default BASE port → **18080**. (b) `wait_for_ready()` polls `/` up to 60s, skips 502/503/504, exits loudly if never ready. (c) `json.loads` wrapped in try/except returning `{}` on malformed body + crash-free. (d) module-level stdlib `import time`. | none (manual smoke + hostile-port test confirmed) |
| F4 | `README.md` | Workflow ports text updated to 18080/18081, traffic script comments updated to reflect ready-wait behaviour. | n/a |

## Verification (post-fix, post-cleanup)
- `pytest`: **51/51 passed in 1.13s** (46 original + 6 new NOISE tests -1 overlap).
- Example `access.jsonl` regression: `total=21 shadow=2 zombie=1 orphan=2 documented=9 noise=7 auth_gap=0`; top findings unchanged (`_debug` SHADOW 85 HIGH, `/createdb` SHADOW 60 HIGH).
- All-502 `secure` log scan: `shadow=0 noise=9` — scanner probes correctly NOISE 0.
- Hostile :8080 call() smoke: status=200, parsed dict empty, **no crash** (was JSONDecodeError pre-fix).

## Instrumentation (all removed)
Debug Server on `:7777` was used for transport probes only. Both source files had their `#region debug-point …` blocks stripped before final close; no util files were introduced; classifier.py `classify()` and traffic script `call()`/`wait_for_ready()` remain free of debug emitters and print.

## Root-cause summary
A **port conflict** (:8080 already bound to another Flask dashboard) prevented `sadm-gateway-1` from binding (H1/H5). The remaining gateway fired before VAmPI was truly ready (H2), logging only 502s; the traffic script also blindly `json.loads`'ed the 200 HTML body from the foreign server on :8080 (H3) and crashed. The NOISE rule, originally specified for "only 404s", was too strict during gateway misconfiguration — unknown paths returning 502/503/504 cannot be interpreted as "the endpoint exists" and were falsely elevated to SHADOW (H4). Port remap + healthchecks + ready-wait + 5xx-NOISE extension together eliminate all 5 reported symptoms without changing the "real SHADOW" semantics (any path that ever answers with 2xx/4xx remains SHADOW if undocumented).
