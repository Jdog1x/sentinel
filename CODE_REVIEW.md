# Sentinel — Code & Structure Review

**Date:** 2026-06-06
**Scope:** Full pass over the Sentinel codebase for clean formatting, authenticity, and removal of redundancies. Findings below were applied directly to the source (and verified: all modules import, `py_compile` clean, 9/9 unit tests pass, `pyproject.toml` valid, git index healthy).

---

## 1. Repository hygiene (the "authentic" problems)

These are the things that made the repo look machine-generated or unfinished.

| # | Issue | Fix |
|---|-------|-----|
| 1 | **`venv/` was committed** — 10,222 files (~250 MB) tracked in git despite a `.gitignore` entry. No real project commits its virtualenv. | `git rm -r --cached venv` (files kept on disk, removed from tracking). |
| 2 | **`sentinel.db` committed** — local SQLite database in version control. | Untracked via `git rm --cached`. |
| 3 | **`sentinel.egg-info/` committed** — build artifact. | Untracked. |
| 4 | **`fix.py`** — a throwaway debug script at the repo root that deletes pending DB rows. Classic "left in by accident" tell. | Deleted. |
| 5 | **Empty `sentinel/README.md`** — a zero-byte duplicate of the real root README. | Removed. |
| 6 | **No `LICENSE` file** despite an MIT badge and "MIT" section in the README. | Added a proper MIT `LICENSE`. |
| 7 | **`.gitignore` excluded the source code.** The `reports/` rule (meant for generated PDF output) also matched the **source package** `sentinel/sentinel/reports/`, so `pdf_generator.py` was *never tracked*. Anyone cloning the repo got a broken `report` command. | Anchored the rule to `/reports/` so only the output dir is ignored; the reports package is now trackable. |
| 8 | **No root `.gitignore`** (only a nested one). | Added a complete root `.gitignore` (venv, db, env, caches, node, OS files). |

## 2. Bugs

| # | Issue | Fix |
|---|-------|-----|
| 9 | **Missing dependency.** `whois_lookup.py` does `import whois` (the `python-whois` package), but it was absent from `requirements.txt` — a fresh install crashes on the WHOIS step. | Added `python-whois>=0.9.0`. |
| 10 | **Env var name mismatch.** `config.py` read `REPORT_OUTPUT_DIR` while `.env.example` documents `REPORTS_OUTPUT_DIR` — a custom report directory was silently ignored. | Aligned config to `REPORTS_OUTPUT_DIR`. |
| 11 | **`FLASK_PORT` was dead config** — documented in `.env.example` but never read; `serve` hardcoded 5000. | Added `flask_port` to config and wired it into `serve` and `__main__`. |
| 12 | **Dashboard hid most scans.** The React scan list filtered on `findings.length > 0` in three places, so running/pending/no-finding scans never appeared (directly contradicting the "real-time scan monitoring" feature), and the "N total" header was miscounted. | Removed the filter; the table now shows all scans and counts correctly. |
| 13 | **`serve` ignored `FLASK_DEBUG`** (ran `debug=False` unconditionally, unlike `__main__`). | Now uses `config.flask_debug` consistently. |

## 3. Redundancies removed

| # | Issue | Fix |
|---|-------|-----|
| 14 | **Scan serialization duplicated 3×.** `app.py` hand-rebuilt the scan dict in `list_scans`, `create_scan`, and `get_scan` instead of using the existing `Scan.to_dict()`. | Replaced all three with `s.to_dict()` (~50 lines removed). |
| 15 | **Unused local** `findings = list(s.findings)` in `create_report`. | Removed. |
| 16 | **`provider.py` repetition.** `import httpx` in every method plus a no-op import in `__init__`; the analysis prompt string and `json.loads(...)` duplicated across all three providers. | Hoisted the `httpx` import; extracted `_analysis_prompt()` and `_parse_json()` helpers. `_parse_json` also now tolerates stray ```` ```json ```` fences. |
| 17 | **Duplicated risk-color map in `App.jsx`** (same object literal inlined twice). | Extracted a single `RISK_COLORS` constant. |
| 18 | **Duplicated severity lookup** in `cli.py._print_summary` (computed twice per row). | Single `col` variable. |
| 19 | **Phantom dependencies.** `python-nmap`, `requests`, `beautifulsoup4`, `flask-sqlalchemy`, and `Pillow` were declared but never imported (nmap runs via `subprocess`, HTTP via `httpx`, tech detection via regex, ORM via raw SQLAlchemy). | Removed; `requirements.txt` now matches actual imports and is grouped by purpose. |
| 20 | **Dead `REDIS_URL`** in both config and `.env.example` — Redis is never used. | Removed. |
| 21 | **Empty unused `tools/` package.** | Given a docstring describing its intended role (plugin/adapter namespace referenced by the README). |

## 4. Formatting & consistency

| # | Issue | Fix |
|---|-------|-----|
| 22 | **Inconsistent UTF-8 BOM** on 17 source files (but not `cli.py`) — a Windows-editor artifact that looks sloppy and can break tooling. | Stripped the BOM from every file. |
| 23 | **Mixed CRLF/LF line endings** across the tree. | Normalized all source to LF. |
| 24 | `requirements.txt` was a flat unordered list. | Reorganized into labeled groups. |

## 5. Added

- **`tests/test_smoke.py`** — the project declared `pytest` but had zero tests. Added 9 fast, network-free unit tests covering severity mapping, JSON-fence parsing, the provider registry, and the nmap output parser. All pass.
- **`pyproject.toml`** — added `license` and `authors` metadata.

---

## Verification

- `python -m py_compile` — clean across all source.
- All modules import successfully.
- `pytest` — **9 passed**.
- `pyproject.toml` — valid TOML.
- Git index repaired and healthy; tracked files dropped from **10,255 → 33**.

## What's left for you to do

The cleanup is applied to the working tree. The venv/db/egg removals are already staged; the new files (`LICENSE`, root `.gitignore`, `reports/` package, `test_smoke.py`) are untracked. To finalize:

```bash
cd <repo root>
git add -A
git commit -m "chore: clean up structure, fix deps, remove redundancies"
```

(That single commit will record the venv/db/egg removal plus all the fixes above.)

## Optional follow-ups (not changed — flagged for your call)

- `CORS(..., origins: "*")` is wide open — tighten for any non-local deployment.
- `http_probe` uses `verify=False` (TLS verification off). Reasonable for a scanner, but worth a comment so it doesn't read as an oversight.
- The scan detail panel doesn't auto-refresh while a scan runs (only the list polls every 5s).
- LLM `analyze()` trusts the model's JSON shape beyond parsing — consider validating against the schema.
- Confirm the README clone URL (`github.com/Jdog1x/sentinel`) is the intended remote.
