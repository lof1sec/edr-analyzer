# AGENTS.md

Guidance for AI coding agents (and future contributors) working on this
repository. Keep this file accurate as the project evolves.

## What this project is

**EDR Logs Graph Analyzer** — a full-stack app that ingests Microsoft Defender
and CrowdStrike Falcon log exports and renders an interactive graph where
processes are the central actors.

- **Frontend:** React 19, Vite, Tailwind CSS v4, Cytoscape.js (`react-cytoscapejs`)
- **Backend:** Python 3.13, FastAPI, SQLAlchemy, Alembic, Pydantic
- **Database / Infra:** PostgreSQL 15, Docker Compose
- **Quality:** pytest (backend), oxlint (frontend), GitHub Actions

## Quick commands

```bash
# First time
cp .env.example .env

# Run the whole stack (applies DB migrations on startup)
docker-compose up -d --build

# Backend tests. pytest is NOT in the runtime image: install dev deps first.
cd backend && pip install -r requirements-dev.txt && python -m pytest -q

# Frontend (run from frontend/)
cd frontend && npm ci && npm run lint && npm run build

# Create a migration after editing backend/app/models.py
cd backend && alembic revision --autogenerate -m "describe change"
```

- Frontend: http://localhost:5173
- Backend / API docs: http://localhost:8000/docs

### Docker layout (dev, not prod)

Both images run **dev servers over a bind mount**, so code edits are picked up
without rebuilding:

- backend: `uvicorn main:app --reload`, `./backend:/app`
- frontend: `vite --host`, `./frontend:/app` + a `frontend_node_modules` volume

The frontend container serves the **Vite dev server**, never a production build.
If a Windows bind-mount edit does not appear, restart just that service
(`docker compose restart frontend`); the file watcher is unreliable there.

## Environment & configuration

All settings come from the environment. `.env` is git-ignored; `.env.example`
is the template. Compose builds `DATABASE_URL` from `POSTGRES_*`.

| Variable | Purpose |
| --- | --- |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | DB credentials and name; user/password are also the app admin login |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Optional override of the app admin login (default `POSTGRES_USER`/`POSTGRES_PASSWORD`) |
| `CORS_ORIGINS` | Comma-separated origin allowlist (never `*`) |
| `MAX_UPLOAD_SIZE_MB` | Upload cap (default `200`; over → HTTP 413) |
| `VITE_API_URL` | Backend base URL used by the frontend |
| `DATABASE_URL` | Full SQLAlchemy URL (only needed outside Compose) |
| `GRAPH_CACHE_SIZE` | Generated-graph cache entries (default `4`) |
| `GRAPH_CACHE_TTL_SECONDS` | Cached graph lifetime, seconds (default `300`; `0` disables) |
| `SECRET_KEY` | Signs session cookies; unset → ephemeral key (sessions lost on restart) |
| `SESSION_COOKIE_SECURE` | `true` restricts the session cookie to HTTPS (default `false`) |

## Architecture & key files

Data flow: **upload → parse → store (Postgres JSONB) → build graph → render**.

- `backend/app/parsers/vendor.py` — vendor / event-type detection from fields.
- `backend/app/parsers/builder.py` — `GraphBuilder`, node/edge ids, digests.
- `backend/app/parsers/falcon.py` / `defender.py` — per-vendor event mapping.
- `backend/app/routers/auth.py` — first-run admin setup, login/logout, and the
  `require_user` guard (httpOnly session cookie).
- `backend/app/security.py` — Argon2id password hashing.
- `backend/app/bootstrap.py` — provisions the admin from the environment
  (Postgres credentials) on startup.
- `backend/app/routers/datasets.py` — upload (streamed), list, delete.
- `backend/app/routers/graph.py` — graph generation (ordered, per-event vendor),
  lazy raw-log and search endpoints, cache-backed payloads.
- `backend/app/routers/graph_cache.py` — bounded process-local LRU + TTL of
  generated graphs; invalidated on dataset delete/upload.
- `backend/ruff.toml` — backend lint config; run `ruff check .` (see Testing).
- `backend/app/database.py` — engine/session; requires `DATABASE_URL`.
- `backend/main.py` — FastAPI app, session middleware, CORS allowlist, startup
  migrations.
- `backend/alembic/` — migration environment + revisions.
- `frontend/src/api/client.js` — **single** place for API calls; always use it.
- `frontend/src/components/GraphView.jsx` — the large graph component (be careful).
- `frontend/src/components/AuthPage.jsx` — login / first-run setup gate.
- `frontend/src/hooks/useDebouncedValue.js` — debounce helper.

## Conventions & invariants (do not break)

1. **Vendor detection is by fields, not file extension.** Defender uses
   `ActionType`, Falcon uses `#event_simpleName`. Reuse
   `app/parsers/vendor.py` rather than hardcoding markers.
2. **Graph ids must be stable and unique.**
   - Node ids: `string_hash()` → sha1 truncated to 16 hex chars. **Never use
     Python's built-in `hash()`** (salted per process).
   - Edge ids: the `GraphBuilder._edge_seq` counter (`edge_1`, `edge_2`, …).
3. **Uploads are streamed**, size-capped (`MAX_UPLOAD_SIZE_MB`), and inserted in
   batches (`INSERT_BATCH_SIZE`). Keep the memory-bounded pattern.
4. **CORS is an explicit allowlist**; never revert to `*`.
5. **Secrets never go in the repo.** `.env` is ignored; `.dockerignore` keeps
   caches and env files out of build contexts.
6. **Schema changes go through Alembic.** `main.py` runs `alembic upgrade head`
   on startup; the initial migration is intentionally idempotent.
7. **All backend API calls go through `frontend/src/api/client.js`.**
8. **Raw events and the search index stay out of element data.**
   `build_cytoscape_elements()` returns lightweight `elements` plus `raw_logs`
   and `search_index` side maps. The browser fetches evidence via
   `/api/graph/{id}/element-logs?element_id=…` and resolves the global search via
   `/api/graph/{id}/search?q=…`. Keep it that way: shipping raw logs inside
   `elements` re-introduces the duplication and per-keystroke JSON serialisation
   this design removed. Raw logs are capped at `MAX_RAW_LOGS_PER_ELEMENT` while
   `raw_logs_total` preserves the true count. `search_index` is built from
   `_search_text`, which every event contributes to (bounded by
   `MAX_SEARCH_TEXT_CHARS`), so search is not limited by the raw-log cap.
   `unmapped_events` is returned as `{event_type: count}`, not a flat list.
9. **Data routes require authentication.** The `datasets` and `graph` routers
   carry `dependencies=[Depends(require_user)]`; `/` and `/api/auth/*` stay
   public. The session is an httpOnly, signed cookie (`SECRET_KEY`) holding only
   the user id — never keep a token in JS-readable storage. Passwords are
   Argon2id-hashed via `app/security.py`. The admin is provisioned from
   `POSTGRES_USER`/`POSTGRES_PASSWORD` (override `ADMIN_*`) at startup, so the DB
   credentials also log into the app; `/api/auth/setup` is only a fallback when no
   environment credentials are set. Existing accounts are never overwritten, so a
   password changed in-app survives restarts.

## Testing

- Backend: `backend/tests/` (63 tests): pure parser/builder tests plus HTTP tests
  (`test_api.py`, `test_auth.py`, `test_bootstrap.py`) against an in-memory sqlite
  DB. Shared fixtures live in `tests/conftest.py`: `client` (fresh DB +
  `TestClient`), `db_session` and `admin_client` (creates the admin and logs in).
  Data routes are authenticated, so new endpoint tests should request
  `admin_client`. `TestClient` is used *without* its context manager so the
  PostgreSQL startup migrations are skipped; `models.py` uses
  `JSON().with_variant(JSONB, "postgresql")` so the schema also builds on sqlite.
  `conftest.py` sets `SECRET_KEY` so session cookies are valid in tests. Add a
  test when adding an event mapping, endpoint, or touching the payload.
- Backend lint: `cd backend && ruff check .` (config in `backend/ruff.toml`).
  Run `ruff check --fix .` before committing. FastAPI's `Depends`/`File`/`Query`
  in defaults are intentionally exempt via `B008`.
- Frontend: `npm run lint` (oxlint) and `npm run build`. A few `react` warnings
  are tolerated (a handful of `set-state-in-effect` for async data loads, plus
  one `react(refs)` for intentionally reading `initialPositions` in a `useMemo`).
  Do not fail the build over these.
- CI (`.github/workflows/ci.yml`) runs on push/PR to `main` and `v2`
  (backend: ruff + pytest; frontend: lint + build).

## Commit style

Conventional-commit prefixes have been used so far (`security:`, `perf:`,
`fix:`, `docs:`, `chore:`). Follow that convention.

## Pitfalls

- `GraphView.jsx` uses `react-cytoscapejs`, which re-runs the layout whenever
  the `layout` prop reference changes — keep it memoised (`useMemo`).
- `react-cytoscapejs` calls the `cy` prop on **every** mount/update. Register
  the graph event listeners inside that callback, guarded by instance identity,
  not in a `useEffect`: the effect version can bind to a destroyed instance
  (e.g. while the loading spinner unmounts Cytoscape) and silently break node
  selection / Node Details. `cy.destroy()` clears the listeners on unmount.
- The upload endpoint is a sync `def` (runs in the threadpool); don't switch it
  back to `async def` while doing blocking DB work.
- `backend/app/database.py` raises at import if `DATABASE_URL` is missing; tests
  set `DATABASE_URL=sqlite://` in `tests/conftest.py`.
- `SECRET_KEY` signs session cookies. If unset, `main.py` generates an ephemeral
  key and warns, so sessions die on every restart — set it in `.env` for stable
  sessions.
- Ruff is configured for **linting only** (`ruff check`), not formatting. There
  is no auto-formatter, so match the surrounding style by hand.
