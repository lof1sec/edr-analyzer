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

# Backend tests (run from backend/)
cd backend && python -m pytest -q

# Frontend (run from frontend/)
cd frontend && npm ci && npm run lint && npm run build

# Create a migration after editing backend/app/models.py
cd backend && alembic revision --autogenerate -m "describe change"
```

- Frontend: http://localhost:5173
- Backend / API docs: http://localhost:8000/docs

## Environment & configuration

All settings come from the environment. `.env` is git-ignored; `.env.example`
is the template. Compose builds `DATABASE_URL` from `POSTGRES_*`.

| Variable | Purpose |
| --- | --- |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | DB credentials and name |
| `CORS_ORIGINS` | Comma-separated origin allowlist (never `*`) |
| `MAX_UPLOAD_SIZE_MB` | Upload cap (default `200`; over → HTTP 413) |
| `VITE_API_URL` | Backend base URL used by the frontend |
| `DATABASE_URL` | Full SQLAlchemy URL (only needed outside Compose) |

## Architecture & key files

Data flow: **upload → parse → store (Postgres JSONB) → build graph → render**.

- `backend/app/parsers/vendor.py` — vendor / event-type detection from fields.
- `backend/app/parsers/builder.py` — `GraphBuilder`, node/edge ids, digests.
- `backend/app/parsers/falcon.py` / `defender.py` — per-vendor event mapping.
- `backend/app/routers/datasets.py` — upload (streamed), list, delete.
- `backend/app/routers/graph.py` — graph generation (ordered, per-event vendor).
- `backend/app/database.py` — engine/session; requires `DATABASE_URL`.
- `backend/main.py` — FastAPI app, CORS allowlist, startup migrations.
- `backend/alembic/` — migration environment + revisions.
- `frontend/src/api/client.js` — **single** place for API calls; always use it.
- `frontend/src/components/GraphView.jsx` — the large graph component (be careful).
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

## Testing

- Backend: `backend/tests/` (27 tests). Cover vendor detection, upload parsing,
  builder ids, and parser smoke tests. Add a test when adding an event mapping.
- Frontend: `npm run lint` (oxlint) and `npm run build`. There are three
  tolerated warnings: two `set-state-in-effect` (pre-existing) and one
  `react(refs)` for intentionally reading `initialPositions` in a `useMemo`.
  Do not fail the build over these.
- CI (`.github/workflows/ci.yml`) runs on push/PR to `main` and `v2`.

## Commit style

Conventional-commit prefixes have been used so far (`security:`, `perf:`,
`fix:`, `docs:`, `chore:`). Follow that convention.

## Pitfalls

- `GraphView.jsx` uses `react-cytoscapejs`, which re-runs the layout whenever
  the `layout` prop reference changes — keep it memoised (`useMemo`).
- The upload endpoint is a sync `def` (runs in the threadpool); don't switch it
  back to `async def` while doing blocking DB work.
- `backend/app/database.py` raises at import if `DATABASE_URL` is missing; tests
  set `DATABASE_URL=sqlite://` in `tests/conftest.py`.
- No Python linter/formatter is configured yet (Ruff would be welcome).
