# EDR Logs Graph Analyzer

A full-stack web application for analysing Endpoint Detection and Response (EDR)
logs. It ingests Microsoft Defender and CrowdStrike Falcon exports, maps the
relationships between entities, and renders them as an interactive graph where
**processes are the central actors** and files, network connections, registry
keys, loaded modules, command lines and alerts appear as related artifacts.

## Features

- **Authentication:** the admin login is provisioned from the PostgreSQL
  credentials (`POSTGRES_USER`/`POSTGRES_PASSWORD`) at startup — the same
  user/password opens the app and connects to the database. Sessions are httpOnly
  cookies; upload and graph endpoints require a session.
- **Flexible ingestion:** Upload `.csv`, `.json` or `.jsonl` files. Parsing is
  streamed (no full-file buffering) and the upload size is capped with a
  configurable limit. Escaped NUL characters are stripped from JSON event
  strings and keys before PostgreSQL JSONB storage; a key collision caused by
  that cleanup is rejected with HTTP 400 rather than losing a field.
- **Automatic vendor detection:** Defender vs CrowdStrike Falcon is detected
  from the event fields (`ActionType` / `#event_simpleName`), not the file
  extension, so a Falcon export delivered as CSV (or vice versa) is still mapped.
- **Interactive graph:** Powered by Cytoscape.js. Process trees, file writes,
  registry changes, network/DNS activity, driver loads and detections are drawn
  as typed nodes and coloured edges.
- **Stable graph identity:** Node ids are derived from deterministic digests and
  edge ids are unique, so the graph is reproducible across restarts and no
  evidence is silently dropped.
- **Dynamic filtering:** Global text search plus per-event-type, per-user and
  per-PID toggles, with an "unmapped events" report.
- **Multiple layouts:** Force-directed, tree and node-centric (concentric).
- **Saved layout:** your node arrangement is persisted per dataset and restored
  when you reopen the graph ("Reset layout" regenerates it).
- **Clustering & lazy loading:** a process that fans out to many exclusively-owned
  artifacts (files, registry, network, command lines…) collapses them into a `+N`
  placeholder that loads on demand. Processes and their `Spawns` edges stay
  visible, so the graph remains connected.
- **Timeline & playback:** a chronological view of the dataset's events with
  play/pause, speed control and a scrubber. In Timeline view the graph remains
  above the list; playback and manual navigation center and highlight each
  event's matching element without changing tabs or rebuilding the layout.
  Paged or clustered elements are loaded on demand, and additional timeline
  pages are fetched automatically during playback.
  The timeline follows the graph's applied time range, search, event-type, user
  and PID filters; unmapped events that produce no graph elements are excluded.
  Visual-only Hide, focus and collapsed clusters do not remove timeline events.
  Event times are normalised at upload
  (`event_time`), so events without a timestamp keep insertion order.
- **Deep inspection:** Click any node or edge to inspect its metadata and the
  raw log events behind it, with copy-to-clipboard.
- **Schema migrations:** Alembic runs automatically on backend startup.
- **Tested & automated:** A pytest suite and GitHub Actions CI (backend tests +
  frontend lint/build).

The graph's initial response respects `MAX_INITIAL_ELEMENTS` even for dense
process graphs; omitted nodes and edges are retrieved in pages. Time-filtered
search uses the same event window as the graph, and saved layouts are only
updated from an unfiltered graph. Uploads commit as a single transaction: failed
imports leave no partial dataset.

## Supported Formats & Vendor Detection

| Vendor | Typical export | Event type field | Mapping |
| --- | --- | --- | --- |
| Microsoft Defender | CSV (also JSON) | `ActionType` | `app/parsers/defender.py` |
| CrowdStrike Falcon | JSON / JSONL | `#event_simpleName` | `app/parsers/falcon.py` |

Vendor detection is **per event**, so a single dataset may contain a mix of both
products. Events that match neither marker are still stored (event type
`Unknown`) and surfaced in the "Unmapped Stats" panel.

## How It Works

1. **Authenticate** — on startup the backend provisions the admin from the
   environment (`POSTGRES_USER`/`POSTGRES_PASSWORD`, or `ADMIN_*` when set), and
   `POST /api/auth/login` starts a signed, httpOnly session cookie that every
   data endpoint requires.
2. **Ingest** — `POST /api/datasets/upload` streams the upload in 1 MiB chunks,
   enforces `MAX_UPLOAD_SIZE_MB` (rejects with HTTP 413), detects UTF-8/latin-1,
   parses CSV/JSONL/JSON-array/single-object input, extracts the event type per
   vendor, and inserts `LogEvent` rows in batches.
3. **Build graph** — `GET /api/graph/{id}` loads the dataset's events in a
   deterministic order and feeds them to `GraphBuilder` plus the per-vendor
   parsers, producing Cytoscape `{ nodes, edges, unmapped_events }`.
   A process hub's exclusively-owned artifact children are collapsed into `+N`
   cluster placeholders and expanded on demand
   (`/api/graph/{id}/clusters/…`); process nodes are never collapsed.
4. **Timeline** — `GET /api/graph/{id}/timeline` returns mapped events matching
   the graph filters, ordered by their normalised `event_time` (paginated and
   filterable). Each entry carries server-side-derived element IDs; a click
   loads and highlights the relevant graph relationship alongside the timeline.
5. **Visualise** — the React frontend renders the graph and applies all
   filtering client-side.

## Tech Stack

- **Frontend:** React 19, Vite, Tailwind CSS v4, Cytoscape.js (`react-cytoscapejs`)
- **Backend:** Python 3.13, FastAPI, SQLAlchemy, Alembic, Pydantic
- **Database / Infra:** PostgreSQL 15, Docker & Docker Compose
- **Quality:** pytest, oxlint, GitHub Actions

---

## 🚀 Quickstart

### Prerequisites

- Docker & Docker Compose

### Configuration

Copy the example environment file and adjust the values:

```bash
cp .env.example .env
```

`.env` is git-ignored and must never be committed. All available settings are
documented in the configuration reference below.

### Run

```bash
docker-compose up -d --build
```

*(On newer Docker versions you may prefer `docker compose up -d --build`.)*

Then open **http://localhost:5173**.

The backend applies all pending database migrations automatically on startup.

### Stop

```bash
docker-compose down
```

Uploaded data persists in the `postgres_data` Docker volume.

---

## ⚙️ Configuration Reference

All settings are read from the environment (via `.env` in Docker Compose).

| Variable | Used by | Default | Description |
| --- | --- | --- | --- |
| `POSTGRES_USER` | db / backend | *(required)* | PostgreSQL user — also the app admin login |
| `POSTGRES_PASSWORD` | db / backend | *(required)* | PostgreSQL password — also the app admin password; set a strong value |
| `POSTGRES_DB` | db / backend | *(required)* | PostgreSQL database name |
| `ADMIN_USERNAME` | backend | `POSTGRES_USER` | Override the app admin login (defaults to the PostgreSQL user) |
| `ADMIN_PASSWORD` | backend | `POSTGRES_PASSWORD` | Override the app admin password (defaults to the PostgreSQL password) |
| `CORS_ORIGINS` | backend | `http://localhost:5173` | Comma-separated allowlist of browser origins. Never use `*` |
| `MAX_UPLOAD_SIZE_MB` | backend | `200` | Maximum accepted upload size; larger files get HTTP 413 |
| `GRAPH_CACHE_SIZE` | backend | `4` | Generated-graph cache entries kept in memory |
| `GRAPH_CACHE_TTL_SECONDS` | backend | `300` | Cached graph lifetime in seconds (`0` disables expiry) |
| `CLUSTER_MIN_CHILDREN` | backend | `50` | Exclusively-owned descendants a hub needs before collapsing into a cluster placeholder (`0` disables) |
| `MAX_INITIAL_ELEMENTS` | backend | `5000` | Maximum nodes plus edges in the initial graph response (`0` disables truncation) |
| `SECRET_KEY` | backend | *(ephemeral)* | Secret used to sign session cookies. Set a strong random value for anything beyond local dev |
| `SESSION_COOKIE_SECURE` | backend | `false` | Set to `true` to restrict the session cookie to HTTPS |
| `VITE_API_URL` | frontend | `http://localhost:8000` | Base URL of the backend API |
| `DATABASE_URL` | backend | built from `POSTGRES_*` | Full SQLAlchemy URL. Only needed when running the backend outside Compose |

### Running the backend outside Docker

```bash
cd backend
pip install -r requirements.txt
export DATABASE_URL="postgresql+psycopg://user:password@localhost:5432/edr_logs"
uvicorn main:app --reload
```

---

## 📖 Usage

1. **Sign in:** use the administrator credentials from your environment — by
   default the same `POSTGRES_USER`/`POSTGRES_PASSWORD` you configured in
   `.env`. The session is an httpOnly cookie; use the sign-out button at the
   bottom of the sidebar to end it.
2. **Upload logs:** use the sidebar to upload a `.csv`, `.json` or `.jsonl`
   export. The backend reports the number of parsed events or the reason for a
   rejection (e.g. file too large).
3. **Analyse:** click a dataset to load its graph. Use the right-hand panel to:
   - search globally (comma-separated terms are OR-ed),
   - toggle event types, users and PIDs,
   - inspect a selected node/edge and its raw logs,
   - review unmapped event types.
4. **Explore:** switch between Force-directed, Tree and Centered layouts, fit the
   graph, and hide elements you don't need (`Unhide All` restores them). Click a
   `+N` cluster to expand it, use **Reveal** to re-show hidden elements within
   one hop, and **Reset layout** to regenerate the arrangement (your layout is
   saved per dataset).

---

## 🔌 API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/auth/status` | Whether first-run setup is needed and if a session is active |
| `POST` | `/api/auth/setup` | Fallback: create the first admin when no environment credentials are set (only while no user exists) |
| `POST` | `/api/auth/login` | Authenticate and start a session |
| `POST` | `/api/auth/logout` | End the session |
| `GET` | `/api/auth/me` | Current user (`401` when unauthenticated) |
| `POST` | `/api/auth/change-password` | Change the signed-in user's password (requires the current one) |
| `POST` | `/api/datasets/upload` | Upload and parse a CSV/JSON/JSONL file. `413` if too large, `400` on invalid input |
| `GET` | `/api/datasets/` | List datasets with their log counts |
| `DELETE` | `/api/datasets/{dataset_id}` | Delete a dataset and all of its events |
| `GET` | `/api/graph/{dataset_id}` | Cytoscape elements and aggregated unmapped-event counts for a dataset |
| `GET` | `/api/graph/{dataset_id}/element-logs?element_id=…` | Raw log events for one node/edge (lazily loaded evidence) |
| `GET` | `/api/graph/{dataset_id}/focus?element_id=…` | Retrieve an element and its connected nodes (including clustered or paged elements) for timeline focus |
| `GET` | `/api/graph/{dataset_id}/search?q=…` | Ids of elements matching the search terms (server-side search) |
| `GET` | `/api/graph/{dataset_id}/clusters/{cluster_id}` | Hidden elements of a collapsed cluster (on-demand expansion) |
| `GET` | `/api/graph/{dataset_id}/neighbors?element_id=…&depth=…` | Subgraph within N hops of an element (1–3) |
| `GET` | `/api/graph/{dataset_id}/timeline?offset=…&limit=…&event_type=…&q=…&from=…&to=…` | Graph-mapped events in chronological order (paginated, compact summaries); also accepts `graph_q` and repeated `hidden_event_type`, `hidden_user`, `hidden_pid` filters |
| `GET` | `/api/graph/{dataset_id}/layout` | Saved node positions for the dataset |
| `PUT` | `/api/graph/{dataset_id}/layout` | Persist node positions for the dataset |
| `GET` | `/` | Liveness/status check |

All `/api/datasets` and `/api/graph` endpoints require an authenticated session
(`401` otherwise); `/` and `/api/auth/*` are public.

Interactive API docs are available at **http://localhost:8000/docs**.

---

## 🛠️ Development

### Backend (tests)

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest -q
```

The suite covers vendor detection, upload parsing (CSV/JSONL/JSON-array/single
object, BOM, latin-1, size/parse limits), the graph builder (stable ids, unique
edge ids, fan-out clustering), saved layouts, on-demand neighbourhoods, the
chronological timeline, Falcon/Defender parser smoke tests, and Hypothesis
property tests for the parsers/upload helpers.

### Database migrations

The schema is managed with **Alembic** and applied automatically when the backend
starts (`alembic upgrade head`). The initial migration is idempotent, so it is
safe on both fresh databases and databases previously created via
`Base.metadata.create_all`.

The timeline search uses a PostgreSQL `pg_trgm` GIN expression index on the
JSONB event text and a composite `(dataset_id, event_time, id)` index. Migration
`0006_timeline_search_indexes` creates them; the database user running migrations
must be permitted to install the trusted `pg_trgm` extension. Index creation on
an existing large dataset may take time and consume temporary disk space. To
measure search performance on a representative PostgreSQL dataset, run:

```sql
EXPLAIN (ANALYZE, BUFFERS)
SELECT id FROM log_events
WHERE dataset_id = 1 AND CAST(data AS text) ILIKE '%example-term%';
```

Compare execution time and buffer reads before/after migration for a term at
least three characters long; short terms often cannot use a trigram index.

Create a new revision after changing `app/models.py`:

```bash
cd backend
alembic revision --autogenerate -m "describe your change"
```

### Frontend

```bash
cd frontend
npm ci
npm run lint
npm run test
npm run build
npm run dev        # dev server on http://localhost:5173
```

### Continuous Integration

`.github/workflows/ci.yml` runs on every push and pull request:

- **backend** — installs requirements and runs `pytest`
- **frontend** — `npm ci`, `npm run lint`, `npm run build`

---

## 📁 Project Structure

```
edr-analyzer/
├── backend/
│   ├── app/
│   │   ├── parsers/          # vendor detection + graph construction
│   │   │   ├── builder.py    # GraphBuilder, stable ids
│   │   │   ├── defender.py   # Microsoft Defender event mapping
│   │   │   ├── events.py     # shared per-vendor actor/target extraction
│   │   │   ├── falcon.py     # CrowdStrike Falcon event mapping
│   │   │   ├── timestamps.py # event-time normalisation (epoch ms)
│   │   │   └── vendor.py     # event type / vendor detection
│   │   ├── routers/
│   │   │   ├── auth.py       # login / logout / first-run setup + auth guard
│   │   │   ├── datasets.py   # upload / list / delete
│   │   │   └── graph.py      # graph generation, clusters, layouts, timeline
│   │   ├── database.py       # engine/session (DATABASE_URL)
│   │   ├── models.py         # Dataset, LogEvent, User, GraphLayout
│   │   ├── security.py       # password hashing (Argon2id)
│   │   ├── bootstrap.py      # provision the admin from the environment
│   │   └── schemas.py        # Pydantic schemas
│   ├── alembic/              # migration environment + revisions
│   ├── tests/                # pytest suite
│   ├── main.py               # FastAPI app + startup migrations
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── api/client.js     # single place for API calls
│   │   ├── components/       # GraphView, TimelineView, Sidebar, AuthPage, styles
│   │   ├── hooks/            # useDebouncedValue
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── Dockerfile
├── .github/workflows/ci.yml
├── .env.example
├── docker-compose.yml
└── README.md
```

---

## 🔒 Security Notes

- Database credentials live in `.env` (git-ignored); no secrets are hardcoded.
- CORS is restricted to an explicit allowlist (`CORS_ORIGINS`).
- Uploads are size-limited and streamed to avoid unbounded memory use.
- Authentication reuses the PostgreSQL credentials as the admin login
  (`POSTGRES_USER`/`POSTGRES_PASSWORD`, override with `ADMIN_*`), delivered
  through an httpOnly, signed session cookie (`SECRET_KEY`). Dataset and graph
  endpoints reject unauthenticated requests with `401`.
- Passwords are hashed with Argon2id; plaintext passwords are never stored.
- The admin account lives in the database volume, not in the repo — two clones
  whose folder name is the same share the same Postgres volume and thus the same
  admin.
# Deployment security notes

The values in `.env.example` are placeholders, not usable production secrets.
Set unique random `POSTGRES_PASSWORD` and `SECRET_KEY` values; never reuse the
database password as the signing key. Set `SESSION_COOKIE_SECURE=true` behind
HTTPS and restrict `CORS_ORIGINS` to your actual frontend origin. Docker Compose
publishes PostgreSQL only on the development host's loopback interface; the
backend connects through the private Compose network. Avoid exposing development
services to untrusted networks.

Uploads accept at most 8 MiB per JSON event, 64 nested container levels and
1 MiB per CSV field in addition to the overall upload cap. Authentication uses
process-local throttling (5 failed attempts per username and 20 attempts per
client IP in 15 minutes); for multiworker deployments add a shared limiter at
the proxy or use a shared store. State-changing API requests require a
session-bound CSRF token from `GET /api/auth/csrf` in `X-CSRF-Token` and reject
unapproved browser origins.
# CSV timestamp timezones

Select an IANA timezone (default `America/Santiago`) when uploading a CSV.
Naive timestamps such as `Sep 14, 2026 3:02:15 PM` and ISO timestamps without
an offset are interpreted in that zone and stored as UTC epoch milliseconds,
including daylight-saving adjustments. Explicit offsets and numeric epochs are
unchanged. Existing API clients omitting the timezone retain UTC interpretation;
JSON uploads retain their existing behavior. Existing datasets are not changed:
reimport them to apply a timezone.
