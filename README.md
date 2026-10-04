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
  configurable limit.
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
- **Clustering & lazy loading:** fan-out hubs collapse their exclusively-owned
  descendants into a `+N` placeholder that loads on demand, and any node's
  neighbourhood can be pulled in on request — so large graphs stay responsive.
- **Deep inspection:** Click any node or edge to inspect its metadata and the
  raw log events behind it, with copy-to-clipboard.
- **Schema migrations:** Alembic runs automatically on backend startup.
- **Tested & automated:** A pytest suite and GitHub Actions CI (backend tests +
  frontend lint/build).

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
   Exclusively-owned fan-out subtrees are collapsed into `+N` cluster
   placeholders and expanded on demand (`/api/graph/{id}/clusters/…`).
4. **Visualise** — the React frontend renders the graph and applies all
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
   `+N` cluster to expand it, use **Neighbours** to load adjacent elements on
   demand, and **Reset layout** to regenerate the arrangement (your layout is
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
| `GET` | `/api/graph/{dataset_id}/search?q=…` | Ids of elements matching the search terms (server-side search) |
| `GET` | `/api/graph/{dataset_id}/clusters/{cluster_id}` | Hidden elements of a collapsed cluster (on-demand expansion) |
| `GET` | `/api/graph/{dataset_id}/neighbors?element_id=…&depth=…` | Subgraph within N hops of an element (1–3) |
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
edge ids, fan-out clustering), saved layouts, on-demand neighbourhoods and
Falcon/Defender parser smoke tests.

### Database migrations

The schema is managed with **Alembic** and applied automatically when the backend
starts (`alembic upgrade head`). The initial migration is idempotent, so it is
safe on both fresh databases and databases previously created via
`Base.metadata.create_all`.

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
│   │   │   ├── falcon.py     # CrowdStrike Falcon event mapping
│   │   │   └── vendor.py     # event type / vendor detection
│   │   ├── routers/
│   │   │   ├── auth.py       # login / logout / first-run setup + auth guard
│   │   │   ├── datasets.py   # upload / list / delete
│   │   │   └── graph.py      # graph generation, clusters, layouts
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
│   │   ├── components/       # GraphView, Sidebar, AuthPage, Cytoscape styles
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
