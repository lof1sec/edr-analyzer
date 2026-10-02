# EDR Logs Graph Analyzer

A full-stack web application for analysing Endpoint Detection and Response (EDR)
logs. It ingests Microsoft Defender and CrowdStrike Falcon exports, maps the
relationships between entities, and renders them as an interactive graph where
**processes are the central actors** and files, network connections, registry
keys, loaded modules, command lines and alerts appear as related artifacts.

## Features

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

1. **Ingest** — `POST /api/datasets/upload` streams the upload in 1 MiB chunks,
   enforces `MAX_UPLOAD_SIZE_MB` (rejects with HTTP 413), detects UTF-8/latin-1,
   parses CSV/JSONL/JSON-array/single-object input, extracts the event type per
   vendor, and inserts `LogEvent` rows in batches.
2. **Build graph** — `GET /api/graph/{id}` loads the dataset's events in a
   deterministic order and feeds them to `GraphBuilder` plus the per-vendor
   parsers, producing Cytoscape `{ nodes, edges, unmapped_events }`.
3. **Visualise** — the React frontend renders the graph and applies all
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
| `POSTGRES_USER` | db / backend | *(required)* | PostgreSQL user |
| `POSTGRES_PASSWORD` | db / backend | *(required)* | PostgreSQL password — set a strong value |
| `POSTGRES_DB` | db / backend | *(required)* | PostgreSQL database name |
| `CORS_ORIGINS` | backend | `http://localhost:5173` | Comma-separated allowlist of browser origins. Never use `*` |
| `MAX_UPLOAD_SIZE_MB` | backend | `200` | Maximum accepted upload size; larger files get HTTP 413 |
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

1. **Upload logs:** use the sidebar to upload a `.csv`, `.json` or `.jsonl`
   export. The backend reports the number of parsed events or the reason for a
   rejection (e.g. file too large).
2. **Analyse:** click a dataset to load its graph. Use the right-hand panel to:
   - search globally (comma-separated terms are OR-ed),
   - toggle event types, users and PIDs,
   - inspect a selected node/edge and its raw logs,
   - review unmapped event types.
3. **Explore:** switch between Force-directed, Tree and Centered layouts, fit the
   graph, and hide elements you don't need (`Unhide All` restores them).

---

## 🔌 API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/datasets/upload` | Upload and parse a CSV/JSON/JSONL file. `413` if too large, `400` on invalid input |
| `GET` | `/api/datasets/` | List datasets with their log counts |
| `DELETE` | `/api/datasets/{dataset_id}` | Delete a dataset and all of its events |
| `GET` | `/api/graph/{dataset_id}` | Cytoscape elements and unmapped-event stats for a dataset |
| `GET` | `/` | Liveness/status check |

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
edge ids) and Falcon/Defender parser smoke tests.

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
│   │   │   ├── datasets.py   # upload / list / delete
│   │   │   └── graph.py      # graph generation
│   │   ├── database.py       # engine/session (DATABASE_URL)
│   │   ├── models.py         # Dataset, LogEvent
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
│   │   ├── components/       # GraphView, Sidebar, Cytoscape styles
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
- There is **no authentication** yet: do not expose the API publicly without
  adding an auth layer in front of it.
