# TODO

Working task list for the EDR Logs Graph Analyzer. Items are grouped by theme and
ordered by the agreed implementation order. Legend: `[x]` done, `[~]` partially
done, `[ ]` pending.

---

## Item 3 — Performance / scale

**Status:** 3.2 and 3.1 implemented; 3.3 has the groundwork in place and the
progressive initial load remains. Order applied: **3.2 → 3.1 → 3.3**.

### 3.2 Persistent per-dataset layout — ✅ DONE

- [x] **Model + Alembic migration**: `graph_layouts` table (1 row per dataset,
      `positions` JSONB) and migration `0003_add_graph_layouts`.
      `backend/app/models.py`, `backend/alembic/versions/0003_add_graph_layouts.py`.
- [x] **Endpoints**: `GET /api/graph/{id}/layout` and
      `PUT /api/graph/{id}/layout` (positions only, `{node_id: {x, y}}`).
      `backend/app/routers/graph.py`, `backend/app/schemas.py`.
- [x] **Apply the saved layout on load**: `GraphView` requests the graph and the
      layout in parallel and uses the positions as the preset for the force
      layout. `frontend/src/components/GraphView.jsx`.
- [x] **Debounced save** (800 ms) when a layout finishes and when a node is
      released (`layoutstop` + `dragfree`).
- [x] **"Reset layout" button**: deletes the saved layout and re-runs the force
      layout.
- [x] **Cascade delete**: deleting a dataset deletes its layout.
      `backend/app/routers/datasets.py`.
- [x] **Tests**: save/read layout and 404 for a nonexistent dataset.

### 3.1 Clustering (collapse large subtrees) — ✅ DONE

- [x] **Hub detection and collapse (artifacts only)**: in `GraphBuilder`, a
      process with more than `CLUSTER_MIN_CHILDREN` **artifact** children that are
      *exclusively* owned (single parent, `group != "process"`) groups them into a
      placeholder. **Processes and their `Spawns` edges are never collapsed**, so
      the graph stays connected; artifacts are leaves, so removing an exclusive one
      never leaves a dangling edge, and a shared artifact stays.
      `backend/app/parsers/builder.py`.
- [x] **Connectivity fix** (after being found in testing): the initial version
      collapsed entire subtrees, including processes, and when the `Spawns` edges
      disappeared the graph looked disconnected. Now only leaf artifacts are
      collapsed.
- [x] **Lightweight payload**: collapsed nodes do not travel in `elements`; the
      placeholder carries `isCluster`, `clusterCount` and `parentId`. `raw_logs`
      and `search_index` are still built so they can be expanded and searched.
- [x] **Expand on demand**: `GET /api/graph/{id}/clusters/{cluster_id}` returns
      the hidden nodes and edges. `backend/app/routers/graph.py`.
- [x] **Render and UX**: `cluster` group (diamond) + legend entry, click to
      expand, panel of expanded clusters with "Collapse All".
      `frontend/src/components/cytoscapeStyles.js`, `GraphView.jsx`.
- [x] **Positioning on expand**: new nodes are arranged in a ring around the hub;
      the full layout is not re-run.
- [x] **Tests**: collapse and expansion of a hub's artifacts; a shared artifact is
      **not** collapsed; processes are **never** collapsed.

### 3.3 Lazy neighbours / pagination — 🚧 PARTIAL

- [x] **Neighbourhood endpoint** (basis for progressive loading):
      `GET /api/graph/{id}/neighbors?element_id=…&depth=1..3`, capped at
      `MAX_NEIGHBOR_NODES` (2000) with a `truncated` flag.
      `backend/app/routers/graph.py`. Still available (unused by the UI).
- [x] **"Reveal" button** in Node Details (option 1): re-shows the 1-hop
      neighbourhood that is hidden by "Hide", the user/PID/event filters, the
      global search or focus. It is **client-side** (does not call the server) and
      acts as a targeted "Unhide All".
- [x] **Reusable merge basis**: new elements (clusters) are added with computed
      positions.
- [ ] **Progressive initial load**: do not send the whole graph for very large
      datasets; load roots and expand the neighbourhood on demand (reusing the
      endpoint and the merge). Requires rethinking filters and layout over a
      partial graph (pending).

---

## Time-range filter in the graph — ✅ DONE

**Status:** implemented. The graph can be filtered by a time window (start/end)
and the UI shows the total range available in the export.

**Goal:** graph only the events inside a time range, showing start/end, without
losing global search.

### Backend

- [x] **Filtering by `event_time`**: `_build_graph_payload` accepts `from_ms`/
      `to_ms` (epoch ms) and adds `WHERE event_time >= from AND <= to`. Events
      without a date (`event_time IS NULL`) are excluded when a window is set.
      `backend/app/routers/graph.py`.
- [x] **`from`/`to` params** on `generate_graph`, `get_elements`,
      `get_element_logs`, `get_cluster` and `get_neighbors`; the global `search`
      is kept without a time filter.
- [x] **Cache by range**: `graph_cache` moves to the key `(dataset_id, from_ms,
      to_ms)`; `invalidate(dataset_id)` clears all windows of the dataset.
      `backend/app/routers/graph_cache.py`.
- [x] **Available range**: `GET /api/graph/{id}/time-range` → `{min_ms, max_ms}`
      (`MIN/MAX(event_time)` aggregate over the whole dataset; `null` when there
      are no dated events).

### Frontend

- [x] **start/end picker** (`datetime-local`) + **Apply** and **Clear** buttons in
      the graph toolbar. `frontend/src/components/GraphView.jsx`.
- [x] **Visible available range** next to the inputs (`Available range: … → …`)
      and as the fields' `min`/`max`, computed over the whole dataset (without a
      filter).
- [x] **Reload on apply**: changing the range reloads the graph (reset of
      selection/layout/truncation). The saved layout is only restored without a
      filter.
- [x] **Consistent pagination and evidence**: "Load more/all", `getCluster` and
      `getElementLogs` propagate the active window.
- [x] **`api` (`frontend/src/api/client.js`)**: `getGraph`/`getGraphElements`/
      `getElementLogs`/`getCluster`/`getNeighbors` accept `{from, to}`; new
      `getTimeRange`.

### Testing

- `backend/tests/test_graph_time.py`: filtering by `from`/`to`, `time-range`
  (full span and ignoring events without a date) and 404 for a nonexistent
  dataset.
- `backend/tests/test_graph_cache.py`: adapted to `(dataset_id, from, to)` keys
  and clearing all windows when invalidating a dataset.
- Frontend: `npm run lint` (0 errors) + `npm run build` OK.

---

## Element time in Node Details — ✅ DONE

**Status:** implemented. The details panel shows when the selected node/edge was
first and last observed.

**Goal:** see the instant of the selected element in the format
`dd/mm/yyyy, HH:MM:SS`.

### Backend

- [x] **`first_time`/`last_time` per element**: `_append_raw_log` (the single
      point where each event is attached to a node/edge) records the `min`/`max`
      of `event_time`, ignoring events without a date. `backend/app/parsers/builder.py`.
- [x] **Time per event**: `GraphBuilder.current_event_time` is set in
      `_build_graph_payload` from `log.event_time` before each `parse(...)`.
      `backend/app/routers/graph.py`.
- [x] **No raw logs in `elements`** (invariant 8): only the normalised epoch ms is
      added to `data`, not the raw event.

### Frontend

- [x] **"Time" row** in Node Details (first appearance) and **"Last activity"**
      only when it differs from the first. `frontend/src/components/GraphView.jsx`.
- [x] **Format** `dd/mm/yyyy, HH:MM:SS` in the local time zone.
- [x] Elements without dated events: no time is shown.

### Testing

- `backend/tests/test_graph_time.py`: `first_time`/`last_time` of a node/edge with
  several events and absence of time on elements without a date.
- Frontend: `npm run lint` (0 errors) + `npm run build` OK.

---

## Process PID display without host — ✅ DONE

**Status:** implemented. Process nodes show only the PID (`600`) instead of
`pid@host` (`600@H1`); the host stays on its own `🖥️ H1` line.

**Goal:** remove the noise of the `@host` suffix in the node label/title.

### Changes

- [x] **`backend/app/parsers/builder.py`** (`get_or_create_process_node`):
      `label`/`title` use the bare PID (`data.pid`); the node **id** remains
      `pid@host` (invariant 2 intact: no collisions between hosts and no layout
      migration).
- [x] **`frontend/src/components/GraphView.jsx`**: the "Process IDs (PIDs)"
      filter shows `process_name (600)` using `data.pid`; the `pids` map is still
      keyed by `id` (the hiding logic does not change).
- [x] **Timeline** (`_timeline_element_ids`) unchanged: it still composes
      `pid@host` to focus the correct node.

### Testing

- `backend/tests/test_builder.py`: the id remains `100@hostA`, `data.pid == "100"`
  and `label`/`title` show `100` (not `100@hostA`).
- Frontend: `npm run lint` (0 errors) + `npm run build` OK.

---

## Suspicious-pattern detection + risk score

**Status:** planned (not implemented). It is the next idea outside item 3.

**Goal:** analyse the already-built graph and detect known suspicious patterns
(LOLBins, obfuscation, injection, persistence, credential access, discovery,
escalation), producing a list of findings with severity, MITRE and evidence, plus
an aggregated **risk score** (0–100) per dataset and a per-node risk used for
colouring.

### Architectural approach

- **New, pure module** `backend/app/analyzers/` that operates on the
  already-built graph (`nodes_dict` + `edges_list`), without touching HTTP or raw
  logs: easy to test in isolation (like the pure parser tests).
  - `base.py`: `Finding` and `Rule` dataclasses, rule registry, and
    `analyze(graph) -> (risk_score, findings)`.
  - `rules/`: one rule per pattern (pure functions).
  - `data/`: curated, versionable lists (LOLBins, persistence paths, credential
    binaries, command-line patterns).
- **On-demand computation + reuse of the graph cache** (`graph_cache.py`): no new
  table or Alembic migration in v1.
- **Detection is derived from the graph**, not from raw logs; artifacts and
  processes already expose `group`, `process_name`, `actions` and
  `event_simplename`. Invariant 8 is respected (no raw logs in `elements`).

### Input data model (already available)

| Source | Fields used | For |
| --- | --- | --- |
| Process node | `process_name`, `label`, `username`, `hostname`, `actions[]` | LOLBins, credentials, discovery, escalation |
| Artifact node | `group` (file/registry/network/module/powershell/commandline…), `label`, `title` | persistence, obfuscation, cradle |
| Edge | `event_simplename`, `source`, `target`, `label` | injection, persistence, chaining |

### Rule framework

- `Finding`: `rule_id`, `name`, `severity` (`low|medium|high|critical`),
  `description`, `node_ids`, `edge_ids`, `mitre` (tactic/technique), `evidence`.
- `Rule`: `id`, `name`, `severity`, `matcher(graph) -> list[Finding]`,
  `references`.
- Declarative registry: adding a rule = one file + registration; no need to touch
  the endpoint.
- The exact `evt_type`/`group` values for injection and persistence are
  **enumerated from `defender.py`/`falcon.py`** (invariant 1: detection by fields,
  not loose strings).

### Initial rule catalogue

| # | Pattern | Signal in the graph | Severity |
| --- | --- | --- | --- |
| 1 | **LOLBin** (rundll32, mshta, regsvr32, certutil, msbuild, cscript, wscript, cmstp…) | `process_name` against a curated list | high |
| 2 | **Obfuscated PowerShell** (`-enc`, `-command`, download cradle) | `powershell`/`commandline` artifact or the process's `actions` | high |
| 3 | **Injection** (CreateRemoteThread / module in another process) | edge with an injection `event_simplename` between 2 processes | critical |
| 4 | **Persistence** (Run/RunOnce, ScheduledTask, schtasks, startup) | `registry` artifact with a startup path or `ScheduledTaskModified` edge | high |
| 5 | **Credential access** (lsass, mimikatz, dump) | `process_name`/`commandline` against a list | critical |
| 6 | **Discovery** (whoami, net view, nltest, adfind) | `process_name`/`commandline` | medium |
| 7 | **Escalation / UAC bypass** | specific events + combination of processes | high |

### Risk score

- Weight per severity (low/medium/high/critical) → aggregated score normalised
  **0–100** with a cap, deterministic and documented formula.
- **Per-node score** to colour the processes/artifacts involved (ring/glow).

### API

- `GET /api/graph/{id}/detections` → `{ risk_score, findings[] }` (requires auth,
  like the rest of the data routes).
- Lightweight `risk_score` included in the main payload to paint a badge without
  waiting for the endpoint.
- Evidence detail reusing `/api/graph/{id}/element-logs` (do not duplicate raw
  logs).

### Frontend

- **"Detections"** panel with findings sorted by severity; click → focus and
  highlight the nodes involved in the graph.
- Red/orange ring on nodes with risk; **badge** with the risk score in the
  dataset header.
- Toggle to show/hide the highlighting.

### Configuration

- `DETECTIONS_ENABLED` toggle (enabled by default).
- Curated lists in `backend/app/analyzers/data/` (editable without touching code).
- Severity weights and threshold documented in the module.

### Testing

- Pure tests per rule: a synthetic graph that **triggers** and one that **does
  not trigger** each pattern (reusable `GraphBuilder` fixture).
- HTTP tests of the endpoint: auth, empty graph, graph with findings.
- Without failing over the tolerated frontend `react` warnings.

### Implementation order

1. `base.py` + `data/` (curated lists).
2. Rules + pure tests.
3. Endpoint + schema + integration with the cache.
4. Frontend panel + highlighting + badge.
5. Docs (`AGENTS.md`, `README.md`) and tick this section.

### Default decisions (to be confirmed)

1. **Knowledge source:** embedded curated lists + versionable data files
   (recommended), expandable to configurable files.
2. **Persistence:** on-demand + cache, with no table or migration (recommended)
   vs. a `detections` table with history/auditing.
3. **Score:** aggregated 0–100 index (recommended) in addition to per-finding
   severity.
4. **Initial rules:** start with **LOLBins + injection + persistence** and grow
   (vs. all 7 at once).
5. **UI:** side panel + badge/colouring (recommended) vs. colouring nodes only.

### Planned files

- New: `backend/app/analyzers/{base.py,rules/,data/}`,
  `backend/tests/test_analyzers.py`.
- Modified: `backend/app/routers/graph.py`, `backend/app/schemas.py`,
  `frontend/src/api/client.js`, `frontend/src/components/GraphView.jsx`
  (panel/legend), possibly `frontend/src/components/NodeDetails…` and
  `.env.example`, `README.md`, `AGENTS.md`.

---

## Parser fuzzing with Hypothesis — ✅ DONE

**Status:** implemented. A *property-based* test suite was added; the fuzzing
already surfaced and fixed a real encoding bug (see "Result").

**Goal:** guarantee with *property-based* tests that the parsing pipeline (pure,
no HTTP or DB) is robust against any input and that the graph invariants always
hold. It looks for two properties:

1. **Never crashes** with unexpected exceptions on unknown events, odd types
   (`None`, int, lists), broken JSON or corrupt bytes.
2. **The graph comes out intact:** JSON-serializable, unique ids, no dangling
   edges and processes never collapsed.

**What it solves (value):**

- **Crashes from unexpected types** that today would be a 500 (e.g. a non-str
  `ImageFileName` and `.split()` in `falcon.py`).
- **Malformed JSON/CSV** that does not translate into a clean `HTTPException`
  400/413 (e.g. `csv.Error`, uncaught `UnicodeDecodeError`).
- **Graph invariants** that no one checks exhaustively: unique ids, no
  node/edge collision, no edges to nonexistent nodes, non-destructive clustering.
- **Security/availability:** the parsers consume user-uploaded files; an input
  that triggers an uncontrolled exception or unbounded consumption is a DoS
  vector.
- **A permanent safety net** in CI against regressions when adding vendors or
  event types with non-defensive accesses.

### Targets (pure functions) and their oracle

| Target | Fuzzed input | Invariant to verify |
| --- | --- | --- |
| `vendor.get_vendor` / `extract_event_type` / `is_falcon_event` | `Any` (dict, list, `None`, int…) | do not raise; only known constants |
| `builder.get_additional_fields_dict` | dict with nested/JSON `AdditionalFields` | does not raise; returns a `dict` |
| `builder.hash_str` / `string_hash` | `str` / `Any` | do not raise; fixed-length hex |
| `defender.parse_defender_event` / `falcon.parse_falcon_event` | JSON-like `event` + `evt_type` + ids (`None`/int/str) | do not raise; the resulting graph is JSON-serializable |
| `builder.GraphBuilder.build_cytoscape_elements` | builder populated by the previous steps | `json.dumps` OK; node and edge ids unique and disjoint; every edge points to an existing node |
| `builder.GraphBuilder._plan_clusters` | builder with many artifacts/processes | only collapses `group != "process"`; processes and `Spawns` edges remain |
| `datasets._parse_csv_rows` / `_parse_json_rows` / `_detect_encoding_and_check_size` | arbitrary `bytes` | only `HTTPException` 400/413, never another exception |

### Hypothesis strategies (shared)

`backend/tests/strategies.py`:

- `json_value`: `st.recursive` with `none`/`bool`/`int`/`float`/`text` + nested
  lists and dicts (for `event`).
- `event_dict`: `st.dictionaries(st.text(), json_value, max_size=30)`.
- `event_type`: a mix of `st.sampled_from(KNOWN_*_TYPES)` (to exercise the real
  branches) + `st.text()` (robustness against unknowns).
- `element_id`: `st.one_of(st.none(), st.text(), st.integers())`.
- Bytes: `st.binary(max_size=4096)` plus prefixes that force BOM, latin-1 and
  broken JSON.

### Oracles and test structure

- Reusable helper `_assert_graph_invariants(payload)` (unique ids, disjoint, no
  dangling edges, non-destructive clustering).
- New files:
  - `backend/tests/strategies.py`
  - `backend/tests/test_fuzz_vendor.py`
  - `backend/tests/test_fuzz_builder.py`
  - `backend/tests/test_fuzz_defender.py`
  - `backend/tests/test_fuzz_falcon.py`
  - `backend/tests/test_fuzz_upload.py`

### Integration and CI

- Add `hypothesis` to `backend/requirements-dev.txt` (not to runtime).
- Deterministic profile in `backend/tests/conftest.py` to avoid flakiness:
  `max_examples=150`, `deadline=None`, `derandomize=True`, and disable the
  `too_slow`/`data_too_large` health checks.
- Hypothesis integrates with pytest; there is no conflict with `ruff` (the
  `@given`/`@settings` decorators are not `B008`).

### Checklist (order applied)

- [x] `strategies.py` (`json_value`, `event_dict`, `graph_id`/`optional_id`,
      `event_type_strategy`, `DEFENDER_/FALCON_EVENT_TYPES`) + helper
      `assert_graph_invariants`.
- [x] Fuzz `vendor.py` and `builder.py` (hashes with non-hashable values,
      `get_additional_fields_dict`, `build_cytoscape_elements` invariants).
- [x] Fuzz `parse_defender_event` / `parse_falcon_event` + graph invariants.
- [x] Fuzz `datasets.py` helpers (bytes) + 3 targeted regressions.
- [x] `hypothesis` in `requirements-dev.txt` + `ci` profile in `conftest.py`.
- [x] Harden the pipeline against what surfaced (see below).
- [x] Docs (`AGENTS.md` → Testing) and tick the `TODO` line.

### Result

`python -m pytest -q` → **81 tests OK** (up from 69) and `ruff check` clean.

Bugs/hardenings the fuzzing motivated:

- **Truncated UTF-8 misdetected** (bug found by Hypothesis with `b"\xc2"`):
  `_detect_encoding_and_check_size` did not finalise the incremental decoder, so
  an incomplete multibyte sequence at the end of the file was accepted as valid
  `utf-8-sig` and blew up when decoding. Now `decoder.decode(b"", final=True)` is
  done and it falls back to latin-1. Regression in `test_fuzz_upload.py`.
- **`hash_str` / `string_hash`** tolerate non-hashable values (dicts/lists): they
  coerce to `str` *before* the `lru_cache`.
- **Parsers**: event fields go through `as_text()` wherever they are used as text
  (`.split`, `.replace`, `textwrap.fill`, slicing), so a `None`/number/list field
  does not raise.
- **`build_cytoscape_elements` / `extract_event_type`**: return type is always
  serializable / text.
- **Upload**: `csv.Error` (field > `field_size_limit`) and `RecursionError` (very
  nested JSON) are translated to 400; `stream.detach()` tolerates already-closed
  streams.

### Deviations from the original plan

- The helper is called `assert_graph_invariants` (not `_assert_graph_invariants`).
- Ids use `graph_id`/`optional_id`: they include integers and `None`, and exclude
  the `edge_` prefix (namespace reserved for edges).
- Bytes `st.binary(max_size=2048)` (enough; the giant CSV field and the deeply
  nested JSON are covered by targeted regressions).

---

## Timeline / chronological view with playback — ✅ DONE

**Status:** implemented. Timeline view with playback highlighting on the graph.

**Goal:** see the dataset's events in chronological order and replay the sequence
(play/pause, speed, scrubber), with filters and synchronized highlights on the
graph.

### Backend

- [x] **Normalised timestamp**: `LogEvent.event_time` (epoch ms, nullable) +
      migration `0004_add_event_time`. It is filled on upload with
      `extract_timestamp` (`app/parsers/timestamps.py`), which understands epoch
      seconds/ms and ISO-8601, with Falcon (`timestamp`) and Defender
      (`Timestamp`/`EventTime`/…) fields. No timestamp → `NULL` (insertion order).
- [x] **Shared event description**: `describe_event` (`app/parsers/events.py`)
      extracts actor/target/user/host per vendor; used by the graph and the
      timeline (same field criterion, invariant 1).
- [x] **Endpoint**: `GET /api/graph/{id}/timeline?offset&limit&event_type&q&from&to`
      (auth), paginated, order `event_time NULLS LAST, id`. Returns compact
      entries (time, type, vendor, summary, graph-derived element ids), never
      raw logs (invariant 11).
- [x] **Exact graph/timeline correspondence**: `GraphBuilder` records a server-side
      event→node/edge map; the timeline excludes events without graph elements,
      applies the active graph time/search/event-type/user/PID filters before
      counting and paging, and preserves events hidden only by clustering,
      truncation, Hide or focus depth. `GET /api/graph/{id}/focus` loads a paged
      or clustered timeline target on demand.

### Frontend

- [x] **`TimelineView.jsx`**: chronological list with playback (play/pause, speed
      0.5×–8×, scrubber, next/previous), search and filter by event type, and
      "Load more" (paginated).
- [x] **Graph/Timeline selector** in `App.jsx`; the graph stays mounted above the
      timeline. Play, row clicks, next/previous and scrubbing highlight the
      current event's real node or edge without switching tabs or rerunning the
      layout. Playback temporarily reveals hidden endpoints without changing
      manual filters, waits for paged/clustered elements to load before advancing
      and prefetches further timeline pages.
- [x] **`api.getTimeline`** in `frontend/src/api/client.js` (single API path).
- [x] `App.jsx` retains the graph's applied range and identity/search filters
      across tabs; `TimelineView.jsx` passes them to the API and clicking an entry
      loads and focuses the real artifact or relationship when needed.

### Configuration

- No new mandatory variables: `TIMELINE_DEFAULT_LIMIT` (200) and
  `TIMELINE_MAX_LIMIT` (1000) are router constants.

### Testing

- `backend/tests/test_timestamps.py` (epoch s/ms, ISO with/without zone, `None`).
- `backend/tests/test_timeline.py` (order with undated events last, pagination,
  filters, 404).
- Frontend: `npm run lint` (0 errors) + `npm run build` OK.
- Playback cursor and pagination regression tests: `frontend/tests/timelinePlayback.test.js`
  (`npm run test`), included in CI.

### Pending / ideas (follow-up)

- [x] Full event→element mapping, including artifacts and edges, is recorded by
      the builder for graph-backed timeline entries.
- [ ] Backfill `event_time` for datasets uploaded before migration `0004` (today
      they fall back to insertion order).
- [x] The graph's applied time range follows the user into the timeline view.
- [x] Playback highlights the current event in the graph in real time without
      changing view or rebuilding its layout.
- [ ] Group/collapse repeated events and "jump to the next event of the same
      process".

---

## Review / corrections (post-review) — ✅ DONE

**Status:** full project review. Fixed the 4 confirmed bugs (crashes, data
duplication and process collision between hosts with the same PID), including the
migration that invalidates layouts saved with the old ids.

### Confirmed and fixed bugs

- [x] **`extract_timestamp` was not safe against `NaN`/`Infinity`/overflows**
      (`app/parsers/timestamps.py`). JSON with `NaN`/`Infinity` (which `json.loads`
      accepts) or a gigantic number raised `ValueError`/`OverflowError` when
      extracting the timestamp of **each row**, breaking the whole upload with a
      500 and leaving an orphaned dataset. Now `math.isfinite` and a plausible
      range (≤ 9999-12-31) are validated; non-finite or out of range → `None`.
      Regressions in `test_timestamps.py` and `test_timeline.py` (upload with
      `NaN`).
- [x] **Numeric `RegValueName` in Falcon crashed** (`app/parsers/falcon.py`):
      `len(raw_reg)` on an `int` → `TypeError`. `as_text()` is applied as to the
      rest of the fields. Regression in `test_parsers_smoke.py`.
- [x] **Clusters duplicated repeated artifacts** (`_plan_clusters`,
      `app/parsers/builder.py`): a hub with several edges to the same artifact
      generated `members` with duplicates, inflated the threshold and produced
      repeated nodes when expanding (although `clusterCount` counted them once).
      It is deduplicated preserving order. Regression in `test_builder.py`.
- [x] **Process collision between hosts** (`get_or_create_process_node`,
      `app/parsers/builder.py`): the node id was only `str(pid)`, so the same PID
      on two machines collapsed into a single node and a process was lost. Now the
      id is **host-scoped** (`pid@host`; without a host the raw PID is kept). The
      parsers reuse the returned id for their edges and for the artifacts that
      embed the process; `_timeline_element_ids` (`app/routers/graph.py`) composes
      the same. Migration `0005_clear_graph_layouts` clears the saved layouts
      (positions by old id) so the graph is re-composed. Regressions in
      `test_builder.py` and `test_parsers_smoke.py`. **Forward-only breaking
      change**: the graph is rebuilt on demand, but the saved positions are
      discarded.

### Minor improvement applied

- [x] `pool_pre_ping=True` in `create_engine` (`app/database.py`) to avoid stale
      connections after a Postgres restart.

### Parser events added

- [x] **Falcon `ScriptControlScanInfo`**: the script scanned by ScriptControl is
      mapped as a `file` artifact (short name + path + SHA256 + content snippet,
      truncated to 200 chars) with a `Runs Script` edge from the process that
      executes it. Regression in `test_parsers_smoke.py`.
- [x] **Falcon `CreateSocket`**: socket creation is mapped as a `network` artifact
      keyed by process + (AddressFamily, SocketType, Protocol), with
      `SocketType`/`Protocol` decoded into labels (`1→STREAM`, `6→TCP`, …) and a
      `Creates Socket` edge (`#00ffff`). Regression in `test_parsers_smoke.py`.
- [x] **Falcon `CriticalFileAccessed`**: the accessed critical file is mapped as a
      `file` artifact (same id `file_{hash(path)}` as the rest of the file events)
      with path, `UID`, `GID` and `UnixMode` in the title, and an
      `Accesses Critical File` edge (`#ff4d4d`). Regression in
      `test_parsers_smoke.py`.
- [x] **Falcon `NetworkLinkConfigGetAddress`**: it only brings the process; the
      node and its action are recorded (no artifact/edge), preventing it from
      counting as unmapped. Regression in `test_parsers_smoke.py`.
- [x] **Falcon `CriticalEnvironmentVariableChanged`**: `EnvironmentVariableName`/
      `Value` are mapped as a `registry` artifact (`Env: NAME`) with a
      `Sets Env Var` edge (`#ff9933`). Regression in `test_parsers_smoke.py`.
- [x] **Falcon `NetworkListenIP4`**: the listening socket is mapped as a `network`
      artifact with the local endpoint (`LocalAddressIP4:LocalPort`, same id
      scheme as the network) and a `Listens On` edge (`#00ffff`), with
      `Protocol`/`ConnectionDirection` decoded. Regression in
      `test_parsers_smoke.py`.

### Recommendations not applied (low impact)

- [ ] Extract the duplicated `"Unknown"` constant in `events.py`/parsers.
- [ ] Lenient JSON: `_parse_json_rows` accepts missing commas and garbage after
      the object; consider a strict mode or count malformed lines.
- [ ] Per-process graph cache (`graph_cache`): it is not shared with
      `--workers N`; documented, revisit if it scales.
- [x] Session-bound CSRF token on all mutating API routes, with Origin checks.

### Testing

- [x] `backend/tests/` becomes **107 tests** (regressions for the 4 bugs + the new
      events); `ruff` clean. Frontend: `lint` (0 errors) + `build` OK.

---

## Review improvements (all implemented)

- [x] **Map nine additional Falcon event types**: `InjectedThread`, `DllInjection`,
      `ProcessInjection`, `NewExecutableRenamed`, `ReflectiveDotnetModuleLoad`,
      `ScriptControlDetectInfo`, `SensitiveWmiQuery`, `CreateService` and
      `RemoteCommandResponse`. Preserve UPID-based process relationships, attach
      process-less command responses to the host, keep full script/output content
      in on-demand raw evidence, and cover graph/timeline mapping with tests.
- [x] **Map Falcon `ClassifiedModuleLoad`**: connect the loaded module to its
      target process, decode module classification, characteristics, signature
      and zone metadata, and include the event in graph-backed timeline entries.
      Cover missing fields, cross-host reuse and timeline mapping with tests.
- [x] **Handle escaped NULs in JSON exports**: remove decoded NULs (`U+0000`) from
      nested values and keys before JSONB insertion, reject colliding keys with
      HTTP 400, and cover JSONL, JSON arrays, single objects and HTTP uploads
      with regression tests. Verified clean data against PostgreSQL JSONB.
- [x] **Enforce the initial graph element cap even for dense process backbones**:
      account for process-process edges before admitting each process; test
      parallel edges and verify pagination recovers them all.
      `backend/app/routers/graph.py`, `backend/tests/test_graph_truncation.py`.
- [x] **Protect saved layouts under time filters**: filtered graphs cannot save
      or reset the unfiltered dataset layout. `frontend/src/components/GraphView.jsx`.
- [x] **Ignore stale graph requests**: generation guards discard late graph,
      search, omitted-element page and cluster responses; cancel pending layout
      save timers when switching datasets or time windows.
      `frontend/src/components/GraphView.jsx`.
- [x] **Make uploads atomic**: flush batches within one transaction, commit only
      on success, and roll back any exception; test failure after the first
      batch. `backend/app/routers/datasets.py`, `backend/tests/test_api.py`.
- [x] **Scope graph search to the active time window**: propagate `from`/`to`
      through the API client and search endpoint; test the same node in two
      windows with evidence matching only one.
      `backend/app/routers/graph.py`, `frontend/src/api/client.js`,
      `backend/tests/test_graph_time.py`.
- [x] **Precompute paginated edges**: bucket omitted edges by the later endpoint
      so each page avoids rescanning the entire omitted graph.
      `backend/app/routers/graph.py`.
- [x] **Improve timeline substring-search performance**: add a PostgreSQL
      `pg_trgm` GIN expression index and a composite dataset/time/id index;
      document a representative `EXPLAIN (ANALYZE, BUFFERS)` comparison in
      `README.md`. Actual PostgreSQL timings remain environment-dependent.
      `backend/alembic/versions/0006_timeline_search_indexes.py`.
- [x] **Use English throughout the graph pagination UI**: labels, tooltips and
      comments now say "Showing", "Load more" and "Load all".
      `frontend/src/components/GraphView.jsx`.

---

## Pending / next ideas (outside item 3)

- [x] **Timeline / chronological view** with playback of the event sequence —
      done (eponymous section above).
- [x] **Code review / corrections** — 4 bugs fixed (eponymous section above).
- [ ] **MITRE ATT&CK mapping** per event (tactic/technique) and filter by
      technique.
- [ ] **Suspicious-pattern detection** (LOLBins, injection, persistence) and
      risk score — detailed plan in the eponymous section above.
- [ ] **Pivoting**: expand parents/children, isolate a subtree, shortest path
      between two nodes.
- [ ] **Statistics dashboard** (top processes, hosts/users, event types).
- [ ] **Search with operators** (`type:process host:foo`) and save views.
- [ ] **Export** the graph to PNG/SVG/JSON and the filtered list to CSV.
- [ ] **New vendors**: Sysmon, SentinelOne, Carbon Black, auditd.
- [ ] **Frontend tests** (Vitest + Testing Library) and E2E (Playwright).
- [x] **Parser fuzzing** (Hypothesis) — done (eponymous section above).
- [ ] **`/api/health`** and basic metrics.
- [ ] **Audit log** of actions (login, upload, delete).
- [x] **Process-local rate limiting** on login and setup (username and IP).
- [ ] **Shared rate limiting** for multiworker deployments; security headers.

## Security and ingestion hardening

- [x] Bound JSON event size (8 MiB) and depth (64), CSV field size (1 MiB),
      and preserve streamed upload/transaction semantics.
- [x] Bound graph artifact titles to 8192 characters; keep raw evidence intact.
- [x] Apply session-bound CSRF checks and origin validation to mutations,
      including authentication, upload, delete and layout writes.
- [x] Throttle login/setup per client IP (20 attempts) and username (5 failures)
      over 15 minutes with HTTP 429 and `Retry-After`; ignore untrusted XFF.
- [x] Leave example secrets blank (database startup requires a password) and bind
      the Compose development database to localhost only.
- [ ] Use a shared rate limiter before running multiple backend workers; local
      counters cannot protect aggregate traffic across processes.
- [ ] (Roadmap) **Multi-user** with per-user or shared datasets.

---

## How to run what was added

```bash
# Backend (Docker; pytest is not in the runtime image)
docker run --rm -v "<path>/backend:/app" -w /app \
  -e DATABASE_URL=sqlite:// -e SECRET_KEY=test-secret-key edr-analyzer-backend \
  sh -c "pip install -q -r requirements-dev.txt && ruff check . && python -m pytest -q"

# Frontend
cd frontend && npm run lint && npm run build
```

`CLUSTER_MIN_CHILDREN` (default `50`; `0` disables) controls how many exclusive
descendants are needed to collapse a hub.
