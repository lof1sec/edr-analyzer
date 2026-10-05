# TODO

Working task list for the EDR Logs Graph Analyzer. Items are grouped by theme and
ordered by the agreed implementation order. Legend: `[x]` done, `[~]` partially
done, `[ ]` pending.

---

## Punto 3 — Rendimiento / escala

**Estado:** implementado el 3.2 y el 3.1; el 3.3 tiene la base hecha y queda la
carga inicial progresiva. Orden aplicado: **3.2 → 3.1 → 3.3**.

### 3.2 Layout persistente por dataset — ✅ HECHO

- [x] **Modelo + migración Alembic**: tabla `graph_layouts` (1 fila por dataset,
      `positions` JSONB) y migración `0003_add_graph_layouts`.
      `backend/app/models.py`, `backend/alembic/versions/0003_add_graph_layouts.py`.
- [x] **Endpoints**: `GET /api/graph/{id}/layout` y
      `PUT /api/graph/{id}/layout` (solo posiciones `{node_id: {x, y}}`).
      `backend/app/routers/graph.py`, `backend/app/schemas.py`.
- [x] **Aplicar el layout guardado al cargar**: `GraphView` pide grafo y layout en
      paralelo y usa las posiciones como preset del layout force.
      `frontend/src/components/GraphView.jsx`.
- [x] **Guardado debounced** (800 ms) al terminar un layout y al soltar un nodo
      (`layoutstop` + `dragfree`).
- [x] **Botón "Reset layout"**: borra el layout guardado y relanza el force.
- [x] **Borrado en cascada**: al eliminar un dataset se borra su layout.
      `backend/app/routers/datasets.py`.
- [x] **Tests**: guardar/leer layout y 404 en dataset inexistente.

### 3.1 Clustering (colapsar subárboles grandes) — ✅ HECHO

- [x] **Detección de hubs y colapso (solo artefactos)**: en `GraphBuilder`, un
      proceso con más de `CLUSTER_MIN_CHILDREN` hijos **artefacto** *exclusivos*
      (un solo padre, `group != "process"`) los agrupa en un placeholder. **Los
      procesos y sus aristas `Spawns` nunca se colapsan**, así que el grafo sigue
      conectado; los artefactos son hojas, así que quitar uno exclusivo nunca deja
      una arista colgando, y un artefacto compartido permanece.
      `backend/app/parsers/builder.py`.
- [x] **Fix de conectividad** (tras detectarse en pruebas): la versión inicial
      colapsaba subárboles enteros, incluidos procesos, y al desaparecer las
      aristas `Spawns` el grafo parecía desconectado. Ahora solo se colapsan
      artefactos hoja.
- [x] **Payload ligero**: los nodos colapsados no viajan en `elements`; el
      placeholder lleva `isCluster`, `clusterCount` y `parentId`. Los `raw_logs` y
      el `search_index` se siguen construyendo para poder expandir y buscar.
- [x] **Expandir bajo demanda**: `GET /api/graph/{id}/clusters/{cluster_id}`
      devuelve nodos y aristas ocultos. `backend/app/routers/graph.py`.
- [x] **Render y UX**: grupo `cluster` (rombo) + entrada de leyenda, click para
      expandir, panel de clusters expandidos con "Collapse All".
      `frontend/src/components/cytoscapeStyles.js`, `GraphView.jsx`.
- [x] **Posicionado al expandir**: los nodos nuevos se disponen en anillo
      alrededor del hub; no se relanza el layout completo.
- [x] **Tests**: colapso y expansión de artefactos de un hub; un artefacto
      compartido **no** se colapsa; los procesos **nunca** se colapsan.

### 3.3 Vecinos lazy / paginación — 🚧 PARCIAL

- [x] **Endpoint de vecindario** (base para la carga progresiva):
      `GET /api/graph/{id}/neighbors?element_id=…&depth=1..3`, con tope de
      `MAX_NEIGHBOR_NODES` (2000) y flag `truncated`.
      `backend/app/routers/graph.py`. Sigue disponible (sin usar por la UI).
- [x] **Botón "Reveal"** en Node Details (opción 1): vuelve a mostrar el
      vecindario a 1 salto que esté oculto por "Hide", los filtros de
      usuario/PID/evento, la búsqueda global o el foco. Es **client-side** (no
      llama al servidor) y actúa como "Unhide All" dirigido.
- [x] **Base reutilizable de fusión**: los elementos nuevos (clusters) se añaden
      con posiciones calculadas.
- [ ] **Carga inicial progresiva**: no enviar todo el grafo en datasets muy
      grandes; cargar raíces y expandir vecindario a demanda (reutilizando el
      endpoint y la fusión). Requiere rediseñar filtros y layout sobre un grafo
      parcial (pendiente).

---

## Detección de patrones sospechosos + risk score

**Estado:** planificado (sin implementar). Es la siguiente idea fuera del punto 3.

**Objetivo:** analizar el grafo ya construido y detectar patrones sospechosos
conocidos (LOLBins, ofuscación, inyección, persistencia, acceso a credenciales,
descubrimiento, escalada), produciendo una lista de hallazgos con severidad, MITRE
y evidencia, más un **risk score** agregado (0–100) por dataset y un riesgo por
nodo para colorearlo.

### Enfoque arquitectónico

- **Módulo nuevo y puro** `backend/app/analyzers/` que opera sobre el grafo ya
  construido (`nodes_dict` + `edges_list`), sin tocar HTTP ni raw logs: fácil de
  testear en aislamiento (como los tests puros de parsers).
  - `base.py`: dataclasses `Finding` y `Rule`, registro de reglas, y
    `analyze(graph) -> (risk_score, findings)`.
  - `rules/`: una regla por patrón (funciones puras).
  - `data/`: listas curadas versionables (LOLBins, rutas de persistencia,
    binarios de credenciales, patrones de command line).
- **Cálculo on-demand + reutilización del cache de grafos** (`graph_cache.py`):
  no se crea tabla nueva ni migración Alembic en v1.
- **La detección se deriva del grafo**, no de los raw logs; los artefactos y
  procesos ya exponen `group`, `process_name`, `actions` y `event_simplename`.
  Se respeta el invariante 8 (nada de raw logs en `elements`).

### Modelo de datos de entrada (ya disponible)

| Fuente | Campos usados | Para |
| --- | --- | --- |
| Nodo proceso | `process_name`, `label`, `username`, `hostname`, `actions[]` | LOLBins, credenciales, descubrimiento, escalada |
| Nodo artefacto | `group` (file/registry/network/module/powershell/commandline…), `label`, `title` | persistencia, ofuscación, cradle |
| Arista | `event_simplename`, `source`, `target`, `label` | inyección, persistencia, encadenamiento |

### Framework de reglas

- `Finding`: `rule_id`, `name`, `severity` (`low|medium|high|critical`),
  `description`, `node_ids`, `edge_ids`, `mitre` (táctica/técnica), `evidence`.
- `Rule`: `id`, `name`, `severity`, `matcher(graph) -> list[Finding]`,
  `references`.
- Registro declarativo: añadir una regla = un archivo + registro; sin tocar el
  endpoint.
- Los `evt_type`/`group` exactos de inyección y persistencia se **enumeran desde
  `defender.py`/`falcon.py`** (invariante 1: detección por campos, no por strings
  sueltos).

### Catálogo inicial de reglas

| # | Patrón | Señal en el grafo | Severidad |
| --- | --- | --- | --- |
| 1 | **LOLBin** (rundll32, mshta, regsvr32, certutil, msbuild, cscript, wscript, cmstp…) | `process_name` contra lista curada | alta |
| 2 | **PowerShell ofuscado** (`-enc`, `-command`, cradle de descarga) | artefacto `powershell`/`commandline` o `actions` del proceso | alta |
| 3 | **Inyección** (CreateRemoteThread / módulo en otro proceso) | arista con `event_simplename` de inyección entre 2 procesos | crítica |
| 4 | **Persistencia** (Run/RunOnce, ScheduledTask, schtasks, startup) | artefacto `registry` con ruta de arranque o arista `ScheduledTaskModified` | alta |
| 5 | **Acceso a credenciales** (lsass, mimikatz, dump) | `process_name`/`commandline` contra lista | crítica |
| 6 | **Descubrimiento** (whoami, net view, nltest, adfind) | `process_name`/`commandline` | media |
| 7 | **Escalada / UAC bypass** | eventos concretos + combinación de procesos | alta |

### Risk score

- Peso por severidad (baja/media/alta/crítica) → score agregado normalizado
  **0–100** con tope, fórmula determinista y documentada.
- **Score por nodo** para colorear procesos/artefactos implicados (aro/brillo).

### API

- `GET /api/graph/{id}/detections` → `{ risk_score, findings[] }` (requiere auth,
  como el resto de rutas de datos).
- `risk_score` ligero incluido en el payload principal para pintar un badge sin
  esperar al endpoint.
- Detalle de evidencia reutilizando `/api/graph/{id}/element-logs` (no duplicar raw
  logs).

### Frontend

- Panel **"Detections"** con hallazgos ordenados por severidad; click → enfoca y
  resalta los nodos implicados en el grafo.
- Aro rojo/naranja en nodos con riesgo; **badge** con el risk score en la cabecera
  del dataset.
- Toggle para mostrar/ocultar el resaltado.

### Configuración

- Toggle `DETECTIONS_ENABLED` (por defecto activo).
- Listas curadas en `backend/app/analyzers/data/` (editables sin tocar código).
- Pesos de severidad y umbral documentados en el módulo.

### Testing

- Tests puros por regla: grafo sintético que **dispara** y que **no dispara** cada
  patrón (fixture `GraphBuilder` reutilizable).
- Tests HTTP del endpoint: auth, grafo vacío, grafo con hallazgos.
- Sin fallar por los warnings de `react` tolerados del frontend.

### Orden de implementación

1. `base.py` + `data/` (listas curadas).
2. Reglas + tests puros.
3. Endpoint + schema + integración con el cache.
4. Panel frontend + resaltado + badge.
5. Docs (`AGENTS.md`, `README.md`) y tildar esta sección.

### Decisiones por defecto (a confirmar)

1. **Fuente de conocimiento:** listas curadas embebidas + data files versionables
   (recomendado), ampliable a archivos configurables.
2. **Persistencia:** on-demand + cache, sin tabla ni migración (recomendado) vs.
   tabla `detections` con historial/auditoría.
3. **Score:** índice agregado 0–100 (recomendado) además de severidad por
   hallazgo.
4. **Reglas iniciales:** empezar por **LOLBins + inyección + persistencia** y
   crecer (vs. las 7 de golpe).
5. **UI:** panel lateral + badge/coloreado (recomendado) vs. solo colorear nodos.

### Ficheros previstos

- Nuevos: `backend/app/analyzers/{base.py,rules/,data/}`,
  `backend/tests/test_analyzers.py`.
- Modificados: `backend/app/routers/graph.py`, `backend/app/schemas.py`,
  `frontend/src/api/client.js`, `frontend/src/components/GraphView.jsx`
  (panel/leyenda), posiblemente `frontend/src/components/NodeDetails…` y
  `.env.example`, `README.md`, `AGENTS.md`.

---

## Fuzzing de parsers con Hypothesis — ✅ HECHO

**Estado:** implementado. Suite de tests *property-based* añadida; el fuzzing ya
destapó y arregló un bug real de codificación (ver "Resultado").

**Objetivo:** garantizar con tests *property-based* que el pipeline de parsing
(puro, sin HTTP ni DB) es robusto ante cualquier entrada y que los invariantes del
grafo se mantienen siempre. Busca dos propiedades:

1. **Nunca crashea** con excepciones no esperadas ante eventos desconocidos, tipos
   raros (`None`, int, listas), JSON roto o bytes corruptos.
2. **El grafo sale íntegro:** serializable a JSON, ids únicos, sin aristas
   colgantes y sin colapsar procesos.

**Qué resuelve (valor):**

- **Crashes por tipos inesperados** que hoy serían un 500 (p. ej. `ImageFileName`
  no-str y `.split()` en `falcon.py`).
- **JSON/CSV malformado** que no se traduce a un `HTTPException` 400/413 limpio
  (p. ej. `csv.Error`, `UnicodeDecodeError` sin capturar).
- **Invariantes del grafo** que nadie comprueba de forma exhaustiva: ids únicos,
  sin colisión nodo/arista, sin aristas a nodos inexistentes, clustering no
  destructivo.
- **Seguridad/disponibilidad:** los parsers consumen ficheros subidos por el
  usuario; un input que provoque excepción no controlada o consumo desmedido es un
  vector de DoS.
- **Red de seguridad permanente** en CI contra regresiones al añadir vendors o
  tipos de evento con accesos no defensivos.

### Targets (funciones puras) y su oráculo

| Target | Entrada fuzzeada | Invariante a verificar |
| --- | --- | --- |
| `vendor.get_vendor` / `extract_event_type` / `is_falcon_event` | `Any` (dict, list, `None`, int…) | no lanzan; solo constantes conocidas |
| `builder.get_additional_fields_dict` | dict con `AdditionalFields` anidado/JSON | no lanza; devuelve `dict` |
| `builder.hash_str` / `string_hash` | `str` / `Any` | no lanzan; hex de longitud fija |
| `defender.parse_defender_event` / `falcon.parse_falcon_event` | `event` JSON-like + `evt_type` + ids (`None`/int/str) | no lanzan; el grafo posterior es JSON-serializable |
| `builder.GraphBuilder.build_cytoscape_elements` | builder poblado por los pasos anteriores | `json.dumps` OK; ids de nodo y arista únicos y disjuntos; toda arista apunta a un nodo existente |
| `builder.GraphBuilder._plan_clusters` | builder con muchos artefactos/procesos | solo colapsa `group != "process"`; procesos y aristas `Spawns` permanecen |
| `datasets._parse_csv_rows` / `_parse_json_rows` / `_detect_encoding_and_check_size` | `bytes` arbitrarios | solo `HTTPException` 400/413, nunca otra excepción |

### Estrategias de Hypothesis (compartidas)

`backend/tests/strategies.py`:

- `json_value`: `st.recursive` con `none`/`bool`/`int`/`float`/`text` + listas y
  dicts anidados (para `event`).
- `event_dict`: `st.dictionaries(st.text(), json_value, max_size=30)`.
- `event_type`: mezcla de `st.sampled_from(KNOWN_*_TYPES)` (para ejercitar las
  ramas reales) + `st.text()` (robustez ante desconocidos).
- `element_id`: `st.one_of(st.none(), st.text(), st.integers())`.
- Bytes: `st.binary(max_size=4096)` más prefijos que fuercen BOM, latin-1 y JSON
  roto.

### Oráculos y estructura de tests

- Helper reutilizable `_assert_graph_invariants(payload)` (ids únicos, disjuntos,
  sin aristas colgantes, clustering no destructivo).
- Archivos nuevos:
  - `backend/tests/strategies.py`
  - `backend/tests/test_fuzz_vendor.py`
  - `backend/tests/test_fuzz_builder.py`
  - `backend/tests/test_fuzz_defender.py`
  - `backend/tests/test_fuzz_falcon.py`
  - `backend/tests/test_fuzz_upload.py`

### Integración y CI

- Añadir `hypothesis` a `backend/requirements-dev.txt` (no a runtime).
- Perfil determinista en `backend/tests/conftest.py` para evitar flakiness:
  `max_examples=150`, `deadline=None`, `derandomize=True`, y desactivar los health
  checks `too_slow`/`data_too_large`.
- Hypothesis se integra con pytest; no hay conflicto con `ruff` (los decoradores
  `@given`/`@settings` no son `B008`).

### Checklist (orden aplicado)

- [x] `strategies.py` (`json_value`, `event_dict`, `graph_id`/`optional_id`,
      `event_type_strategy`, `DEFENDER_/FALCON_EVENT_TYPES`) + helper
      `assert_graph_invariants`.
- [x] Fuzz de `vendor.py` y `builder.py` (hashes con valores no hashables,
      `get_additional_fields_dict`, invariantes de `build_cytoscape_elements`).
- [x] Fuzz de `parse_defender_event` / `parse_falcon_event` + invariantes del grafo.
- [x] Fuzz de helpers de `datasets.py` (bytes) + 3 regresiones dirigidas.
- [x] `hypothesis` en `requirements-dev.txt` + perfil `ci` en `conftest.py`.
- [x] Endurecer el pipeline ante lo que afloró (ver abajo).
- [x] Docs (`AGENTS.md` → Testing) y tildar la línea del `TODO`.

### Resultado

`python -m pytest -q` → **81 tests OK** (antes 69) y `ruff check` limpio.

Bugs/endurecimientos que el fuzzing motivó:

- **UTF-8 truncado mal detectado** (bug encontrado por Hypothesis con `b"\xc2"`):
  `_detect_encoding_and_check_size` no finalizaba el decoder incremental, así que
  una secuencia multibyte incompleta al final del fichero se daba por válida como
  `utf-8-sig` y reventaba al decodificar. Ahora se hace
  `decoder.decode(b"", final=True)` y se cae a latin-1. Regresión en
  `test_fuzz_upload.py`.
- **`hash_str` / `string_hash`** toleran valores no hashables (dicts/listas):
  coercionan a `str` *antes* del `lru_cache`.
- **Parsers**: los campos de evento pasan por `as_text()` allí donde se usan como
  texto (`.split`, `.replace`, `textwrap.fill`, slicing), de modo que un campo
  `None`/número/lista no lanza.
- **`build_cytoscape_elements` / `extract_event_type`**: tipo de retorno siempre
  serializable / texto.
- **Subida**: `csv.Error` (campo > `field_size_limit`) y `RecursionError` (JSON
  muy anidado) se traducen a 400; `stream.detach()` tolera streams ya cerrados.

### Desviaciones del plan original

- El helper se llama `assert_graph_invariants` (no `_assert_graph_invariants`).
- Los ids usan `graph_id`/`optional_id`: incluyen enteros y `None`, y excluyen el
  prefijo `edge_` (namespace reservado a las aristas).
- Bytes `st.binary(max_size=2048)` (suficiente; el campo gigante de CSV y el JSON
  profundamente anidado se cubren con regresiones dirigidas).

---

## Timeline / vista cronológica con reproducción — ✅ HECHO

**Estado:** implementado. Vista de línea temporal con reproducción y enlace al
grafo.

**Objetivo:** ver los eventos del dataset en orden cronológico y reproducir la
secuencia (play/pausa, velocidad, scrubber), con filtros y salto al elemento en
el grafo.

### Backend

- [x] **Timestamp normalizado**: `LogEvent.event_time` (epoch ms, nullable) +
      migración `0004_add_event_time`. Se rellena en el upload con
      `extract_timestamp` (`app/parsers/timestamps.py`), que entiende epoch
      segundos/ms y ISO-8601, con campos de Falcon (`timestamp`) y Defender
      (`Timestamp`/`EventTime`/…). Sin timestamp → `NULL` (orden de inserción).
- [x] **Descripción de evento compartida**: `describe_event`
      (`app/parsers/events.py`) extrae actor/target/usuario/host por vendor; lo
      usan el grafo y la timeline (mismo criterio de campos, invariante 1).
- [x] **Endpoint**: `GET /api/graph/{id}/timeline?offset&limit&event_type&q&from&to`
      (auth), paginado, orden `event_time NULLS LAST, id`. Devuelve entradas
      compactas (hora, tipo, vendor, resumen, ids de elemento best-effort), nunca
      raw logs (invariante 11).

### Frontend

- [x] **`TimelineView.jsx`**: lista cronológica con reproducción (play/pausa,
      velocidad 0.5×–8×, scrubber, siguiente/anterior), búsqueda y filtro por
      tipo de evento, y "Load more" (paginado).
- [x] **Selector Grafo/Timeline** en `App.jsx`; al pulsar un evento se salta al
      grafo y se enfoca el elemento (`focusElementId` → `GraphView`).
- [x] **`api.getTimeline`** en `frontend/src/api/client.js` (única vía de API).

### Configuración

- Sin variables nuevas obligatorias: `TIMELINE_DEFAULT_LIMIT` (200) y
  `TIMELINE_MAX_LIMIT` (1000) son constantes del router.

### Testing

- `backend/tests/test_timestamps.py` (epoch s/ms, ISO con/sin zona, `None`).
- `backend/tests/test_timeline.py` (orden con undated al final, paginación,
  filtros, 404).
- Frontend: `npm run lint` (0 errores) + `npm run build` OK.

### Pendiente / ideas (follow-up)

- [ ] Mapeo completo evento→elemento (hoy solo procesos vía PID); enlazar
      artefactos (files/registry/network) requiere que el builder registre el id
      por evento.
- [ ] Backfill de `event_time` para datasets subidos antes de la migración
      `0004` (hoy caen a orden de inserción).
- [ ] Filtro por rango temporal en la UI (el endpoint ya acepta `from`/`to`).
- [ ] Reproducción que resalte en el grafo en tiempo real sin cambiar de vista.
- [ ] Agrupar/colapsar eventos repetidos y "saltar al siguiente evento del mismo
      proceso".

---

## Revisión / correcciones (post-revisión) — 🟡 EN CURSO

**Estado:** revisión completa del proyecto. Corregidos los bugs confirmados 1–3
(crashes y duplicación de datos); el 4 queda pendiente de decisión por su impacto
en ids/layouts.

### Bugs confirmados y corregidos

- [x] **`extract_timestamp` no era seguro ante `NaN`/`Infinity`/desbordes**
      (`app/parsers/timestamps.py`). Un JSON con `NaN`/`Infinity` (que
      `json.loads` acepta) o un número gigante lanzaba `ValueError`/
      `OverflowError` al extraer el timestamp de **cada fila**, rompiendo el
      upload completo con 500 y dejando un dataset huérfano. Ahora se valida
      `math.isfinite` y un rango plausible (≤ 9999-12-31); no finito o fuera de
      rango → `None`. Regresiones en `test_timestamps.py` y `test_timeline.py`
      (upload con `NaN`).
- [x] **`RegValueName` numérico en Falcon crasheaba** (`app/parsers/falcon.py`):
      `len(raw_reg)` sobre un `int` → `TypeError`. Se aplica `as_text()` como al
      resto de campos. Regresión en `test_parsers_smoke.py`.
- [x] **Clusters duplicaban artefactos repetidos** (`_plan_clusters`,
      `app/parsers/builder.py`): un hub con varias aristas al mismo artefacto
      generaba `members` con duplicados, inflaba el umbral y producía nodos
      repetidos al expandir (aunque `clusterCount` los contaba una vez). Se
      deduplica preservando el orden. Regresión en `test_builder.py`.

### Mejora menor aplicada

- [x] `pool_pre_ping=True` en `create_engine` (`app/database.py`) para evitar
      conexiones stale tras un reinicio de Postgres.

### Pendiente (requiere decisión)

- [ ] **Id de proceso compuesto por host + PID** (`get_or_create_process_node`).
      Hoy la clave del nodo es solo `str(pid)`, así que el mismo PID en dos hosts
      distintos colisiona y se pierde el segundo proceso (habitual en exports
      multi-host de Defender/Falcon). Componer el id con el hostname cambiaría
      los ids (invariante 2), invalidaría layouts guardados y obligaría a ajustar
      `element_ids` de la timeline; conviene planificarlo con migración.

### Recomendaciones no aplicadas (bajo impacto)

- [ ] Extraer la constante `"Unknown"` duplicada en `events.py`/parsers.
- [ ] JSON leniente: `_parse_json_rows` acepta comas ausentes y basura tras el
      objeto; valorar modo estricto o contabilizar líneas malformadas.
- [ ] Cache de grafo por-proceso (`graph_cache`): no se comparte con
      `--workers N`; documentado, revisar si se escala.
- [ ] Sin token CSRF (mitigado por allowlist CORS + `SameSite=lax` + httpOnly).

### Testing

- [x] `backend/tests/` pasa a **98 tests** (regresiones de los 3 bugs); `ruff`
      limpio. Sin cambios de frontend.

---

## Pendiente / ideas siguientes (fuera del punto 3)

- [x] **Timeline / vista cronológica** con reproducción de la secuencia de
      eventos — hecho (sección homónima de arriba).
- [~] **Revisión de código / correcciones** — 3 bugs corregidos, 1 pendiente
      (sección homónima de arriba).
- [ ] **Mapeo MITRE ATT&CK** por evento (táctica/técnica) y filtro por técnica.
- [ ] **Detección de patrones sospechosos** (LOLBins, inyección, persistencia) y
      risk score — plan detallado en la sección homónima de arriba.
- [ ] **Pivoting**: expandir padres/hijos, aislar subárbol, ruta más corta entre
      dos nodos.
- [ ] **Dashboard de estadísticas** (top procesos, hosts/usuarios, tipos de evento).
- [ ] **Búsqueda con operadores** (`type:process host:foo`) y guardar vistas.
- [ ] **Exportar** grafo a PNG/SVG/JSON y lista filtrada a CSV.
- [ ] **Nuevos vendors**: Sysmon, SentinelOne, Carbon Black, auditd.
- [ ] **Tests de frontend** (Vitest + Testing Library) y E2E (Playwright).
- [x] **Fuzzing de parsers** (Hypothesis) — hecho (sección homónima de arriba).
- [ ] **`/api/health`** y métricas básicas.
- [ ] **Audit log** de acciones (login, upload, delete).
- [ ] (Opcional) **Rate limiting** en login y cabeceras de seguridad.
- [ ] (Roadmap) **Multi-usuario** con datasets por usuario o compartidos.

---

## Cómo ejecutar lo añadido

```bash
# Backend (Docker; pytest no está en la imagen de runtime)
docker run --rm -v "<ruta>/backend:/app" -w /app \
  -e DATABASE_URL=sqlite:// -e SECRET_KEY=test-secret-key edr-analyzer-backend \
  sh -c "pip install -q -r requirements-dev.txt && ruff check . && python -m pytest -q"

# Frontend
cd frontend && npm run lint && npm run build
```

`CLUSTER_MIN_CHILDREN` (por defecto `50`; `0` desactiva) controla cuántos
descendientes exclusivos hacen falta para colapsar un hub.
