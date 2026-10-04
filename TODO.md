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

## Pendiente / ideas siguientes (fuera del punto 3)

- [ ] **Timeline / vista cronológica** con reproducción de la secuencia de eventos.
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
- [ ] **Fuzzing de parsers** (Hypothesis).
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
