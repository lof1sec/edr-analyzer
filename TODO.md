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

## Pendiente / ideas siguientes (fuera del punto 3)

- [ ] **Timeline / vista cronológica** con reproducción de la secuencia de eventos.
- [ ] **Mapeo MITRE ATT&CK** por evento (táctica/técnica) y filtro por técnica.
- [ ] **Detección de patrones sospechosos** (LOLBins, inyección, persistencia) y
      risk score.
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
