// Defender observation nodes have a dedicated, stable ID namespace. Checking
// both endpoints avoids hiding unrelated edges (including Falcon labels).
export function isDefenderReportedBy(edge, nodesById) {
  const data = edge.data;
  return data.label === 'Reported by' &&
    data.target?.startsWith('defender_event_') &&
    nodesById.get(data.target)?.data.group === 'event' &&
    nodesById.get(data.source)?.data.group === 'process';
}

// Presentation-only suppression. Keep the graph intact for search, layout and
// timeline; prune context nodes only when every incident edge is suppressed.
export function hiddenDefenderElements(elements, { show = false, selectedId = null, playbackId = null } = {}) {
  if (show) return new Set();
  const nodes = new Map(elements.filter(el => !el.data.source).map(el => [el.data.id, el]));
  const edges = elements.filter(el => el.data.source);
  const incidentEdges = new Map();
  for (const edge of edges) {
    for (const id of [edge.data.source, edge.data.target]) {
      if (!incidentEdges.has(id)) incidentEdges.set(id, []);
      incidentEdges.get(id).push(edge);
    }
  }
  const reports = edges.filter(edge => isDefenderReportedBy(edge, nodes));
  const hiddenEvents = new Set(reports.map(edge => edge.data.target));
  const revealed = new Set([selectedId, playbackId]);
  for (const edge of reports) {
    if (revealed.has(edge.data.source) || revealed.has(edge.data.target) ||
        revealed.has(edge.data.id)) hiddenEvents.delete(edge.data.target);
  }
  const hidden = new Set(hiddenEvents);
  for (const edge of edges) {
    if (hiddenEvents.has(edge.data.source) || hiddenEvents.has(edge.data.target)) hidden.add(edge.data.id);
  }
  // Context artifacts attached exclusively to suppressed observations would
  // otherwise appear as disconnected islands. Never prune a shared artifact.
  let changed;
  do {
    changed = false;
    for (const [id, node] of nodes) {
      if (hidden.has(id) || node.data.group === 'process' || node.data.group === 'event') continue;
      const incident = incidentEdges.get(id) || [];
      if (incident.length && incident.every(edge => hidden.has(edge.data.id))) {
        hidden.add(id);
        changed = true;
      }
    }
    for (const edge of edges) {
      if (!hidden.has(edge.data.id) && (hidden.has(edge.data.source) || hidden.has(edge.data.target))) {
        hidden.add(edge.data.id);
        changed = true;
      }
    }
  } while (changed);
  return hidden;
}
