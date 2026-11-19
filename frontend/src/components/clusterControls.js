export function getClusterSummary(elements, expandedClusters = {}) {
  const collapsedClusters = elements.filter(el => !el.data?.source && el.data?.isCluster);
  const collapsedNodeCount = collapsedClusters.reduce(
    (sum, el) => sum + (Number(el.data?.clusterCount) || 0),
    0,
  );
  const expandedList = Object.values(expandedClusters);
  const expandedNodeCount = expandedList.reduce(
    (sum, info) => sum + (info?.memberIds?.length || 0),
    0,
  );
  const collapsedClusterCount = collapsedClusters.length;
  const expandedClusterCount = expandedList.length;
  const nextAction = collapsedClusterCount > 0
    ? 'expand'
    : expandedClusterCount > 0
      ? 'collapse'
      : 'none';

  return {
    collapsedClusters,
    collapsedClusterCount,
    collapsedNodeCount,
    expandedClusterCount,
    expandedNodeCount,
    hasClusters: collapsedClusterCount > 0 || expandedClusterCount > 0,
    nextAction,
  };
}

export function collapseClustersInElements(elements, clusterInfos) {
  const memberIds = new Set();
  const restored = [];
  clusterInfos.forEach(info => {
    if (!info) return;
    (info.memberIds || []).forEach(id => memberIds.add(id));
    (info.memberEdgeIds || []).forEach(id => memberIds.add(id));
    if (info.node) restored.push(info.node);
    if (info.edge) restored.push(info.edge);
  });

  const kept = elements.filter(el => !memberIds.has(el.data?.id));
  const seen = new Set(kept.map(el => el.data?.id));
  restored.forEach(el => {
    if (el?.data?.id && !seen.has(el.data.id)) {
      kept.push(el);
      seen.add(el.data.id);
    }
  });
  return { elements: kept, removedIds: memberIds };
}
