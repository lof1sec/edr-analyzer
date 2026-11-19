import assert from 'node:assert/strict';
import test from 'node:test';
import { collapseClustersInElements, getClusterSummary } from '../src/components/clusterControls.js';

test('getClusterSummary reports expand, collapse, and none states', () => {
  const none = getClusterSummary([{ data: { id: 'p1', group: 'process' } }], {});
  assert.equal(none.hasClusters, false);
  assert.equal(none.nextAction, 'none');

  const collapsed = getClusterSummary([
    { data: { id: 'p1', group: 'process' } },
    { data: { id: 'cluster_p1', isCluster: true, clusterCount: 60 } },
    { data: { id: 'cluster_edge_p1', source: 'p1', target: 'cluster_p1' } },
    { data: { id: 'cluster_p2', isCluster: true, clusterCount: 75 } },
  ], {});
  assert.equal(collapsed.hasClusters, true);
  assert.equal(collapsed.collapsedClusterCount, 2);
  assert.equal(collapsed.collapsedNodeCount, 135);
  assert.equal(collapsed.nextAction, 'expand');

  const expanded = getClusterSummary(
    [{ data: { id: 'p1', group: 'process' } }],
    { cluster_p1: { memberIds: ['n1', 'n2'], memberEdgeIds: ['e1', 'e2'] } },
  );
  assert.equal(expanded.hasClusters, true);
  assert.equal(expanded.expandedClusterCount, 1);
  assert.equal(expanded.expandedNodeCount, 2);
  assert.equal(expanded.nextAction, 'collapse');
});

test('collapseClustersInElements removes expanded members and restores placeholders without duplicates', () => {
  const clusterNode = { data: { id: 'cluster_p1', isCluster: true, clusterCount: 2 }, position: { x: 10, y: 20 } };
  const clusterEdge = { data: { id: 'cluster_edge_p1', source: 'p1', target: 'cluster_p1' } };
  const elements = [
    { data: { id: 'p1', group: 'process' } },
    { data: { id: 'n1', group: 'network' } },
    { data: { id: 'n2', group: 'network' } },
    { data: { id: 'e1', source: 'p1', target: 'n1' } },
    { data: { id: 'e2', source: 'p1', target: 'n2' } },
  ];
  const { elements: next, removedIds } = collapseClustersInElements(elements, [
    { node: clusterNode, edge: clusterEdge, memberIds: ['n1', 'n2'], memberEdgeIds: ['e1', 'e2'] },
  ]);
  assert.deepEqual(next.map(el => el.data.id), ['p1', 'cluster_p1', 'cluster_edge_p1']);
  assert.deepEqual(next[1].position, { x: 10, y: 20 });
  assert.equal(removedIds.has('n1'), true);
  assert.equal(removedIds.has('e2'), true);

  // Calling again if placeholder is already present does not duplicate it.
  const second = collapseClustersInElements(next, [
    { node: clusterNode, edge: clusterEdge, memberIds: ['n1', 'n2'], memberEdgeIds: ['e1', 'e2'] },
  ]);
  assert.deepEqual(second.elements.map(el => el.data.id), ['p1', 'cluster_p1', 'cluster_edge_p1']);
});
