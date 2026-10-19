import test from 'node:test';
import assert from 'node:assert/strict';
import { isDefenderReportedBy, hiddenDefenderElements } from '../src/components/defenderEdges.js';

const nodes = new Map([
  ['p', { data: { group: 'process' } }],
  ['defender_event_42', { data: { group: 'event' } }],
  ['falcon', { data: { group: 'event' } }],
]);

test('only Defender process-to-observation reporting edges are visually muted', () => {
  const edge = (source, target, label) => ({ data: { source, target, label } });
  assert.equal(isDefenderReportedBy(edge('p', 'defender_event_42', 'Reported by'), nodes), true);
  assert.equal(isDefenderReportedBy(edge('p', 'falcon', 'Reported by'), nodes), false);
  assert.equal(isDefenderReportedBy(edge('p', 'defender_event_42', 'Spawns'), nodes), false);
  assert.equal(isDefenderReportedBy(edge('falcon', 'defender_event_42', 'Reported by'), nodes), false);
});

test('suppresses Defender observations and exclusive context, preserving shared and unrelated nodes', () => {
  const node = (id, group) => ({ data: { id, group } });
  const edge = (id, source, target, label = 'Uses') => ({ data: { id, source, target, label } });
  const graph = [node('p', 'process'), node('defender_event_1', 'event'),
    node('defender_event_2', 'event'), node('orphan_event', 'event'),
    node('exclusive', 'file'), node('shared', 'file'), node('falcon', 'event'),
    edge('r1', 'p', 'defender_event_1', 'Reported by'),
    edge('r2', 'p', 'defender_event_2', 'Reported by'),
    edge('context', 'defender_event_1', 'exclusive'),
    edge('shared1', 'defender_event_1', 'shared'), edge('shared2', 'falcon', 'shared')];
  const hidden = hiddenDefenderElements(graph);
  for (const id of ['defender_event_1', 'defender_event_2', 'r1', 'r2', 'context', 'shared1', 'exclusive']) {
    assert.ok(hidden.has(id), id);
  }
  for (const id of ['p', 'orphan_event', 'falcon', 'shared', 'shared2']) assert.ok(!hidden.has(id), id);
  assert.ok(!hiddenDefenderElements(graph, { selectedId: 'p' }).size);
  assert.ok(!hiddenDefenderElements(graph, { show: true }).size);
  const playing = hiddenDefenderElements(graph, { playbackId: 'defender_event_1' });
  assert.ok(!playing.has('defender_event_1'));
  assert.ok(!playing.has('exclusive'));
  assert.ok(playing.has('defender_event_2'));
});
