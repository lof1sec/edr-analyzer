import assert from 'node:assert/strict';
import test from 'node:test';
import { mergeEventTypeSelection, setCatalogEventTypes } from '../src/components/eventTypeCatalog.js';

test('refresh preserves hidden types and enables newly available types', () => {
  const previous = { ProcessCreated: false, OldType: false };
  const catalog = ['ProcessCreated', 'DeviceProcessEvents'];
  assert.deepEqual(mergeEventTypeSelection(previous, catalog), {
    ProcessCreated: false,
    OldType: false,
    DeviceProcessEvents: true,
  });
  assert.deepEqual(setCatalogEventTypes(previous, catalog, true), {
    ProcessCreated: true,
    OldType: false,
    DeviceProcessEvents: true,
  });
});
