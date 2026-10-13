import assert from 'node:assert/strict';
import test from 'node:test';

import { nextPlaybackCursor, shouldPrefetchTimeline } from '../src/components/timelinePlayback.js';

test('playback waits for the graph to highlight the current event', () => {
  const entries = [{ id: 10 }, { id: 11 }];
  assert.equal(nextPlaybackCursor(0, entries, null), 0);
  assert.equal(nextPlaybackCursor(0, entries, 11), 0);
  assert.equal(nextPlaybackCursor(0, entries, 10), 1);
  assert.equal(nextPlaybackCursor(1, entries, 11), 1);
});

test('playback prefetches at a page boundary but not after the final page', () => {
  assert.equal(shouldPrefetchTimeline(494, 500, 1000), false);
  assert.equal(shouldPrefetchTimeline(495, 500, 1000), true);
  assert.equal(shouldPrefetchTimeline(499, 500, 500), false);
  assert.equal(shouldPrefetchTimeline(0, 0, 1000), false);
});
