// Never skip a timeline event while its graph element is still loading.
export function nextPlaybackCursor(cursor, entries, readyEventId) {
  if (entries[cursor]?.id !== readyEventId) return cursor;
  return Math.min(cursor + 1, entries.length - 1);
}

// Request the next page before reaching the end of the loaded sequence.
export function shouldPrefetchTimeline(cursor, loaded, total) {
  return loaded > 0 && loaded < total && cursor >= loaded - 5;
}
