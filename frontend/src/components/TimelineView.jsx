import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { Clock, Play, Pause, Search, SkipBack, SkipForward, Network } from 'lucide-react';
import { api } from '../api/client';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import EmptyState from './EmptyState';
import { nextPlaybackCursor, shouldPrefetchTimeline } from './timelinePlayback';

const PAGE_SIZE = 500;

const SPEEDS = [
  { label: '0.5×', ms: 1600 },
  { label: '1×', ms: 800 },
  { label: '2×', ms: 400 },
  { label: '4×', ms: 200 },
  { label: '8×', ms: 100 },
];

const VENDOR_DOT = {
  falcon: 'bg-red-500',
  defender: 'bg-blue-500',
  unknown: 'bg-slate-400',
};

function formatTime(iso) {
  if (!iso) return 'no timestamp';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

function hiddenFilterKey(filters) {
  return JSON.stringify(Object.keys(filters).filter(key => filters[key] === false).sort());
}

/**
 * Chronological timeline of a dataset's events with playback.
 *
 * Playback advances through mapped events and highlights the current element in
 * the graph kept alongside the list. Fetches additional pages as needed.
 */
export default function TimelineView({ datasetId, graphFilters, onSelectElement, playbackReadyId, playbackError }) {
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speedMs, setSpeedMs] = useState(SPEEDS[1].ms);
  const [q, setQ] = useState('');
  const [eventType, setEventType] = useState('');

  const debouncedQ = useDebouncedValue(q, 250);
  const activeRowRef = useRef(null);
  const requestKey = useRef(null);
  const highlightedEntryRef = useRef(null);
  const hiddenEventTypesKey = useMemo(() => hiddenFilterKey(graphFilters.eventTypes), [graphFilters.eventTypes]);
  const hiddenUsersKey = useMemo(() => hiddenFilterKey(graphFilters.users), [graphFilters.users]);
  const hiddenPidsKey = useMemo(() => hiddenFilterKey(graphFilters.pids), [graphFilters.pids]);
  const graphQuery = graphFilters.globalSearch.trim();
  const graphParams = useMemo(() => ({
    from: graphFilters.rangeFrom, to: graphFilters.rangeTo, graphQ: graphQuery,
    hiddenEventTypes: JSON.parse(hiddenEventTypesKey),
    hiddenUsers: JSON.parse(hiddenUsersKey),
    hiddenPids: JSON.parse(hiddenPidsKey),
  }), [graphFilters.rangeFrom, graphFilters.rangeTo, graphQuery,
    hiddenEventTypesKey, hiddenUsersKey, hiddenPidsKey]);

  useEffect(() => {
    if (!datasetId) {
      setEntries([]);
      setTotal(0);
      highlightedEntryRef.current = null;
      onSelectElement(null);
      return;
    }
    let cancelled = false;
    const key = JSON.stringify([datasetId, eventType, debouncedQ, graphParams]);
    requestKey.current = key;
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    setPlaying(false);
    highlightedEntryRef.current = null;
    onSelectElement(null);
    api.getTimeline(datasetId, { ...graphParams, offset: 0, limit: PAGE_SIZE, eventType, q: debouncedQ })
      .then((res) => {
        if (cancelled) return;
        setEntries(res.entries || []);
        setTotal(res.total || 0);
        setCursor(0);
      })
      .catch((err) => {
        if (!cancelled) setError(err?.message || 'Failed to load the timeline.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; if (requestKey.current === key) requestKey.current = null; };
  }, [datasetId, eventType, debouncedQ, graphParams, onSelectElement]);

  // Auto-advance the cursor while playing.
  useEffect(() => {
    if (!playing || entries.length === 0) return undefined;
    const interval = setInterval(() => {
      setCursor((prev) => nextPlaybackCursor(prev, entries, playbackReadyId));
    }, speedMs);
    return () => clearInterval(interval);
  }, [playing, speedMs, entries, playbackReadyId]);

  useEffect(() => {
    if (playbackError) setPlaying(false);
  }, [playbackError]);

  // Stop only at the end of *all* filtered events, not at a page boundary.
  useEffect(() => {
    if (playing && total > 0 && entries.length >= total && cursor >= total - 1) {
      setPlaying(false);
    }
  }, [playing, cursor, entries.length, total]);

  // Keep the active row in view during playback.
  useEffect(() => {
    if (activeRowRef.current) {
      activeRowRef.current.scrollIntoView({ block: 'nearest' });
    }
  }, [cursor]);

  const loadMore = useCallback(async () => {
    if (!datasetId || loadingMore || entries.length >= total) return;
    const key = JSON.stringify([datasetId, eventType, debouncedQ, graphParams]);
    setLoadingMore(true);
    try {
      const res = await api.getTimeline(datasetId, {
        offset: entries.length,
        limit: PAGE_SIZE,
        eventType,
        q: debouncedQ,
        ...graphParams,
      });
      if (requestKey.current !== key) return;
      setEntries((prev) => [...prev, ...(res.entries || [])]);
      setTotal(res.total || 0);
    } catch (err) {
      if (requestKey.current === key) {
        setPlaying(false);
        setError(err?.message || 'Failed to load more events.');
      }
    } finally {
      if (requestKey.current === key) setLoadingMore(false);
    }
  }, [datasetId, entries.length, total, loadingMore, eventType, debouncedQ, graphParams]);

  // Prefetch the next page before playback reaches its end. If the request is
  // slower than the selected speed, the cursor waits for it rather than stopping.
  useEffect(() => {
    if (playing && !loading && !loadingMore &&
        shouldPrefetchTimeline(cursor, entries.length, total)) {
      loadMore();
    }
  }, [playing, loading, loadingMore, cursor, entries.length, total, loadMore]);

  useEffect(() => {
    const entry = !loading ? entries[cursor] : null;
    if (entry && highlightedEntryRef.current !== entry.id) {
      highlightedEntryRef.current = entry.id;
      onSelectElement(entry);
    }
  }, [cursor, entries, loading, onSelectElement]);

  const focusEntry = useCallback((entry) => {
    setCursor(entry.index);
    if (entry.focus_element_id && onSelectElement) {
      highlightedEntryRef.current = entry.id;
      onSelectElement(entry);
    }
  }, [onSelectElement]);

  const eventTypeOptions = useMemo(() => {
    const types = new Set();
    entries.forEach((entry) => { if (entry.event_type) types.add(entry.event_type); });
    return Array.from(types).sort();
  }, [entries]);

  if (!datasetId) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <EmptyState
          icon={Network}
          title="No dataset selected"
          description="Select a dataset from the sidebar or upload a CSV export to view its timeline."
        />
      </div>
    );
  }

  return (
      <div className="h-full flex-1 min-w-0 min-h-0 flex flex-col bg-white dark:bg-slate-900">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-slate-200 dark:border-slate-700">
        <Clock size={16} className="text-slate-500 dark:text-slate-400" />
        <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Timeline</span>
        <span className="text-xs text-slate-400 dark:text-slate-500">{total} events</span>
        {(graphParams.from != null || graphParams.to != null || graphParams.graphQ ||
          graphParams.hiddenEventTypes.length || graphParams.hiddenUsers.length || graphParams.hiddenPids.length) ? (
          <span className="text-[10px] text-blue-600 dark:text-blue-400" title="The timeline follows the graph's time range, search and identity filters">
            Graph filters applied
          </span>
        ) : null}
        <div className="flex-1" />
        <div className="relative">
          <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search events…"
            aria-label="Search events"
            className="pl-7 pr-2 py-1.5 w-56 text-xs bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded outline-none focus:border-blue-500"
          />
        </div>
        <input
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          placeholder="Event type"
          list="timeline-event-types"
          aria-label="Filter by event type"
          className="px-2 py-1.5 w-40 text-xs bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded outline-none focus:border-blue-500"
        />
        <datalist id="timeline-event-types">
          {eventTypeOptions.map((type) => <option key={type} value={type} />)}
        </datalist>
      </div>

      {/* Playback bar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
        <button
          onClick={() => {
            if (playing) {
              setPlaying(false);
            } else {
              if (cursor >= total - 1) setCursor(0);
              setPlaying(true);
            }
          }}
          disabled={entries.length === 0 || Boolean(playbackError)}
          title={playbackError ? 'Select an event to retry playback' : playing ? 'Pause graph playback' : 'Play events on graph'}
          aria-label={playing ? 'Pause graph playback' : 'Play events on graph'}
          className="p-1.5 rounded bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white transition-colors"
        >
          {playing ? <Pause size={16} /> : <Play size={16} />}
        </button>
        <button
          onClick={() => setCursor((c) => Math.max(0, c - 1))}
          disabled={entries.length === 0}
          title="Previous event"
          aria-label="Previous event"
          className="p-1.5 rounded border border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-700 disabled:opacity-40 text-slate-600 dark:text-slate-300 transition-colors"
        >
          <SkipBack size={15} />
        </button>
        <button
          onClick={() => setCursor((c) => Math.min(entries.length - 1, c + 1))}
          disabled={entries.length === 0}
          title="Next event"
          aria-label="Next event"
          className="p-1.5 rounded border border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-700 disabled:opacity-40 text-slate-600 dark:text-slate-300 transition-colors"
        >
          <SkipForward size={15} />
        </button>
        <input
          type="range"
          min={0}
          max={Math.max(entries.length - 1, 0)}
          value={cursor}
          onChange={(e) => setCursor(Number(e.target.value))}
          disabled={entries.length === 0}
          aria-label="Timeline position"
          className="flex-1 accent-blue-600"
        />
        <span className="text-xs tabular-nums text-slate-500 dark:text-slate-400 w-20 text-right">
          {entries.length === 0 ? '0 / 0' : `${cursor + 1} / ${entries.length}`}
        </span>
        <select
          value={speedMs}
          onChange={(e) => setSpeedMs(Number(e.target.value))}
          aria-label="Playback speed"
          className="text-xs bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-1.5 py-1 outline-none"
        >
          {SPEEDS.map((speed) => (
            <option key={speed.ms} value={speed.ms}>{speed.label}</option>
          ))}
        </select>
        <span className="hidden sm:inline text-[10px] text-slate-500 dark:text-slate-400">Highlights each event on the graph</span>
      </div>

      {playbackError && (
        <p role="alert" className="px-3 py-1 text-xs text-red-600 dark:text-red-400">
          Playback paused: {playbackError}
        </p>
      )}

      {/* List */}
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center justify-center gap-2 py-8 text-xs text-slate-500 dark:text-slate-400">
            <span className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500" />
            Loading timeline…
          </div>
        )}
        {!loading && error && (
          <div className="px-4 py-6 text-center text-xs text-red-600 dark:text-red-400">{error}</div>
        )}
        {!loading && !error && entries.length === 0 && (
          <EmptyState
            icon={Clock}
            title="No events"
            description="No events match the current filters."
          />
        )}
        {!loading && !error && entries.map((entry, index) => {
          const isActive = index === cursor;
          return (
            <button
              key={entry.id}
              ref={isActive ? activeRowRef : null}
              onClick={() => focusEntry(entry)}
              className={`w-full text-left flex items-start gap-3 px-3 py-2 border-b border-slate-100 dark:border-slate-800 transition-colors ${
                isActive
                  ? 'bg-blue-50 dark:bg-blue-900/30'
                  : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
              }`}
            >
              <span
                className={`mt-1.5 inline-block w-2 h-2 rounded-full shrink-0 ${VENDOR_DOT[entry.vendor] || VENDOR_DOT.unknown}`}
                title={entry.vendor}
              />
              <span className="w-40 shrink-0 text-[11px] tabular-nums text-slate-500 dark:text-slate-400">
                {formatTime(entry.iso)}
              </span>
              <span className="shrink-0 inline-flex items-center rounded bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 text-[11px] font-semibold text-slate-600 dark:text-slate-300">
                {entry.event_type}
              </span>
              <span className="flex-1 min-w-0 truncate text-xs text-slate-600 dark:text-slate-300">
                {entry.summary}
              </span>
            </button>
          );
        })}
        {!loading && !error && entries.length < total && (
          <div className="p-3 text-center">
            <button
              onClick={loadMore}
              disabled={loadingMore}
              className="text-xs bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-50 px-3 py-1.5 rounded font-semibold text-slate-600 dark:text-slate-300 transition-colors"
            >
              {loadingMore ? 'Loading…' : `Load more (${total - entries.length} remaining)`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
