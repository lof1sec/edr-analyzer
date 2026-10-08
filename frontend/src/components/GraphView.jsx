import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import { Filter, X, Copy, Check, ZoomIn, ZoomOut, Network, RotateCcw, Eye, Clock } from 'lucide-react';
import { stylesheet, NODE_GROUPS } from './cytoscapeStyles';
import { api } from '../api/client';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import EmptyState from './EmptyState';
import { useToast } from '../hooks/useToast';

// Sub-component for individual copy buttons
const CopyButton = ({ textToCopy }) => {
  const [copied, setCopied] = useState(false);
  const toast = useToast();

  const handleCopy = () => {
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    toast.success('Copied to clipboard.');
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors text-slate-600 dark:text-slate-300"
      title="Copy JSON"
      aria-label="Copy JSON"
    >
      {copied ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
    </button>
  );
};

// Above this many elements the physics simulation is capped and animations are
// dropped so the layout stays interactive.
const LARGE_GRAPH_THRESHOLD = 2000;

// Convert epoch ms to a `datetime-local` input value in the user's timezone.
function msToLocalInput(ms) {
  if (ms == null) return '';
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// Human-readable rendering of an epoch-ms instant for the "available range" hint.
function formatRange(ms) {
  if (ms == null) return '—';
  return new Date(ms).toLocaleString();
}

function getLayoutConfig(mode, initialPositions, selectedNode, elementCount = 0) {
  const large = elementCount > LARGE_GRAPH_THRESHOLD;
  switch (mode) {
    case 'tree':
      return {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.5,
        fit: true,
        padding: 30,
        animate: !large,
        animationDuration: 300,
        transform: function (node, position) {
          // Flip x and y to create a Left-to-Right tree instead of Top-to-Bottom
          return { x: position.y, y: position.x };
        }
      };
    case 'centered':
      return {
        name: 'concentric',
        fit: true,
        padding: 30,
        minNodeSpacing: 100,
        avoidOverlap: true,
        animate: !large,
        animationDuration: 300,
        concentric: (node) => {
          // Center on selected node if one exists
          if (selectedNode && selectedNode.id === node.id()) {
            return 100;
          }
          // Otherwise use degree centrality
          return node.degree();
        },
        levelWidth: () => 1
      };
    case 'force':
    default:
      // If we already saved the initial force-directed positions, snap back to them immediately
      if (initialPositions && Object.keys(initialPositions).length > 0) {
        return {
          name: 'preset',
          positions: initialPositions,
          fit: true,
          padding: 30,
          animate: !large,
          animationDuration: 300
        };
      }

      return {
        name: 'cose',
        idealEdgeLength: 100,
        nodeOverlap: 20,
        refresh: large ? 5 : 20,
        fit: true,
        padding: 30,
        randomize: false,
        componentSpacing: 100,
        nodeRepulsion: 400000,
        edgeElasticity: 100,
        nestingFactor: 5,
        gravity: 80,
        numIter: large ? 250 : 1000,
        initialTemp: 200,
        coolingFactor: 0.95,
        minTemp: 1.0,
        animate: !large
      };
  }
}

export default function GraphView({ datasetId, focusElementId, onFocusConsumed }) {
  const [elements, setElements] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedLogs, setSelectedLogs] = useState([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [layoutMode, setLayoutMode] = useState('force');
  const [focusDepth, setFocusDepth] = useState(0);
  // Bumped to force a re-layout after resetting the saved arrangement.
  const [layoutKey, setLayoutKey] = useState(0);
  // Element count of the initial payload: layout decisions use this instead of
  // `elements.length` so expanding a cluster/neighbourhood does not re-run the
  // whole layout (the graph would jump around).
  const [baseElementCount, setBaseElementCount] = useState(0);
  // cluster_id -> { node, edge, memberIds, memberEdgeIds } for the expanded set.
  const [expandedClusters, setExpandedClusters] = useState({});
  // Large graphs are truncated server-side: these track the initial view vs the
  // full element count and drive the "load more" pager.
  const [truncated, setTruncated] = useState(false);
  const [totalElements, setTotalElements] = useState(0);
  const [loadingMore, setLoadingMore] = useState(false);
  const omittedOffsetRef = useRef(0);
  // Time-range filter: `rangeFrom`/`rangeTo` are the *applied* bounds (epoch ms)
  // that drive the graph; `fromInput`/`toInput` are the picker values edited by
  // the user. `availableRange` is the dataset's full span, shown as a hint.
  const [rangeFrom, setRangeFrom] = useState(null);
  const [rangeTo, setRangeTo] = useState(null);
  const [fromInput, setFromInput] = useState('');
  const [toInput, setToInput] = useState('');
  const [availableRange, setAvailableRange] = useState({ min: null, max: null });
  const timeRangeRef = useRef({ from: null, to: null });
  const rangeDatasetRef = useRef(datasetId);
  const cyRef = useRef(null);
  const initialPositions = useRef({});
  const isRightPaneOpenRef = useRef(true);
  const layoutModeRef = useRef(layoutMode);
  const rawLogsCache = useRef(new Map());
  const datasetIdRef = useRef(datasetId);
  const saveTimer = useRef(null);
  const expandClusterRef = useRef(null);

  // Filters state
  const [globalSearch, setGlobalSearch] = useState('');
  const [eventTypes, setEventTypes] = useState({});
  const [users, setUsers] = useState({});
  const [pids, setPids] = useState({});
  const debouncedGlobalSearch = useDebouncedValue(globalSearch, 250);

  // Local Filter Searches
  const [eventTypeSearch, setEventTypeSearch] = useState('');
  const [userSearch, setUserSearch] = useState('');
  const [pidSearch, setPidSearch] = useState('');

  // Manual Hiding State
  const [manuallyHidden, setManuallyHidden] = useState(new Set());

  // Right Pane Toggle State
  const [isRightPaneOpen, setIsRightPaneOpen] = useState(true);

  const [activeTab, setActiveTab] = useState('filters'); // 'filters', 'details', 'unmapped'
  const [unmappedEvents, setUnmappedEvents] = useState([]);

  // Server-side search result. Stored with the query it belongs to so a stale
  // result is ignored instead of flashing the wrong matches.
  const [searchResult, setSearchResult] = useState({ q: '', ids: null });

  // Keep refs in sync so long-lived cytoscape listeners read fresh values.
  useEffect(() => { isRightPaneOpenRef.current = isRightPaneOpen; }, [isRightPaneOpen]);
  useEffect(() => { layoutModeRef.current = layoutMode; }, [layoutMode]);
  useEffect(() => { datasetIdRef.current = datasetId; }, [datasetId]);
  useEffect(() => { timeRangeRef.current = { from: rangeFrom, to: rangeTo }; }, [rangeFrom, rangeTo]);

  // The dataset's full event-time span (unfiltered) backs the range hint and the
  // pickers' min/max. Fetched once per dataset, in parallel-ish with the graph.
  useEffect(() => {
    if (!datasetId) {
      setAvailableRange({ min: null, max: null });
      return undefined;
    }
    let cancelled = false;
    api.getTimeRange(datasetId)
      .then((res) => {
        if (!cancelled) setAvailableRange({ min: res?.min_ms ?? null, max: res?.max_ms ?? null });
      })
      .catch((err) => {
        console.error(err);
        if (!cancelled) setAvailableRange({ min: null, max: null });
      });
    return () => { cancelled = true; };
  }, [datasetId]);

  const elementsById = useMemo(() => {
    const map = new Map();
    for (const el of elements) {
      if (el.data && el.data.id) {
        map.set(el.data.id, el);
      }
    }
    return map;
  }, [elements]);

  // Focus an element requested by another view (e.g. the timeline). Waits until
  // it is present in the loaded payload, then centres and selects it, and
  // reports back so the same request is not repeated.
  useEffect(() => {
    if (!focusElementId || !cyRef.current) return;
    const element = elementsById.get(focusElementId);
    if (!element) return;
    const cy = cyRef.current;
    const target = cy.getElementById(focusElementId);
    if (target.nonempty()) {
      cy.animate(
        { center: { eles: target }, zoom: Math.max(cy.zoom(), 1) },
        { duration: 300 }
      );
    }
    if (element.data) {
      setSelectedLogs([]);
      setSelectedNode(element.data);
      setIsRightPaneOpen(true);
      setActiveTab('details');
    }
    if (onFocusConsumed) onFocusConsumed();
  }, [focusElementId, elementsById, onFocusConsumed]);

  useEffect(() => {
    if (!datasetId) return;

    // Switching datasets starts unfiltered: ignore (and clear) any range applied
    // to the previous dataset, without skipping this run's fetch.
    const datasetChanged = rangeDatasetRef.current !== datasetId;
    if (datasetChanged) {
      rangeDatasetRef.current = datasetId;
      setRangeFrom(null);
      setRangeTo(null);
      setFromInput('');
      setToInput('');
    }
    const activeFrom = datasetChanged ? null : rangeFrom;
    const activeTo = datasetChanged ? null : rangeTo;

    initialPositions.current = {}; // Reset positions on new dataset/range
    rawLogsCache.current = new Map();
    setSelectedNode(null);
    setSelectedLogs([]);
    setFocusDepth(0);
    setLayoutMode('force');
    setSearchResult({ q: '', ids: null });
    setExpandedClusters({});
    setError(null);
    const fetchGraph = async () => {
      setLoading(true);
      try {
        const [data, savedLayout] = await Promise.all([
          api.getGraph(datasetId, { from: activeFrom, to: activeTo }),
          api.getLayout(datasetId).catch(() => null),
        ]);

        // Restore the saved arrangement (if any) before the layout memo runs.
        // A time filter changes the node set, so the full-graph layout no longer
        // applies and is skipped.
        const saved = savedLayout?.positions;
        if (activeFrom == null && activeTo == null && saved && Object.keys(saved).length > 0) {
          initialPositions.current = saved;
        }

        const uniqueEvents = new Set();
        const uniqueUsers = new Set();
        const uniquePids = new Set();

        data.elements.edges?.forEach(e => {
          if (e.data.event_simplename) uniqueEvents.add(e.data.event_simplename);
        });

        data.elements.nodes?.forEach(n => {
          if (n.data.group === 'process') {
            if (n.data.username) uniqueUsers.add(n.data.username);
            if (n.data.id) uniquePids.add(n.data.id);
          }
        });

        setEventTypes(Array.from(uniqueEvents).reduce((acc, evt) => ({ ...acc, [evt]: true }), {}));
        setUsers(Array.from(uniqueUsers).reduce((acc, usr) => ({ ...acc, [usr]: true }), {}));
        setPids(Array.from(uniquePids).reduce((acc, pid) => ({ ...acc, [pid]: true }), {}));

        const cyElements = [
          ...(data.elements.nodes || []),
          ...(data.elements.edges || [])
        ];

        setBaseElementCount(cyElements.length);
        setElements(cyElements);
        setUnmappedEvents(data.unmapped_events || {});
        setTruncated(Boolean(data.truncated));
        setTotalElements((data.total_nodes || 0) + (data.total_edges || 0));
        omittedOffsetRef.current = 0;
        setLoadingMore(false);
      } catch (err) {
        console.error(err);
        setError(err?.message || 'Failed to load the graph.');
      } finally {
        setLoading(false);
      }
    };
    fetchGraph();
  }, [datasetId, reloadKey, rangeFrom, rangeTo]);

  // The backend resolves the global search against its cached search index, so
  // raw events never reach the browser. Storing the query with the result lets
  // us ignore stale responses.
  useEffect(() => {
    const query = debouncedGlobalSearch.trim();
    if (!datasetId || !query) return;
    let cancelled = false;
    api.searchGraph(datasetId, query)
      .then(res => {
        if (!cancelled) setSearchResult({ q: query, ids: new Set(res.ids || []) });
      })
      .catch(err => {
        console.error(err);
      });
    return () => { cancelled = true; };
  }, [datasetId, debouncedGlobalSearch]);

  const searchQuery = debouncedGlobalSearch.trim();
  const matchedIds = searchQuery && searchResult.q === searchQuery ? searchResult.ids : null;

  // Apply filters whenever state changes. Element data holds no raw events, so
  // filtering is a pure, cheap pass over the precomputed search result.
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    cy.batch(() => {
      cy.elements().removeClass('hidden dimmed');

      const passesManualAndIdentity = (data) => {
        if (data.id && manuallyHidden.has(data.id)) return false;
        if (data.group === 'process') {
          if (data.username && users[data.username] === false) return false;
          if (data.id && pids[data.id] === false) return false;
        }
        return true;
      };

      // Depth-limited focus around the selected node (0 = entire graph).
      let focusIds = null;
      if (focusDepth > 0 && selectedNode && selectedNode.id) {
        const selected = cy.getElementById(selectedNode.id);
        if (selected.nonempty()) {
          if (selected.isNode()) {
            let visited = selected;
            for (let hop = 0; hop < focusDepth; hop += 1) {
              const next = visited.connectedEdges().connectedNodes().not(visited);
              if (next.empty()) break;
              visited = visited.union(next);
            }
            focusIds = new Set(visited.map(el => el.id()));
          } else {
            focusIds = new Set([selected.id(), selected.source().id(), selected.target().id()]);
          }
        }
      }

      // Node filtering
      cy.nodes().forEach(node => {
        const d = node.data();
        let isVisible = passesManualAndIdentity(d);

        if (isVisible && matchedIds && !matchedIds.has(d.id)) {
          isVisible = false;
        }

        if (isVisible && focusIds && !focusIds.has(d.id)) {
          isVisible = false;
        }

        if (!isVisible) {
          node.addClass('hidden');
        }
      });

      // Edge filtering
      cy.edges().forEach(edge => {
        const d = edge.data();
        let isVisible = passesManualAndIdentity(d);

        if (isVisible && d.event_simplename && eventTypes[d.event_simplename] === false) {
          isVisible = false;
        }

        if (isVisible && matchedIds && matchedIds.has(d.id)) {
          // If the edge matches, reveal its source and target so the edge can
          // be drawn, but only when they pass the manual/identity filters.
          [edge.source(), edge.target()].forEach(endpoint => {
            if (passesManualAndIdentity(endpoint.data())) {
              endpoint.removeClass('hidden');
            }
          });
        }

        if (edge.source().hasClass('hidden') || edge.target().hasClass('hidden')) {
          isVisible = false;
        }

        if (!isVisible) {
          edge.addClass('hidden');
        }
      });

      // Cleanup orphan artifacts
      cy.nodes().forEach(node => {
        if (node.data('group') !== 'process' && !node.hasClass('hidden')) {
          const visibleEdges = node.connectedEdges().filter(e => !e.hasClass('hidden'));
          if (visibleEdges.length === 0) {
            node.addClass('hidden');
          }
        }
      });

      // Spotlight the selected element's neighbourhood.
      if (selectedNode && selectedNode.id) {
        const selected = cy.getElementById(selectedNode.id);
        if (selected.nonempty()) {
          const focusElements = (selected.isNode()
            ? selected.closedNeighborhood()
            : selected.union(selected.source()).union(selected.target())
          ).filter(el => !el.hasClass('hidden'));
          cy.elements().not(focusElements).addClass('dimmed');
        }
      }
    });
  }, [matchedIds, eventTypes, users, pids, elements, manuallyHidden, selectedNode, focusDepth]);

  // Fetch raw evidence for the selected element on demand and cache it. The
  // previous element's logs are cleared from the tap handlers, not here, so
  // this effect never calls setState synchronously on its own.
  useEffect(() => {
    if (!datasetId || !selectedNode || !selectedNode.id || activeTab !== 'details') {
      return;
    }

    const elementId = selectedNode.id;
    const cached = rawLogsCache.current.get(elementId);
    if (cached) {
      setSelectedLogs(cached);
      return;
    }

    let cancelled = false;
    setLogsLoading(true);
    api.getElementLogs(datasetId, elementId, { from: rangeFrom, to: rangeTo })
      .then(res => {
        const logs = res?.raw_logs || [];
        rawLogsCache.current.set(elementId, logs);
        if (!cancelled) setSelectedLogs(logs);
      })
      .catch(err => {
        console.error(err);
        if (!cancelled) setSelectedLogs([]);
      })
      .finally(() => {
        if (!cancelled) setLogsLoading(false);
      });

    return () => { cancelled = true; };
  }, [datasetId, selectedNode, activeTab, rangeFrom, rangeTo]);

  const centeredOn = layoutMode === 'centered' ? selectedNode : null;

  // Memoise the layout object: react-cytoscapejs re-runs the layout whenever
  // the prop reference changes, so a fresh object on every render (e.g. when
  // merely selecting a node) caused constant re-layouts.
  const layout = useMemo(() => {
    // `datasetId`/`layoutKey` force a fresh layout object when the dataset
    // changes or the saved arrangement is reset, even if the element count is
    // unchanged; the layout itself does not need their values.
    void datasetId;
    void layoutKey;
    return getLayoutConfig(layoutMode, initialPositions.current, centeredOn, baseElementCount);
  }, [layoutMode, centeredOn, baseElementCount, datasetId, layoutKey]);

  // The stylesheet is static: memoise it so react-cytoscapejs does not re-apply
  // the whole style (a fresh array reference triggers style.fromJson().update())
  // on every render/filter toggle.
  const styleSheet = useMemo(() => stylesheet(), []);

  const applyLayout = (mode) => {
    // Updating the mode changes the memoised layout prop above, which makes
    // react-cytoscapejs run the new layout. No manual run needed.
    setLayoutMode(mode);
  };

  const fitGraph = () => {
      if(cyRef.current) cyRef.current.fit(cyRef.current.elements().not('.hidden'), 30);
  };

  const zoomBy = (factor) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({
      level: cy.zoom() * factor,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
    });
  };

  // Apply the picker values as the active time window. Only changing the
  // applied range triggers a graph reload (see the fetch effect); a range where
  // only one bound is set is valid.
  const applyTimeRange = () => {
    const from = fromInput ? new Date(fromInput).getTime() : null;
    const to = toInput ? new Date(toInput).getTime() : null;
    setRangeFrom(Number.isFinite(from) ? from : null);
    setRangeTo(Number.isFinite(to) ? to : null);
  };

  const clearTimeRange = () => {
    setFromInput('');
    setToInput('');
    setRangeFrom(null);
    setRangeTo(null);
  };

  const hasActiveTimeRange = rangeFrom != null || rangeTo != null;

  // Persist the current node positions (debounced). The in-memory snapshot is
  // updated immediately so switching back to the force layout snaps to the
  // user's latest arrangement even before the request completes.
  const persistLayout = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const fresh = {};
    cy.nodes().forEach(node => {
      const pos = node.position();
      fresh[node.id()] = { x: pos.x, y: pos.y };
    });
    // Keep positions of currently-collapsed nodes too, so collapsing a cluster
    // restores it where it was.
    const positions = { ...initialPositions.current, ...fresh };
    initialPositions.current = positions;
    if (saveTimer.current) clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      if (datasetIdRef.current) {
        api.saveLayout(datasetIdRef.current, positions).catch(err => {
          console.error('Failed to save layout', err);
        });
      }
    }, 800);
  }, []);

  const resetLayout = async () => {
    initialPositions.current = {};
    if (saveTimer.current) clearTimeout(saveTimer.current);
    try {
      if (datasetIdRef.current) await api.saveLayout(datasetIdRef.current, {});
    } catch (err) {
      console.error('Failed to clear layout', err);
    }
    setLayoutMode('force');
    setLayoutKey(k => k + 1);
  };

  // Lay elements out in a ring around `origin`, so merged-on-demand elements do
  // not pile up at (0, 0) and the whole graph does not need a re-layout.
  const ringPositions = (items, origin) => {
    const radius = 90;
    return items.map((element, index) => {
      const angle = (2 * Math.PI * index) / Math.max(items.length, 1);
      return {
        ...element,
        position: { x: origin.x + radius * Math.cos(angle), y: origin.y + radius * Math.sin(angle) },
      };
    });
  };

  // Fetch the next page of elements omitted from the truncated initial view and
  // append them without re-running the layout (baseElementCount is left alone,
  // so the memoised layout object stays the same). New nodes are fanned out
  // around the current viewport centre instead of piling up at (0, 0).
  const loadMoreElements = useCallback(async () => {
    if (!datasetIdRef.current || loadingMore || !truncated) return;
    setLoadingMore(true);
    try {
      const res = await api.getGraphElements(datasetIdRef.current, {
        offset: omittedOffsetRef.current,
        limit: 500,
        from: timeRangeRef.current.from,
        to: timeRangeRef.current.to,
      });
      const cy = cyRef.current;
      let center = { x: 0, y: 0 };
      if (cy) {
        const ext = cy.extent();
        center = { x: (ext.x1 + ext.x2) / 2, y: (ext.y1 + ext.y2) / 2 };
      }
      const nodes = res.nodes || [];
      setElements((prev) => [...prev, ...ringPositions(nodes, center), ...(res.edges || [])]);
      omittedOffsetRef.current += nodes.length;
      if ((res.remaining ?? 0) === 0) setTruncated(false);
    } catch (err) {
      console.error(err);
      toast.error(err?.message || 'Could not load more elements.');
    } finally {
      setLoadingMore(false);
    }
  }, [loadingMore, truncated]);

  // Load *every* remaining element, paging until nothing is left. Offered by the
  // "Cargar todos" button, which only shows while the user is searching or has
  // filtered the graph, when seeing the whole element set actually matters.
  const loadAllElements = useCallback(async () => {
    if (!datasetIdRef.current || loadingMore || !truncated) return;
    setLoadingMore(true);
    try {
      const nodes = [];
      const edges = [];
      let offset = omittedOffsetRef.current;
      while (true) {
        const res = await api.getGraphElements(datasetIdRef.current, {
          offset,
          limit: 1000,
          from: timeRangeRef.current.from,
          to: timeRangeRef.current.to,
        });
        const pageNodes = res.nodes || [];
        nodes.push(...pageNodes);
        edges.push(...(res.edges || []));
        offset += pageNodes.length;
        if ((res.remaining ?? 0) === 0 || pageNodes.length === 0) break;
      }
      const cy = cyRef.current;
      let center = { x: 0, y: 0 };
      if (cy) {
        const ext = cy.extent();
        center = { x: (ext.x1 + ext.x2) / 2, y: (ext.y1 + ext.y2) / 2 };
      }
      setElements((prev) => [...prev, ...ringPositions(nodes, center), ...edges]);
      omittedOffsetRef.current = offset;
      setTruncated(false);
    } catch (err) {
      console.error(err);
      toast.error(err?.message || 'Could not load all elements.');
    } finally {
      setLoadingMore(false);
    }
  }, [loadingMore, truncated]);

  const expandCluster = useCallback(async (clusterId) => {
    const cy = cyRef.current;
    if (!cy || !datasetIdRef.current) return;
    const clusterNode = cy.getElementById(clusterId);
    if (clusterNode.empty()) return;

    const clusterData = clusterNode.data();
    const hubId = clusterData.parentId;
    const hub = hubId ? cy.getElementById(hubId) : null;
    const origin = hub && hub.nonempty() ? hub.position() : clusterNode.position();
    const clusterEdge = cy.getElementById(`cluster_edge_${hubId}`);
    const clusterEdgeData = clusterEdge.nonempty() ? clusterEdge.data() : null;

    try {
      const res = await api.getCluster(datasetIdRef.current, clusterId, timeRangeRef.current);
      const nodes = res.nodes || [];
      const edges = res.edges || [];
      setElements(prev => prev
        .filter(el => el.data.id !== clusterId && el.data.id !== res.cluster_edge_id)
        .concat(ringPositions(nodes, origin), edges)
      );
      setExpandedClusters(prev => ({
        ...prev,
        [clusterId]: {
          node: { data: clusterData },
          edge: clusterEdgeData ? { data: clusterEdgeData } : null,
          memberIds: nodes.map(n => n.data.id),
          memberEdgeIds: edges.map(e => e.data.id),
        },
      }));
      toast.info(`Expanded ${nodes.length} collapsed element${nodes.length === 1 ? '' : 's'}.`);
    } catch (err) {
      console.error(err);
      toast.error('Could not expand the cluster.');
    }
  }, []);

  useEffect(() => { expandClusterRef.current = expandCluster; }, [expandCluster]);

  const collapseCluster = (clusterId) => {
    const info = expandedClusters[clusterId];
    if (!info) return;
    const memberIds = new Set([...info.memberIds, ...info.memberEdgeIds]);
    setElements(prev => prev
      .filter(el => !memberIds.has(el.data.id))
      .concat([info.node, info.edge].filter(Boolean))
    );
    setExpandedClusters(prev => {
      const next = { ...prev };
      delete next[clusterId];
      return next;
    });
  };

  const collapseAllClusters = () => {
    const memberIds = new Set();
    const restored = [];
    Object.values(expandedClusters).forEach(info => {
      info.memberIds.forEach(id => memberIds.add(id));
      info.memberEdgeIds.forEach(id => memberIds.add(id));
      if (info.node) restored.push(info.node);
      if (info.edge) restored.push(info.edge);
    });
    setElements(prev => prev.filter(el => !memberIds.has(el.data.id)).concat(restored));
    setExpandedClusters({});
  };

  // Reveal the selected node's 1-hop neighbourhood when it is hidden by manual
  // hides, identity/event filters, the global search or the focus depth. It acts
  // on elements already in the graph (no server round-trip) and is the targeted
  // counterpart to "Unhide All".
  const revealNeighbors = () => {
    const cy = cyRef.current;
    if (!cy || !selectedNode?.id) return;
    const selected = cy.getElementById(selectedNode.id);
    if (selected.empty() || !selected.isNode()) return;

    const neighborhood = selected.closedNeighborhood();
    let hiddenCount = 0;
    const ids = new Set();
    const usersToShow = new Set();
    const pidsToShow = new Set();
    const eventsToShow = new Set();

    neighborhood.forEach(el => {
      ids.add(el.id());
      if (el.hasClass('hidden')) hiddenCount += 1;
      const data = el.data();
      if (el.isNode() && data.group === 'process') {
        if (data.username) usersToShow.add(data.username);
        if (data.id) pidsToShow.add(data.id);
      } else if (el.isEdge() && data.event_simplename) {
        eventsToShow.add(data.event_simplename);
      }
    });

    if (hiddenCount === 0) {
      toast.info('Neighbourhood is already visible.');
      return;
    }

    setManuallyHidden(prev => {
      const next = new Set(prev);
      ids.forEach(id => next.delete(id));
      return next;
    });
    if (usersToShow.size) {
      setUsers(prev => {
        const next = { ...prev };
        usersToShow.forEach(user => { next[user] = true; });
        return next;
      });
    }
    if (pidsToShow.size) {
      setPids(prev => {
        const next = { ...prev };
        pidsToShow.forEach(pid => { next[pid] = true; });
        return next;
      });
    }
    if (eventsToShow.size) {
      setEventTypes(prev => {
        const next = { ...prev };
        eventsToShow.forEach(event => { next[event] = true; });
        return next;
      });
    }
    // The global search and the focus depth can hide the neighbourhood too.
    if (globalSearch) setGlobalSearch('');
    if (focusDepth > 0) setFocusDepth(0);

    toast.success(
      `Revealed ${hiddenCount} neighbouring element${hiddenCount === 1 ? '' : 's'}.`
    );
  };

  useEffect(() => () => { if (saveTimer.current) clearTimeout(saveTimer.current); }, []);

  // react-cytoscapejs invokes this on every mount and update. Listeners are
  // attached here — right where the instance is created — and guarded by
  // instance identity. This mirrors the original (working) pattern while
  // avoiding the duplicate handlers it leaked: repeated calls with the same
  // instance are ignored, and a recreated instance gets its own handlers.
  // `cy.destroy()` on unmount removes them, so no manual cleanup is needed.
  const handleCy = useCallback((cy) => {
    if (cyRef.current === cy) return;
    cyRef.current = cy;

    const onElementTap = (event) => {
      const data = event.target.data();
      // A collapsed hub is a button: tapping it loads its hidden subtree.
      if (data.isCluster) {
        if (expandClusterRef.current) expandClusterRef.current(data.id);
        return;
      }
      setSelectedLogs([]);
      setSelectedNode(data);
      if (!isRightPaneOpenRef.current) {
        setIsRightPaneOpen(true);
      }
      setActiveTab('details');
    };

    const onBackgroundTap = (event) => {
      if (event.target === cy) {
        setSelectedLogs([]);
        setSelectedNode(null);
        setFocusDepth(0);
      }
    };

    // Capture the initial force layout once per dataset so we can snap back to
    // it when the user switches layouts and returns, then persist the result.
    const onLayoutStop = () => {
      if (Object.keys(initialPositions.current).length === 0 && layoutModeRef.current === 'force') {
        cy.nodes().forEach(node => {
          initialPositions.current[node.id()] = { ...node.position() };
        });
      }
      persistLayout();
    };

    cy.on('tap', 'node', onElementTap);
    cy.on('tap', 'edge', onElementTap);
    cy.on('tap', onBackgroundTap);
    cy.on('layoutstop', onLayoutStop);
    cy.on('dragfree', 'node', persistLayout);
  }, [persistLayout]);

  // Resize cytoscape on pane toggle so canvas redraws to fit new width
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (cyRef.current) cyRef.current.resize();
    }, 300); // Wait for CSS transition to finish
    return () => clearTimeout(timeoutId);
  }, [isRightPaneOpen]);

  // Observer to auto resize cytoscape when container size changes
  useEffect(() => {
    const container = document.getElementById('cy-container');
    if (!container) return;
    const resizeObserver = new ResizeObserver(() => {
      if (cyRef.current) cyRef.current.resize();
    });
    resizeObserver.observe(container);
    return () => resizeObserver.disconnect();
  }, [datasetId, isRightPaneOpen]);

  if (!datasetId) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <EmptyState
          icon={Network}
          title="No dataset selected"
          description="Select a dataset from the sidebar or upload a CSV export to build a graph."
        />
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-3">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        <p className="text-xs text-slate-500 dark:text-slate-400">Loading graph…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center px-6">
        <p className="text-sm font-semibold text-red-600 dark:text-red-400">Could not load the graph</p>
        <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md break-words">{error}</p>
        <button
          onClick={() => setReloadKey(k => k + 1)}
          className="text-xs bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded font-semibold transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  const toggleEvent = (evt) => setEventTypes(p => ({ ...p, [evt]: !p[evt] }));
  const setAllEvents = (val) => setEventTypes(p => Object.keys(p).reduce((acc, k) => ({ ...acc, [k]: val }), {}));

  const toggleUser = (usr) => setUsers(p => ({ ...p, [usr]: !p[usr] }));
  const setAllUsers = (val) => setUsers(p => Object.keys(p).reduce((acc, k) => ({ ...acc, [k]: val }), {}));

  const togglePid = (pid) => setPids(p => ({ ...p, [pid]: !p[pid] }));
  const setAllPids = (val) => setPids(p => Object.keys(p).reduce((acc, k) => ({ ...acc, [k]: val }), {}));

  // Backend sends aggregated counts; show the most frequent first.
  const unmappedEntries = Object.entries(unmappedEvents).sort((a, b) => b[1] - a[1]);

  const filteredEventTypes = Object.keys(eventTypes)
    .sort()
    .filter((evt) => evt.toLowerCase().includes(eventTypeSearch.toLowerCase()));
  const filteredUsers = Object.keys(users)
    .sort()
    .filter((usr) => usr.toLowerCase().includes(userSearch.toLowerCase()));
  const pidLabel = (pid) => {
    const node = elementsById.get(pid);
    return node && node.data.process_name ? `${node.data.process_name} (${pid})` : pid;
  };
  const filteredPids = Object.keys(pids)
    .sort()
    .filter((pid) => pidLabel(pid).toLowerCase().includes(pidSearch.toLowerCase()));

  const searchHasNoMatches = Boolean(searchQuery && matchedIds && matchedIds.size === 0);

  // "Cargar todos" is offered whenever the user is actively narrowing the graph:
  // a global search term, or at least one checkbox hidden in the Event Types,
  // Users or PIDs filters. Only then does loading the full set matter.
  const showLoadAll =
    Boolean(searchQuery) ||
    Object.values(eventTypes).some((value) => value === false) ||
    Object.values(users).some((value) => value === false) ||
    Object.values(pids).some((value) => value === false);

  return (
    <div className="flex-1 flex relative overflow-hidden w-full h-full">

      {/* Cytoscape Container */}
      <div id="cy-container" className="flex-1 min-w-0 relative bg-slate-100 dark:bg-[#222]">

        {/* Layout Toolbar */}
        <div className="absolute top-4 left-4 z-10 flex flex-wrap gap-2 max-w-[calc(100%-2rem)]">
            <select
                value={layoutMode}
                onChange={(e) => applyLayout(e.target.value)}
                aria-label="Graph layout"
                className="bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-3 py-1.5 text-xs font-semibold shadow hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors outline-none"
            >
                <option value="force">Layout: Force-directed</option>
                <option value="tree">Layout: Tree</option>
                <option value="centered">Layout: Centered</option>
            </select>
            <select
                value={focusDepth}
                onChange={(e) => setFocusDepth(Number(e.target.value))}
                disabled={!selectedNode}
                title={selectedNode ? 'Limit the graph to the selected node\'s neighbourhood' : 'Select a node to focus'}
                aria-label="Focus depth"
                className="bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-3 py-1.5 text-xs font-semibold shadow hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors outline-none disabled:opacity-50 disabled:cursor-not-allowed"
            >
                <option value={0}>Focus: Entire graph</option>
                <option value={1}>Focus: 1 hop</option>
                <option value={2}>Focus: 2 hops</option>
            </select>
            <button
                onClick={fitGraph}
                className="bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-3 py-1.5 text-xs font-semibold shadow hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                title="Fit the graph to the viewport"
            >
                Fit Graph
            </button>
            <button
                onClick={resetLayout}
                className="flex items-center gap-1.5 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-3 py-1.5 text-xs font-semibold shadow hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                title="Clear the saved arrangement and re-run the force layout"
                aria-label="Reset layout"
            >
                <RotateCcw size={14} />
                Reset layout
            </button>
            <div className="flex items-center bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded shadow overflow-hidden">
              <button
                onClick={() => zoomBy(1 / 1.3)}
                className="px-2 py-1.5 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                title="Zoom out"
                aria-label="Zoom out"
              >
                <ZoomOut size={16} />
              </button>
              <button
                onClick={() => zoomBy(1.3)}
                className="px-2 py-1.5 border-l border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                title="Zoom in"
                aria-label="Zoom in"
              >
                <ZoomIn size={16} />
              </button>
            </div>
            <div className="flex items-center gap-1.5 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-2 py-1 shadow">
              <Clock size={14} className="text-slate-500 dark:text-slate-400 shrink-0" aria-hidden="true" />
              <input
                type="datetime-local"
                value={fromInput}
                min={availableRange.min != null ? msToLocalInput(availableRange.min) : undefined}
                max={toInput || (availableRange.max != null ? msToLocalInput(availableRange.max) : undefined)}
                onChange={(e) => setFromInput(e.target.value)}
                aria-label="Start time"
                title="Start time"
                className="bg-transparent text-xs text-slate-700 dark:text-slate-200 outline-none"
              />
              <span className="text-slate-400" aria-hidden="true">→</span>
              <input
                type="datetime-local"
                value={toInput}
                min={fromInput || (availableRange.min != null ? msToLocalInput(availableRange.min) : undefined)}
                max={availableRange.max != null ? msToLocalInput(availableRange.max) : undefined}
                onChange={(e) => setToInput(e.target.value)}
                aria-label="End time"
                title="End time"
                className="bg-transparent text-xs text-slate-700 dark:text-slate-200 outline-none"
              />
              <button
                onClick={applyTimeRange}
                disabled={!fromInput && !toInput}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-2 py-1 rounded text-xs font-semibold transition-colors"
                title="Apply the time range to the graph"
              >
                Apply
              </button>
              {hasActiveTimeRange && (
                <button
                  onClick={clearTimeRange}
                  className="text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 px-1 text-xs font-semibold"
                  title="Clear the time filter"
                  aria-label="Clear the time filter"
                >
                  Clear
                </button>
              )}
            </div>
            {(availableRange.min != null || availableRange.max != null) && (
              <span className="w-full text-[10px] text-slate-500 dark:text-slate-400">
                Available range: {formatRange(availableRange.min)} → {formatRange(availableRange.max)}
              </span>
            )}
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 z-10 bg-white/90 dark:bg-slate-800/90 backdrop-blur border border-slate-200 dark:border-slate-700 rounded p-2 shadow text-[10px] grid grid-cols-2 gap-x-3 gap-y-1 pointer-events-none">
          {NODE_GROUPS.map(item => (
            <div key={item.label} className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
              <span
                className="inline-block w-3 h-3 rounded-sm border"
                style={{ backgroundColor: item.color, borderColor: item.border }}
              />
              <span>{item.label}</span>
            </div>
          ))}
        </div>

        {/* Truncated-graph notice + pager */}
        {truncated && (
          <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-10 flex items-center gap-2 bg-white/90 dark:bg-slate-800/90 backdrop-blur border border-slate-200 dark:border-slate-700 rounded shadow px-3 py-2 text-xs text-slate-600 dark:text-slate-300">
            <span>
              Mostrando {elements.length} de {totalElements} elementos
            </span>
            {showLoadAll ? (
              <button
                onClick={loadAllElements}
                disabled={loadingMore}
                title="Cargar todos los elementos restantes"
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-2 py-1 rounded font-semibold transition-colors"
              >
                {loadingMore ? 'Cargando…' : 'Cargar todos'}
              </button>
            ) : (
              <button
                onClick={loadMoreElements}
                disabled={loadingMore}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-2 py-1 rounded font-semibold transition-colors"
              >
                {loadingMore ? 'Cargando…' : `Cargar más (${totalElements - elements.length})`}
              </button>
            )}
          </div>
        )}

        <CytoscapeComponent
          elements={elements}
          stylesheet={styleSheet}
          layout={layout}
          style={{ width: '100%', height: '100%' }}
          cy={handleCy}
        />

        {elements.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <EmptyState
              icon={Network}
              title="Empty graph"
              description="This dataset produced no graph elements to display."
            />
          </div>
        )}
      </div>

      {/* Right Pane: Filters OR Details depending on state */}
      {!isRightPaneOpen ? (
        <div className="w-16 h-full bg-white dark:bg-slate-800 border-l border-slate-200 dark:border-slate-700 flex flex-col items-center py-4 transition-all duration-300 z-30 shrink-0">
          <button
            onClick={() => setIsRightPaneOpen(true)}
            className="p-2 rounded-md hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors text-slate-500 dark:text-slate-400"
            title="Open filters and details"
            aria-label="Open filters and details"
          >
            <Filter size={24} />
          </button>
        </div>
      ) : (
        <div
          className="w-80 h-full bg-white dark:bg-slate-800 border-l border-slate-200 dark:border-slate-700 flex flex-col overflow-hidden transition-all duration-300 z-30 shrink-0 shadow-lg relative max-md:absolute max-md:inset-y-0 max-md:right-0"
        >

          {/* Toggle View Header */}
          <div className="flex border-b border-slate-200 dark:border-slate-700" role="tablist" aria-label="Graph panels">
             <button
               role="tab"
               aria-selected={activeTab === 'filters'}
               className={`flex-1 p-2 text-xs font-bold transition-colors ${activeTab === 'filters' ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700'}`}
               onClick={() => setActiveTab('filters')}
             >
               Filters
             </button>
             <button
               role="tab"
               aria-selected={activeTab === 'details'}
               className={`flex-1 p-2 text-xs font-bold transition-colors ${activeTab === 'details' ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700'} ${!selectedNode && 'opacity-50 cursor-not-allowed'}`}
               onClick={() => selectedNode && setActiveTab('details')}
               disabled={!selectedNode}
             >
               Node Details
             </button>
             <button
               role="tab"
               aria-selected={activeTab === 'unmapped'}
               className={`flex-1 p-2 text-xs font-bold transition-colors ${activeTab === 'unmapped' ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700'}`}
               onClick={() => setActiveTab('unmapped')}
             >
               Unmapped Stats
             </button>
             <button
               onClick={() => setIsRightPaneOpen(false)}
               className="p-3 text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors border-l border-slate-200 dark:border-slate-700 shrink-0"
               title="Collapse panel"
               aria-label="Collapse panel"
             >
               <X size={20} />
             </button>
          </div>

          {/* Scrollable Content Area */}
          <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">

            {/* Details Pane Content */}
            {activeTab === 'details' && selectedNode ? (
              <div className="space-y-4">
                <div className="flex justify-between items-start mb-2 gap-2">
                  <h4 className="font-bold text-lg text-slate-800 dark:text-white break-all min-w-0 flex-1">
                    {selectedNode.label || selectedNode.event_simplename || "Selected Element"}
                  </h4>
                  <div className="flex gap-2 shrink-0">
                    <button
                      onClick={() => {
                        if (selectedNode.id) {
                          setManuallyHidden(prev => new Set(prev).add(selectedNode.id));
                          setSelectedLogs([]);
                          setSelectedNode(null);
                          setFocusDepth(0);
                        }
                      }}
                      className="shrink-0 text-[10px] bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800 px-2 py-1 rounded hover:bg-red-200 dark:hover:bg-red-800/50 transition-colors font-semibold"
                      title="Hide this element from the graph"
                    >
                      Hide
                    </button>
                    {selectedNode.group && (
                      <button
                        onClick={revealNeighbors}
                        className="shrink-0 text-[10px] bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-800 px-2 py-1 rounded hover:bg-blue-200 dark:hover:bg-blue-800/50 transition-colors font-semibold flex items-center gap-1"
                        title="Reveal hidden elements within one hop"
                      >
                        <Eye size={12} />
                        Reveal
                      </button>
                    )}
                    {selectedLogs.length > 0 && (
                       <CopyButton textToCopy={JSON.stringify(selectedLogs, null, 2)} />
                    )}
                  </div>
                </div>

                <div className="bg-slate-50 dark:bg-black p-3 rounded border border-slate-200 dark:border-slate-700 text-xs font-mono text-slate-700 dark:text-green-400 overflow-x-auto">
                  <pre>{selectedNode.title || (selectedNode.label ? "No title" : "Edge")}</pre>
                </div>

                {logsLoading ? (
                  <p className="text-xs text-slate-500 italic">Loading evidence…</p>
                ) : selectedLogs.length > 0 ? (
                  <div className="mt-4">
                    <h5 className="font-bold text-sm text-slate-600 dark:text-slate-300 mb-2 border-b border-slate-200 dark:border-slate-700 pb-1">Raw Log Events</h5>
                    {selectedNode.raw_logs_total > selectedLogs.length && (
                      <p className="text-[10px] text-amber-600 dark:text-amber-400 mb-2">
                        Showing {selectedLogs.length} of {selectedNode.raw_logs_total} events (truncated for performance).
                      </p>
                    )}
                    {selectedLogs.map((log, idx) => {
                      const jsonStr = JSON.stringify(log, null, 2);
                      return (
                        <div key={idx} className="mb-4 relative bg-slate-100 dark:bg-slate-900 rounded border border-slate-200 dark:border-slate-600 text-xs font-mono text-slate-800 dark:text-slate-200">
                          <div className="absolute top-2 right-2">
                            <CopyButton textToCopy={jsonStr} />
                          </div>
                          <div className="p-3 overflow-x-auto custom-scrollbar">
                            <pre>{jsonStr}</pre>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No raw log events for this element.</p>
                )}
              </div>
            ) : activeTab === 'unmapped' ? (

            /* Unmapped Stats Pane Content */
              <div className="space-y-4">
                <h4 className="font-bold text-sm text-slate-800 dark:text-white border-b border-slate-200 dark:border-slate-700 pb-2">
                  Unmapped Events ({unmappedEntries.length})
                </h4>
                {unmappedEntries.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">All events have been successfully mapped.</p>
                ) : (
                  <div className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded p-2 overflow-y-auto max-h-[60vh] custom-scrollbar">
                    <ul className="list-disc list-inside space-y-1">
                      {unmappedEntries.map(([evt, count]) => (
                        <li key={evt} className="text-xs font-mono text-slate-700 dark:text-slate-300 truncate" title={`${evt} (${count})`}>
                          {evt} ({count})
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : activeTab === 'filters' && (

            /* Filters Pane Content */
              <div className="space-y-6 text-sm">

              {manuallyHidden.size > 0 && (
                <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded p-3 flex justify-between items-center">
                  <span className="text-xs text-orange-800 dark:text-orange-300 font-semibold">
                    {manuallyHidden.size} element{manuallyHidden.size > 1 ? 's' : ''} hidden
                  </span>
                  <button
                    onClick={() => setManuallyHidden(new Set())}
                    className="text-[10px] bg-orange-200 dark:bg-orange-800 text-orange-800 dark:text-orange-200 px-2 py-1 rounded hover:bg-orange-300 dark:hover:bg-orange-700 transition-colors font-bold"
                  >
                    Unhide All
                  </button>
                </div>
              )}

              {Object.keys(expandedClusters).length > 0 && (
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded p-3">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs text-blue-800 dark:text-blue-300 font-semibold">
                      {Object.keys(expandedClusters).length} expanded cluster
                      {Object.keys(expandedClusters).length > 1 ? 's' : ''}
                    </span>
                    <button
                      onClick={collapseAllClusters}
                      className="text-[10px] bg-blue-200 dark:bg-blue-800 text-blue-800 dark:text-blue-200 px-2 py-1 rounded hover:bg-blue-300 dark:hover:bg-blue-700 transition-colors font-bold"
                    >
                      Collapse All
                    </button>
                  </div>
                  <div className="space-y-1">
                    {Object.entries(expandedClusters).map(([clusterId, info]) => (
                      <button
                        key={clusterId}
                        onClick={() => collapseCluster(clusterId)}
                        className="w-full text-left text-[10px] bg-white/60 dark:bg-slate-800/60 border border-blue-200 dark:border-blue-800 rounded px-2 py-1 hover:bg-white dark:hover:bg-slate-800 transition-colors font-mono truncate text-slate-700 dark:text-slate-300"
                        title={`Collapse ${info.memberIds.length} elements`}
                      >
                        {info.node?.data?.label || clusterId} · {info.memberIds.length} elements
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <label htmlFor="global-search" className="font-semibold text-xs text-slate-500 uppercase mb-2 block">Global Search</label>
                <input
                  id="global-search"
                  type="text"
                  value={globalSearch}
                  onChange={(e) => setGlobalSearch(e.target.value)}
                  placeholder="Search text or PID..."
                  aria-label="Global search"
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded p-2 focus:ring-1 focus:ring-blue-500 outline-none"
                />
                {searchHasNoMatches && (
                  <p className="mt-1 text-[10px] text-amber-600 dark:text-amber-400">
                    No elements match “{searchQuery}”.
                  </p>
                )}
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="font-semibold text-xs text-slate-500 uppercase block">Event Types</label>
                  <div className="flex gap-2">
                    <button onClick={() => setAllEvents(true)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">All</button>
                    <button onClick={() => setAllEvents(false)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">None</button>
                  </div>
                </div>
                <input
                  type="text"
                  value={eventTypeSearch}
                  onChange={(e) => setEventTypeSearch(e.target.value)}
                  placeholder="Search event types..."
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded p-1.5 mb-2 focus:ring-1 focus:ring-blue-500 outline-none text-xs"
                />
                <div className="max-h-40 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded custom-scrollbar">
                  {filteredEventTypes.length === 0 ? (
                    <p className="text-xs text-slate-500 dark:text-slate-400 italic">No matches.</p>
                  ) : (
                    filteredEventTypes.map(evt => (
                      <label key={evt} className="flex items-center gap-2 cursor-pointer text-xs">
                        <input type="checkbox" checked={eventTypes[evt]} onChange={() => toggleEvent(evt)} className="rounded text-blue-500" />
                        <span className="truncate" title={evt}>{evt}</span>
                      </label>
                    ))
                  )}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="font-semibold text-xs text-slate-500 uppercase block">Users</label>
                  <div className="flex gap-2">
                    <button onClick={() => setAllUsers(true)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">All</button>
                    <button onClick={() => setAllUsers(false)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">None</button>
                  </div>
                </div>
                <input
                  type="text"
                  value={userSearch}
                  onChange={(e) => setUserSearch(e.target.value)}
                  placeholder="Search users..."
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded p-1.5 mb-2 focus:ring-1 focus:ring-blue-500 outline-none text-xs"
                />
                <div className="max-h-40 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded custom-scrollbar">
                  {filteredUsers.length === 0 ? (
                    <p className="text-xs text-slate-500 dark:text-slate-400 italic">No matches.</p>
                  ) : (
                    filteredUsers.map(usr => (
                      <label key={usr} className="flex items-center gap-2 cursor-pointer text-xs">
                        <input type="checkbox" checked={users[usr]} onChange={() => toggleUser(usr)} className="rounded text-blue-500" />
                        <span className="truncate" title={usr}>{usr}</span>
                      </label>
                    ))
                  )}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="font-semibold text-xs text-slate-500 uppercase block">Process IDs (PIDs)</label>
                  <div className="flex gap-2">
                    <button onClick={() => setAllPids(true)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">All</button>
                    <button onClick={() => setAllPids(false)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">None</button>
                  </div>
                </div>
                <input
                  type="text"
                  value={pidSearch}
                  onChange={(e) => setPidSearch(e.target.value)}
                  placeholder="Search PIDs..."
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded p-1.5 mb-2 focus:ring-1 focus:ring-blue-500 outline-none text-xs"
                />
                <div className="max-h-40 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded custom-scrollbar">
                  {filteredPids.length === 0 ? (
                    <p className="text-xs text-slate-500 dark:text-slate-400 italic">No matches.</p>
                  ) : (
                    filteredPids.map(pid => {
                      const label = pidLabel(pid);
                      return (
                        <label key={pid} className="flex items-center gap-2 cursor-pointer text-xs">
                          <input type="checkbox" checked={pids[pid]} onChange={() => togglePid(pid)} className="rounded text-blue-500" />
                          <span className="truncate" title={label}>{label}</span>
                        </label>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
