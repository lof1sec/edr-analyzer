import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import cytoscape from 'cytoscape';
import CytoscapeComponent from 'react-cytoscapejs';
import { Filter, X, Copy, Check } from 'lucide-react';
import { stylesheet } from './cytoscapeStyles';

// Sub-component for individual copy buttons
const CopyButton = ({ textToCopy }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors text-slate-600 dark:text-slate-300"
      title="Copy JSON"
    >
      {copied ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
    </button>
  );
};

export default function GraphView({ datasetId }) {
  const [elements, setElements] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [layoutMode, setLayoutMode] = useState('force');
  const cyRef = useRef(null);
  const initialPositions = useRef({});

  // Filters state
  const [globalSearch, setGlobalSearch] = useState('');
  const [eventTypes, setEventTypes] = useState({});
  const [users, setUsers] = useState({});
  const [pids, setPids] = useState({});

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

  const elementsById = useMemo(() => {
    const map = new Map();
    for (const el of elements) {
      if (el.data && el.data.id) {
        map.set(el.data.id, el);
      }
    }
    return map;
  }, [elements]);

  useEffect(() => {
    if (!datasetId) return;
    initialPositions.current = {}; // Reset positions on new dataset
    setLayoutMode('force');
    const fetchGraph = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/graph/${datasetId}`);
        const data = await res.json();

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

        setElements(cyElements);
        setUnmappedEvents(data.unmapped_events || []);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchGraph();
  }, [datasetId]);

  // Apply filters whenever state changes
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    cy.batch(() => {
      cy.elements().removeClass('hidden');

      const terms = globalSearch.toLowerCase().split(',').map(t => t.trim()).filter(Boolean);

      // Node filtering
      cy.nodes().forEach(node => {
        let isVisible = true;
        const d = node.data();

        if (d.id && manuallyHidden.has(d.id)) {
          isVisible = false;
        }

        if (isVisible && d.group === 'process') {
          if (d.username && users[d.username] === false) isVisible = false;
          if (d.id && pids[d.id] === false) isVisible = false;
        }

        if (isVisible && terms.length > 0) {
          const rawLogsStr = d.raw_logs ? JSON.stringify(d.raw_logs).toLowerCase() : "";
          const text = ((d.title || "") + " " + (d.label || "") + " " + (d.id || "") + " " + rawLogsStr).toLowerCase();
          isVisible = terms.some(term => text.includes(term));
        }

        if (!isVisible) {
          node.addClass('hidden');
        }
      });

      // Edge filtering
      cy.edges().forEach(edge => {
        const d = edge.data();
        let isVisible = true;

        if (d.id && manuallyHidden.has(d.id)) {
          isVisible = false;
        }

        if (d.event_simplename && eventTypes[d.event_simplename] === false) {
          isVisible = false;
        }

        // Global search match for edges
        if (isVisible && terms.length > 0) {
          const rawLogsStr = d.raw_logs ? JSON.stringify(d.raw_logs).toLowerCase() : "";
          const text = ((d.title || "") + " " + (d.label || "") + " " + (d.id || "") + " " + (d.event_simplename || "") + " " + rawLogsStr).toLowerCase();
          const edgeMatches = terms.some(term => text.includes(term));

          if (edgeMatches) {
            // If edge matches, reveal its source and target nodes so the edge can be drawn,
            // EXCEPT if they are manually hidden.
            if (!manuallyHidden.has(edge.source().id())) {
              edge.source().removeClass('hidden');
            }
            if (!manuallyHidden.has(edge.target().id())) {
              edge.target().removeClass('hidden');
            }
          }
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
          if(node.data('group') !== 'process' && !node.hasClass('hidden')){
              const visibleEdges = node.connectedEdges().filter(e => !e.hasClass('hidden'));
              if(visibleEdges.length === 0){
                  node.addClass('hidden');
              }
          }
      })
    });
  }, [globalSearch, eventTypes, users, pids, elements, manuallyHidden]);

  const getLayoutConfig = (mode, cy, selectedNode) => {
    switch(mode) {
      case 'tree':
        return {
          name: 'breadthfirst',
          directed: true,
          spacingFactor: 1.5,
          fit: true,
          padding: 30,
          animate: true,
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
          animate: true,
          animationDuration: 300,
          concentric: (node) => {
             // Center on selected node if one exists
             if (selectedNode && selectedNode.id === node.id()) {
               return 100;
             }
             // Otherwise use degree centrality
             return node.degree();
          },
          levelWidth: (nodes) => 1
        };
      case 'force':
      default:
        // If we already saved the initial force-directed positions, snap back to them immediately
        if (Object.keys(initialPositions.current).length > 0) {
           return {
             name: 'preset',
             positions: initialPositions.current,
             fit: true,
             padding: 30,
             animate: true,
             animationDuration: 300
           };
        }

        return {
          name: 'cose',
          idealEdgeLength: 100,
          nodeOverlap: 20,
          refresh: 20,
          fit: true,
          padding: 30,
          randomize: false,
          componentSpacing: 100,
          nodeRepulsion: 400000,
          edgeElasticity: 100,
          nestingFactor: 5,
          gravity: 80,
          numIter: 1000,
          initialTemp: 200,
          coolingFactor: 0.95,
          minTemp: 1.0
        };
    }
  };

  const layout = getLayoutConfig(layoutMode, cyRef.current, selectedNode);

  const applyLayout = (mode) => {
    setLayoutMode(mode);
    if (cyRef.current) {
        cyRef.current.layout(getLayoutConfig(mode, cyRef.current, selectedNode)).run();
    }
  }

  const fitGraph = () => {
      if(cyRef.current) cyRef.current.fit(cyRef.current.elements().not('.hidden'), 30);
  }

  const handleNodeClick = (e) => {
    const node = e.target;
    setSelectedNode(node.data());
    if (!isRightPaneOpen) {
      setIsRightPaneOpen(true);
    }
    setActiveTab('details');
  };

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
      <div className="flex-1 flex items-center justify-center text-slate-400">
        Select or upload a dataset to view the graph.
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  const toggleEvent = (evt) => setEventTypes(p => ({ ...p, [evt]: !p[evt] }));
  const setAllEvents = (val) => setEventTypes(p => Object.keys(p).reduce((acc, k) => ({ ...acc, [k]: val }), {}));

  const toggleUser = (usr) => setUsers(p => ({ ...p, [usr]: !p[usr] }));
  const setAllUsers = (val) => setUsers(p => Object.keys(p).reduce((acc, k) => ({ ...acc, [k]: val }), {}));

  const togglePid = (pid) => setPids(p => ({ ...p, [pid]: !p[pid] }));
  const setAllPids = (val) => setPids(p => Object.keys(p).reduce((acc, k) => ({ ...acc, [k]: val }), {}));

  return (
    <div className="flex-1 flex relative overflow-hidden w-full h-full">

      {/* Cytoscape Container */}
      <div id="cy-container" className="flex-1 min-w-0 relative bg-slate-100 dark:bg-[#222]">

        {/* Layout Toolbar */}
        <div className="absolute top-4 left-4 z-10 flex gap-2">
            <select
                value={layoutMode}
                onChange={(e) => applyLayout(e.target.value)}
                className="bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-3 py-1.5 text-xs font-semibold shadow hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors outline-none"
            >
                <option value="force">Layout: Force-directed</option>
                <option value="tree">Layout: Tree</option>
                <option value="centered">Layout: Centered</option>
            </select>
            <button
                onClick={fitGraph}
                className="bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-3 py-1.5 text-xs font-semibold shadow hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            >
                Fit Graph
            </button>
        </div>

        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet()}
          layout={layout}
          style={{ width: '100%', height: '100%' }}
          cy={(cy) => {
            cyRef.current = cy;

            // Try to capture initial layout positions when the physics simulation stops.
            // We only save it once per dataset so we can snap back to it later.
            cy.on('layoutstop', () => {
              if (Object.keys(initialPositions.current).length === 0 && layoutMode === 'force') {
                cy.nodes().forEach(node => {
                  initialPositions.current[node.id()] = { ...node.position() };
                });
              }
            });

            cy.on('tap', 'node', handleNodeClick);
            cy.on('tap', 'edge', handleNodeClick);
            cy.on('tap', (e) => {
              if (e.target === cy) setSelectedNode(null);
            });
          }}
        />
      </div>

      {/* Right Pane: Filters OR Details depending on state */}
      {!isRightPaneOpen ? (
        <div className="w-16 h-full bg-white dark:bg-slate-800 border-l border-slate-200 dark:border-slate-700 flex flex-col items-center py-4 transition-all duration-300 z-20 shrink-0">
          <button
            onClick={() => setIsRightPaneOpen(true)}
            className="p-2 rounded-md hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors text-slate-500 dark:text-slate-400"
            title="Open Filters & Details"
          >
            <Filter size={24} />
          </button>
        </div>
      ) : (
        <div
          className="w-80 h-full bg-white dark:bg-slate-800 border-l border-slate-200 dark:border-slate-700 flex flex-col overflow-hidden transition-all duration-300 z-10 shrink-0 shadow-lg relative"
        >

          {/* Toggle View Header */}
          <div className="flex border-b border-slate-200 dark:border-slate-700">
             <button
               className={`flex-1 p-2 text-xs font-bold transition-colors ${activeTab === 'filters' ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700'}`}
               onClick={() => setActiveTab('filters')}
             >
               Filters
             </button>
             <button
               className={`flex-1 p-2 text-xs font-bold transition-colors ${activeTab === 'details' ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700'} ${!selectedNode && 'opacity-50 cursor-not-allowed'}`}
               onClick={() => selectedNode && setActiveTab('details')}
               disabled={!selectedNode}
             >
               Node Details
             </button>
             <button
               className={`flex-1 p-2 text-xs font-bold transition-colors ${activeTab === 'unmapped' ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700'}`}
               onClick={() => setActiveTab('unmapped')}
             >
               Unmapped Stats
             </button>
             <button
               onClick={() => setIsRightPaneOpen(false)}
               className="p-3 text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors border-l border-slate-200 dark:border-slate-700 shrink-0"
               title="Collapse Pane"
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
                          setSelectedNode(null);
                        }
                      }}
                      className="shrink-0 text-[10px] bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800 px-2 py-1 rounded hover:bg-red-200 dark:hover:bg-red-800/50 transition-colors font-semibold"
                      title="Hide this element from the graph"
                    >
                      Hide
                    </button>
                    {selectedNode.raw_logs && selectedNode.raw_logs.length > 0 && (
                       <CopyButton textToCopy={JSON.stringify(selectedNode.raw_logs, null, 2)} />
                    )}
                  </div>
                </div>

                <div className="bg-slate-50 dark:bg-black p-3 rounded border border-slate-200 dark:border-slate-700 text-xs font-mono text-slate-700 dark:text-green-400 overflow-x-auto">
                  <pre>{selectedNode.title || (selectedNode.label ? "No title" : "Edge")}</pre>
                </div>

                {selectedNode.raw_logs && selectedNode.raw_logs.length > 0 && (
                  <div className="mt-4">
                    <h5 className="font-bold text-sm text-slate-600 dark:text-slate-300 mb-2 border-b border-slate-200 dark:border-slate-700 pb-1">Raw Log Events</h5>
                    {selectedNode.raw_logs.map((log, idx) => {
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
                )}
              </div>
            ) : activeTab === 'unmapped' ? (

            /* Unmapped Stats Pane Content */
              <div className="space-y-4">
                <h4 className="font-bold text-sm text-slate-800 dark:text-white border-b border-slate-200 dark:border-slate-700 pb-2">
                  Unmapped Events ({unmappedEvents.length})
                </h4>
                {unmappedEvents.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">All events have been successfully mapped.</p>
                ) : (
                  <div className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded p-2 overflow-y-auto max-h-[60vh] custom-scrollbar">
                    <ul className="list-disc list-inside space-y-1">
                      {Object.entries(unmappedEvents.reduce((acc, evt) => {
                        acc[evt] = (acc[evt] || 0) + 1;
                        return acc;
                      }, {})).map(([evt, count], idx) => (
                        <li key={idx} className="text-xs font-mono text-slate-700 dark:text-slate-300 truncate" title={`${evt} (${count})`}>
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

              <div>
                <label className="font-semibold text-xs text-slate-500 uppercase mb-2 block">Global Search</label>
                <input
                  type="text"
                  value={globalSearch}
                  onChange={(e) => setGlobalSearch(e.target.value)}
                  placeholder="Search text or PID..."
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded p-2 focus:ring-1 focus:ring-blue-500 outline-none"
                />
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
                  {Object.keys(eventTypes).sort()
                    .filter(evt => evt.toLowerCase().includes(eventTypeSearch.toLowerCase()))
                    .map(evt => (
                    <label key={evt} className="flex items-center gap-2 cursor-pointer text-xs">
                      <input type="checkbox" checked={eventTypes[evt]} onChange={() => toggleEvent(evt)} className="rounded text-blue-500" />
                      <span className="truncate" title={evt}>{evt}</span>
                    </label>
                  ))}
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
                  {Object.keys(users).sort()
                    .filter(usr => usr.toLowerCase().includes(userSearch.toLowerCase()))
                    .map(usr => (
                    <label key={usr} className="flex items-center gap-2 cursor-pointer text-xs">
                      <input type="checkbox" checked={users[usr]} onChange={() => toggleUser(usr)} className="rounded text-blue-500" />
                      <span className="truncate" title={usr}>{usr}</span>
                    </label>
                  ))}
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
                  {Object.keys(pids).sort()
                    .filter(pid => {
                      const node = elementsById.get(pid);
                      const label = node && node.data.process_name ? `${node.data.process_name} (${pid})` : pid;
                      return label.toLowerCase().includes(pidSearch.toLowerCase());
                    })
                    .map(pid => {
                    const node = elementsById.get(pid);
                    const label = node && node.data.process_name ? `${node.data.process_name} (${pid})` : pid;
                    return (
                      <label key={pid} className="flex items-center gap-2 cursor-pointer text-xs">
                        <input type="checkbox" checked={pids[pid]} onChange={() => togglePid(pid)} className="rounded text-blue-500" />
                        <span className="truncate" title={label}>{label}</span>
                      </label>
                    );
                  })}
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
