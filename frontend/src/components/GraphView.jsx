import React, { useState, useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import CytoscapeComponent from 'react-cytoscapejs';
import { stylesheet } from './cytoscapeStyles';

export default function GraphView({ datasetId, theme }) {
  const [elements, setElements] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const cyRef = useRef(null);

  // Filters state
  const [globalSearch, setGlobalSearch] = useState('');
  const [eventTypes, setEventTypes] = useState({});
  const [users, setUsers] = useState({});
  const [pids, setPids] = useState({});

  useEffect(() => {
    if (!datasetId) return;
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

        // Standard filter for process nodes
        if (d.group === 'process') {
          if (d.username && users[d.username] === false) isVisible = false;
          if (d.id && pids[d.id] === false) isVisible = false;
        }

        // Global text search
        if (isVisible && terms.length > 0) {
          const text = ((d.title || "") + " " + (d.label || "") + " " + (d.id || "")).toLowerCase();
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

        if (d.event_simplename && eventTypes[d.event_simplename] === false) {
          isVisible = false;
        }

        // If source or target is hidden, edge must be hidden
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
  }, [globalSearch, eventTypes, users, pids, elements]);

  const layout = {
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

  const handleNodeClick = (e) => {
    const node = e.target;
    setSelectedNode(node.data());
  };

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
    <div className="flex-1 flex relative overflow-hidden">

      {/* Cytoscape Container */}
      <div className="flex-1 relative bg-slate-100 dark:bg-[#222]">
        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet(theme)}
          layout={layout}
          style={{ width: '100%', height: '100%' }}
          cy={(cy) => {
            cyRef.current = cy;
            cy.on('tap', 'node', handleNodeClick);
            cy.on('tap', 'edge', handleNodeClick); // Added edge click
            cy.on('tap', (e) => {
              if (e.target === cy) setSelectedNode(null);
            });
          }}
        />
      </div>

      {/* Right Pane: Filters OR Details depending on state */}
      <div className="w-80 bg-white dark:bg-slate-800 border-l border-slate-200 dark:border-slate-700 flex flex-col h-full overflow-hidden transition-all duration-300 z-10 shrink-0 shadow-lg relative">

        {/* Toggle View Header */}
        <div className="flex border-b border-slate-200 dark:border-slate-700">
           <button
             className={`flex-1 p-3 text-sm font-bold transition-colors ${!selectedNode ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700'}`}
             onClick={() => setSelectedNode(null)}
           >
             Filters
           </button>
           <button
             className={`flex-1 p-3 text-sm font-bold transition-colors ${selectedNode ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-700'}`}
           >
             Node Details
           </button>
        </div>

        {/* Scrollable Content Area */}
        <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">

          {/* Details Pane Content */}
          {selectedNode ? (
            <div className="space-y-4">
              <h4 className="font-bold text-lg text-slate-800 dark:text-white break-words">
                {selectedNode.label || selectedNode.event_simplename || "Selected Element"}
              </h4>

              <div className="bg-slate-50 dark:bg-black p-3 rounded border border-slate-200 dark:border-slate-700 text-xs font-mono text-slate-700 dark:text-green-400 overflow-x-auto">
                <pre>{selectedNode.title || (selectedNode.label ? "No title" : "Edge")}</pre>
              </div>

              {selectedNode.raw_logs && selectedNode.raw_logs.length > 0 && (
                <div className="mt-4">
                  <h5 className="font-bold text-sm text-slate-600 dark:text-slate-300 mb-2 border-b border-slate-200 dark:border-slate-700 pb-1">Raw Log Events</h5>
                  {selectedNode.raw_logs.map((log, idx) => (
                    <div key={idx} className="mb-4 bg-slate-100 dark:bg-slate-900 p-2 rounded border border-slate-200 dark:border-slate-600 text-xs font-mono overflow-x-auto text-slate-800 dark:text-slate-200">
                      <pre>{JSON.stringify(log, null, 2)}</pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (

          {/* Filters Pane Content */}
            <div className="space-y-6 text-sm">
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
                <div className="flex justify-between items-center mb-2">
                  <label className="font-semibold text-xs text-slate-500 uppercase block">Event Types</label>
                  <div className="flex gap-2">
                    <button onClick={() => setAllEvents(true)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">All</button>
                    <button onClick={() => setAllEvents(false)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">None</button>
                  </div>
                </div>
                <div className="max-h-40 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded custom-scrollbar">
                  {Object.keys(eventTypes).sort().map(evt => (
                    <label key={evt} className="flex items-center gap-2 cursor-pointer text-xs">
                      <input type="checkbox" checked={eventTypes[evt]} onChange={() => toggleEvent(evt)} className="rounded text-blue-500" />
                      <span className="truncate" title={evt}>{evt}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-2">
                  <label className="font-semibold text-xs text-slate-500 uppercase block">Users</label>
                  <div className="flex gap-2">
                    <button onClick={() => setAllUsers(true)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">All</button>
                    <button onClick={() => setAllUsers(false)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">None</button>
                  </div>
                </div>
                <div className="max-h-40 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded custom-scrollbar">
                  {Object.keys(users).sort().map(usr => (
                    <label key={usr} className="flex items-center gap-2 cursor-pointer text-xs">
                      <input type="checkbox" checked={users[usr]} onChange={() => toggleUser(usr)} className="rounded text-blue-500" />
                      <span className="truncate" title={usr}>{usr}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-2">
                  <label className="font-semibold text-xs text-slate-500 uppercase block">Process IDs (PIDs)</label>
                  <div className="flex gap-2">
                    <button onClick={() => setAllPids(true)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">All</button>
                    <button onClick={() => setAllPids(false)} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600">None</button>
                  </div>
                </div>
                <div className="max-h-40 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded custom-scrollbar">
                  {Object.keys(pids).sort().map(pid => {
                    const node = elements.find(el => el.data && el.data.id === pid);
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
    </div>
  );
}
