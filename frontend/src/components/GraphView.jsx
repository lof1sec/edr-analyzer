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

  useEffect(() => {
    if (!datasetId) return;
    const fetchGraph = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/graph/${datasetId}`);
        const data = await res.json();

        // Initial setup for filters based on incoming data
        const uniqueEvents = new Set();
        const uniqueUsers = new Set();

        data.elements.edges?.forEach(e => {
          if (e.data.event_simplename) uniqueEvents.add(e.data.event_simplename);
        });

        data.elements.nodes?.forEach(n => {
          if (n.data.group === 'process' && n.data.username) uniqueUsers.add(n.data.username);
        });

        setEventTypes(Array.from(uniqueEvents).reduce((acc, evt) => ({ ...acc, [evt]: true }), {}));
        setUsers(Array.from(uniqueUsers).reduce((acc, usr) => ({ ...acc, [usr]: true }), {}));

        // Convert to cytoscape flat format
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
        }

        // Global text search
        if (isVisible && terms.length > 0) {
          const text = ((d.title || "") + " " + (d.label || "")).toLowerCase();
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
  }, [globalSearch, eventTypes, users, elements]);

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
  const toggleUser = (usr) => setUsers(p => ({ ...p, [usr]: !p[usr] }));

  return (
    <div className="flex-1 flex relative">

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
            cy.on('tap', (e) => {
              if (e.target === cy) setSelectedNode(null);
            });
          }}
        />
      </div>

      {/* Filter Sidebar (Right) */}
      <div className="w-72 bg-white dark:bg-slate-800 border-l border-slate-200 dark:border-slate-700 flex flex-col h-full overflow-y-auto">
        <div className="p-4 border-b border-slate-200 dark:border-slate-700">
          <h3 className="font-bold">Filters & Search</h3>
        </div>

        <div className="p-4 space-y-6 text-sm">
          <div>
            <label className="font-semibold text-xs text-slate-500 uppercase mb-2 block">Global Search</label>
            <input
              type="text"
              value={globalSearch}
              onChange={(e) => setGlobalSearch(e.target.value)}
              placeholder="Search..."
              className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded p-2 focus:ring-1 focus:ring-blue-500 outline-none"
            />
          </div>

          <div>
            <label className="font-semibold text-xs text-slate-500 uppercase mb-2 block">Event Types</label>
            <div className="max-h-40 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded">
              {Object.keys(eventTypes).sort().map(evt => (
                <label key={evt} className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={eventTypes[evt]} onChange={() => toggleEvent(evt)} className="rounded text-blue-500" />
                  <span className="truncate" title={evt}>{evt}</span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="font-semibold text-xs text-slate-500 uppercase mb-2 block">Users</label>
            <div className="max-h-40 overflow-y-auto space-y-1 p-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded">
              {Object.keys(users).sort().map(usr => (
                <label key={usr} className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={users[usr]} onChange={() => toggleUser(usr)} className="rounded text-blue-500" />
                  <span className="truncate" title={usr}>{usr}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Detail Modal/Panel */}
      {selectedNode && (
        <div className="absolute bottom-4 left-4 w-96 bg-white dark:bg-slate-800 shadow-xl border border-slate-200 dark:border-slate-600 rounded-lg flex flex-col z-10">
          <div className="p-3 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center bg-slate-50 dark:bg-slate-900 rounded-t-lg">
            <h4 className="font-bold text-sm text-blue-600 dark:text-blue-400">Node Details</h4>
            <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-600 dark:hover:text-white">✕</button>
          </div>
          <div className="p-4 overflow-y-auto max-h-96">
            <pre className="text-xs whitespace-pre-wrap font-mono text-slate-700 dark:text-green-400 bg-slate-50 dark:bg-black p-3 rounded border border-slate-200 dark:border-slate-700">
              {selectedNode.title || selectedNode.label}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
