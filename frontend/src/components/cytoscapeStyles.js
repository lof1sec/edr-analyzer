// Translate the vis-network physics/colors to cytoscape standard styles.

// Single source of truth for node groups: the Cytoscape stylesheet below and
// the legend in GraphView are both derived from it, so colors cannot drift.
export const NODE_GROUPS = [
  { group: 'process', label: 'Process', shape: 'round-rectangle', color: '#4d0000', border: '#ff4d4d' },
  { group: 'file', label: 'File', shape: 'rectangle', color: '#00264d', border: '#4da6ff' },
  { group: 'module', label: 'Module', shape: 'hexagon', color: '#4d0099', border: '#b366ff' },
  { group: 'registry', label: 'Registry', shape: 'rectangle', color: '#804000', border: '#ff9933' },
  { group: 'network', label: 'Network', shape: 'rectangle', color: '#003333', border: '#00ffff' },
  { group: 'commandline', label: 'Command line', shape: 'rectangle', color: '#332b00', border: '#ffcc00', borderWidth: 1 },
  { group: 'powershell', label: 'PowerShell', shape: 'rectangle', color: '#4d2e00', border: '#ff9900', borderWidth: 1 },
  // PowerShell command / command history artifacts (darker orange).
  { group: 'commandline-exec', label: 'Command exec', shape: 'rectangle', color: '#431407', border: '#c2410c', borderWidth: 1 },
  // Placeholder for a collapsed subtree; click to expand on demand.
  { group: 'cluster', label: 'Collapsed', shape: 'diamond', color: '#1e293b', border: '#94a3b8', borderWidth: 2 },
  { group: 'alert', label: 'Alert', shape: 'star', color: '#b30000', border: '#ff0000', borderWidth: 3 },
];

const groupStyle = ({ group, shape, color, border, borderWidth }) => ({
  selector: `node[group="${group}"]`,
  style: {
    'shape': shape,
    'background-color': color,
    'border-color': border,
    ...(borderWidth !== undefined ? { 'border-width': borderWidth } : {}),
    'color': '#fff',
  },
});

export const stylesheet = () => [
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'text-wrap': 'wrap',
      'text-max-width': '200px',
      'font-size': '10px',
      'font-family': 'monospace',
      'color': '#fff',
      'text-valign': 'center',
      'text-halign': 'center',
      'border-width': 2,
      'min-zoomed-font-size': 6,
      'width': 'label',
      'height': 'label',
      'padding': '12px',
    }
  },
  ...NODE_GROUPS.map(groupStyle),
  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': 'data(color)',
      'target-arrow-color': 'data(color)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'label': 'data(label)',
      'font-size': '8px',
      'color': '#aaa',
      'text-rotation': 'autorotate',
      'text-background-opacity': 1,
      'text-background-color': '#222',
      'min-zoomed-font-size': 5,
      'control-point-step-size': 40,
    }
  },
  {
    selector: 'edge[?dashed]',
    style: {
      'line-style': 'dashed'
    }
  },
  {
    selector: '.hidden',
    style: {
      'display': 'none'
    }
  },
  {
    // Spotlight: everything outside the selected element's neighbourhood.
    selector: '.dimmed',
    style: {
      'opacity': 0.12
    }
  },
  {
    selector: 'node:selected',
    style: {
      'border-width': 4,
      'border-color': '#ffffff',
      'overlay-opacity': 0
    }
  },
  {
    selector: 'edge:selected',
    style: {
      'width': 4
    }
  }
];
