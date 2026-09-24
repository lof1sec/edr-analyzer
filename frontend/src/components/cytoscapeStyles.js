// Translate the vis-network physics/colors to cytoscape standard styles.

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
  {
    selector: 'node[group="process"]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#4d0000',
      'border-color': '#ff4d4d',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="file"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#00264d',
      'border-color': '#4da6ff',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="module"]',
    style: {
      'shape': 'hexagon',
      'background-color': '#4d0099',
      'border-color': '#b366ff',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="registry"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#804000',
      'border-color': '#ff9933',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="network"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#003333',
      'border-color': '#00ffff',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="commandline"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#332b00',
      'border-color': '#ffcc00',
      'border-width': 1,
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="alert"]',
    style: {
      'shape': 'star',
      'background-color': '#b30000',
      'border-color': '#ff0000',
      'border-width': 3,
      'color': '#fff'
    }
  },
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
  }
];
