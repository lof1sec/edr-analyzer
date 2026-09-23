// Translate the vis-network physics/colors to cytoscape standard styles.

export const stylesheet = (nodeStyle = 'detailed') => [
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'text-wrap': nodeStyle === 'compact' ? 'ellipsis' : 'wrap',
      'text-max-width': nodeStyle === 'compact' ? '40px' : '150px',
      'font-size': nodeStyle === 'compact' ? '6px' : '10px',
      'font-family': 'monospace',
      'color': '#fff',
      'text-valign': 'center',
      'text-halign': 'center',
      'border-width': nodeStyle === 'compact' ? 1 : 2,
    }
  },
  {
    selector: 'node[group="process"]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#4d0000',
      'border-color': '#ff4d4d',
      'width': nodeStyle === 'compact' ? '40px' : '120px',
      'height': nodeStyle === 'compact' ? '20px' : '60px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="file"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#00264d',
      'border-color': '#4da6ff',
      'width': nodeStyle === 'compact' ? '30px' : '100px',
      'height': nodeStyle === 'compact' ? '12px' : '40px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="module"]',
    style: {
      'shape': 'hexagon',
      'background-color': '#4d0099',
      'border-color': '#b366ff',
      'width': nodeStyle === 'compact' ? '30px' : '90px',
      'height': nodeStyle === 'compact' ? '16px' : '50px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="registry"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#804000',
      'border-color': '#ff9933',
      'width': nodeStyle === 'compact' ? '30px' : '100px',
      'height': nodeStyle === 'compact' ? '12px' : '40px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="network"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#003333',
      'border-color': '#00ffff',
      'width': nodeStyle === 'compact' ? '30px' : '100px',
      'height': nodeStyle === 'compact' ? '12px' : '40px',
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
      'width': nodeStyle === 'compact' ? '50px' : '150px',
      'height': nodeStyle === 'compact' ? '16px' : '50px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="alert"]',
    style: {
      'shape': 'star',
      'background-color': '#b30000',
      'border-color': '#ff0000',
      'border-width': nodeStyle === 'compact' ? 1 : 3,
      'width': nodeStyle === 'compact' ? '25px' : '80px',
      'height': nodeStyle === 'compact' ? '25px' : '80px',
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
