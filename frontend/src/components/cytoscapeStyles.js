// Translate the vis-network physics/colors to cytoscape standard styles.

export const stylesheet = (theme) => [
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'text-wrap': 'wrap',
      'text-max-width': '150px',
      'font-size': '10px',
      'font-family': 'monospace',
      'color': theme === 'dark' ? '#fff' : '#000',
      'text-valign': 'center',
      'text-halign': 'center',
      'border-width': 2,
    }
  },
  {
    selector: 'node[group="process"]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#4d0000',
      'border-color': '#ff4d4d',
      'width': '120px',
      'height': '60px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="file"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#00264d',
      'border-color': '#4da6ff',
      'width': '100px',
      'height': '40px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="module"]',
    style: {
      'shape': 'hexagon',
      'background-color': '#4d0099',
      'border-color': '#b366ff',
      'width': '90px',
      'height': '50px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="registry"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#804000',
      'border-color': '#ff9933',
      'width': '100px',
      'height': '40px',
      'color': '#fff'
    }
  },
  {
    selector: 'node[group="network"]',
    style: {
      'shape': 'rectangle',
      'background-color': '#003333',
      'border-color': '#00ffff',
      'width': '100px',
      'height': '40px',
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
      'width': '150px',
      'height': '50px',
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
      'width': '80px',
      'height': '80px',
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
      'color': theme === 'dark' ? '#aaa' : '#555',
      'text-rotation': 'autorotate',
      'text-background-opacity': 1,
      'text-background-color': theme === 'dark' ? '#222' : '#fff',
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
