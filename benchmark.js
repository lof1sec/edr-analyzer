const { performance } = require('perf_hooks');

const NUM_ELEMENTS = 50000;
const NUM_PIDS = 5000;

const elements = [];
for (let i = 0; i < NUM_ELEMENTS; i++) {
  elements.push({
    data: {
      id: `pid_${i}`,
      process_name: `process_${i}`
    }
  });
}

// Add some edges too, which might not have id or process_name
for (let i = 0; i < 50000; i++) {
    elements.push({
        data: {
            source: `pid_${i}`,
            target: `pid_${i+1}`
        }
    })
}


const pids = {};
for (let i = 0; i < NUM_PIDS; i++) {
  pids[`pid_${i}`] = true;
}

// Unoptimized baseline
function runBaseline() {
  const start = performance.now();
  const sortedPids = Object.keys(pids).sort();
  const result = [];
  for (const pid of sortedPids) {
    const node = elements.find(el => el.data && el.data.id === pid);
    const label = node && node.data.process_name ? `${node.data.process_name} (${pid})` : pid;
    result.push(label);
  }
  const end = performance.now();
  return end - start;
}

// Optimized
function runOptimized() {
  const start = performance.now();
  const sortedPids = Object.keys(pids).sort();

  const elementsById = new Map();
  for (const el of elements) {
    if (el.data && el.data.id) {
      elementsById.set(el.data.id, el);
    }
  }

  const result = [];
  for (const pid of sortedPids) {
    const node = elementsById.get(pid);
    const label = node && node.data.process_name ? `${node.data.process_name} (${pid})` : pid;
    result.push(label);
  }
  const end = performance.now();
  return end - start;
}

console.log("Warming up...");
runBaseline();
runOptimized();

console.log("Running baseline...");
const baseResult = runBaseline();
console.log(`Baseline time: ${baseResult.toFixed(2)}ms`);

console.log("Running optimized...");
const optResult = runOptimized();
console.log(`Optimized time: ${optResult.toFixed(2)}ms`);

console.log(`Improvement: ${(baseResult / optResult).toFixed(2)}x faster`);
