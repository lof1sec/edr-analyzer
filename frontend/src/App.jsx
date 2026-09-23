import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import GraphView from './components/GraphView';

function App() {
  const [theme, setTheme] = useState('dark');
  const [datasets, setDatasets] = useState([]);
  const [activeDataset, setActiveDataset] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  const fetchDatasets = async () => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/datasets`);
      const data = await res.json();
      setDatasets(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchDatasets();
  }, []);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-white dark:bg-slate-900 transition-colors duration-200">
      <Sidebar
        theme={theme}
        setTheme={setTheme}
        datasets={datasets}
        activeDataset={activeDataset}
        setActiveDataset={setActiveDataset}
        fetchDatasets={fetchDatasets}
        isUploading={isUploading}
        setIsUploading={setIsUploading}
        isOpen={isSidebarOpen}
        setIsOpen={setIsSidebarOpen}
      />
      <GraphView
        datasetId={activeDataset}
        theme={theme}
      />
    </div>
  );
}

export default App;
