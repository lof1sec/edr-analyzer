import React from 'react';
import { Upload, X, Database, Menu } from 'lucide-react';

export default function Sidebar({
  theme,
  setTheme,
  datasets,
  activeDataset,
  setActiveDataset,
  fetchDatasets,
  isUploading,
  setIsUploading,
  isOpen,
  setIsOpen
}) {

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/datasets/upload`, {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        await fetchDatasets();
      } else {
        alert('Upload failed.');
      }
    } catch (error) {
      console.error(error);
      alert('Upload failed due to network error.');
    } finally {
      setIsUploading(false);
      event.target.value = null;
    }
  };

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this dataset?')) return;
    try {
      await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/datasets/${id}`, {
        method: 'DELETE'
      });
      if (activeDataset === id) setActiveDataset(null);
      fetchDatasets();
    } catch (err) {
      console.error(err);
    }
  };

  if (!isOpen) {
    return (
      <div className="w-16 h-full bg-white dark:bg-slate-800 border-r border-slate-200 dark:border-slate-700 flex flex-col items-center py-4 transition-all duration-300 z-20 shrink-0">
        <button
          onClick={() => setIsOpen(true)}
          className="p-2 rounded-md hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors text-slate-500 dark:text-slate-400"
          title="Open Sidebar"
        >
          <Menu size={24} />
        </button>
      </div>
    );
  }

  return (
    <div className="w-80 h-full bg-white dark:bg-slate-800 border-r border-slate-200 dark:border-slate-700 flex flex-col transition-all duration-300 z-20 shrink-0">
      <div className="p-4 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <Database size={24} className="text-blue-500" />
          <h1 className="text-xl font-bold truncate">EDR Analyzer</h1>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            className="p-2 rounded-md hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
            title="Toggle Light/Dark Mode"
          >
            {theme === 'dark' ? '🌞' : '🌙'}
          </button>
          <button
            onClick={() => setIsOpen(false)}
            className="p-2 rounded-md hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors text-slate-500 dark:text-slate-400"
            title="Collapse Sidebar"
          >
            <Menu size={20} />
          </button>
        </div>
      </div>

      <div className="p-4 border-b border-slate-200 dark:border-slate-700">
        <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed rounded-lg cursor-pointer bg-slate-50 hover:bg-slate-100 dark:bg-slate-700 dark:border-slate-600 dark:hover:bg-slate-600 transition-colors">
          <div className="flex flex-col items-center justify-center pt-5 pb-6">
            <Upload className="w-8 h-8 mb-3 text-slate-500 dark:text-slate-400" />
            <p className="mb-2 text-sm text-slate-500 dark:text-slate-400">
              <span className="font-semibold">Click to upload CSV</span>
            </p>
            {isUploading && <p className="text-xs text-blue-500 font-bold">Uploading & Parsing...</p>}
          </div>
          <input type="file" className="hidden" accept=".csv" onChange={handleFileUpload} disabled={isUploading} />
        </label>
      </div>

      <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-4">
          Datasets
        </h2>
        <div className="space-y-2">
          {datasets.map((ds) => (
            <div
              key={ds.id}
              onClick={() => setActiveDataset(ds.id)}
              className={`p-3 rounded-lg border cursor-pointer flex justify-between items-start transition-all ${
                activeDataset === ds.id
                  ? 'bg-blue-50 border-blue-500 dark:bg-blue-900/20 dark:border-blue-400'
                  : 'bg-white border-slate-200 hover:border-blue-300 dark:bg-slate-800 dark:border-slate-700 dark:hover:border-slate-500'
              }`}
            >
              <div className="overflow-hidden pr-2">
                <p className="font-medium text-sm truncate" title={ds.name}>{ds.name}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{ds.log_count} logs</p>
              </div>
              <button onClick={(e) => handleDelete(ds.id, e)} className="text-slate-400 hover:text-red-500 transition-colors shrink-0">
                <X size={16} />
              </button>
            </div>
          ))}
          {datasets.length === 0 && (
            <p className="text-sm text-slate-500 dark:text-slate-400 text-center italic mt-10">No datasets found.</p>
          )}
        </div>
      </div>
    </div>
  );
}
