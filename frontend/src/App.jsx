import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import GraphView from './components/GraphView';
import AuthPage from './components/AuthPage';
import { api } from './api/client';

function App() {
  const [authState, setAuthState] = useState({
    loading: true,
    authenticated: false,
    needsSetup: false,
    username: null,
  });
  const [datasets, setDatasets] = useState([]);
  const [activeDataset, setActiveDataset] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  const checkAuth = async () => {
    try {
      const status = await api.authStatus();
      setAuthState({
        loading: false,
        authenticated: status.authenticated,
        needsSetup: status.needs_setup,
        username: status.username,
      });
    } catch (err) {
      console.error(err);
      setAuthState({ loading: false, authenticated: false, needsSetup: false, username: null });
    }
  };

  const fetchDatasets = async () => {
    try {
      const data = await api.listDatasets();
      setDatasets(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  // Datasets are only fetched once there is an authenticated session.
  useEffect(() => {
    if (authState.authenticated) fetchDatasets();
  }, [authState.authenticated]);

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch (err) {
      console.error(err);
    }
    setDatasets([]);
    setActiveDataset(null);
    setAuthState({ loading: false, authenticated: false, needsSetup: false, username: null });
  };

  if (authState.loading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-slate-50 dark:bg-slate-900">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!authState.authenticated) {
    return <AuthPage needsSetup={authState.needsSetup} onAuthenticated={checkAuth} />;
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-white dark:bg-slate-900 transition-colors duration-200">
      <Sidebar
        datasets={datasets}
        activeDataset={activeDataset}
        setActiveDataset={setActiveDataset}
        fetchDatasets={fetchDatasets}
        isUploading={isUploading}
        setIsUploading={setIsUploading}
        isOpen={isSidebarOpen}
        setIsOpen={setIsSidebarOpen}
        username={authState.username}
        onLogout={handleLogout}
      />
      <GraphView
        datasetId={activeDataset}
      />
    </div>
  );
}

export default App;
