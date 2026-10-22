import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Clock, Network } from 'lucide-react';
import Sidebar from './components/Sidebar';
import GraphView from './components/GraphView';
import TimelineView from './components/TimelineView';
import AuthPage from './components/AuthPage';
import { api } from './api/client';
import { useTheme } from './hooks/useTheme';

const emptyGraphFilters = () => ({
  rangeFrom: null, rangeTo: null, globalSearch: '',
  eventTypes: {}, users: {}, pids: {},
});

function App() {
  const { theme, cycleTheme } = useTheme();
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
  const [view, setView] = useState('graph');
  // The graph remains mounted during playback; only the current event is highlighted.
  const [playbackEntry, setPlaybackEntry] = useState(null);
  const [playbackReadyId, setPlaybackReadyId] = useState(null);
  const [playbackError, setPlaybackError] = useState(null);
  const [graphFilters, setGraphFilters] = useState(emptyGraphFilters);
  const [savedHidden, setSavedHidden] = useState([]);
  const [viewLoading, setViewLoading] = useState(false);
  const [viewError, setViewError] = useState('');
  const selectionGeneration = useRef(0);

  const handleSelectTimelineElement = useCallback((entry) => {
    setPlaybackEntry(previous => entry?.focus_element_id
      ? { ...entry, requestId: (previous?.requestId || 0) + 1 }
      : null);
    setPlaybackReadyId(null);
    setPlaybackError(null);
  }, []);

  const handlePlaybackReady = useCallback((eventId) => setPlaybackReadyId(eventId), []);
  const handlePlaybackError = useCallback((message) => setPlaybackError(message), []);

  const selectDataset = useCallback((id) => {
    const generation = ++selectionGeneration.current;
    setActiveDataset(id);
    setGraphFilters(emptyGraphFilters());
    setSavedHidden([]);
    setViewError('');
    setViewLoading(Boolean(id));
    if (id) api.getView(id).then(({ view: saved }) => {
      if (selectionGeneration.current !== generation) return;
      if (saved) {
        setGraphFilters({ rangeFrom: saved.rangeFrom, rangeTo: saved.rangeTo,
          globalSearch: saved.globalSearch,
          eventTypes: Object.fromEntries(saved.hiddenEventTypes.map(value => [value, false])),
          users: Object.fromEntries(saved.hiddenUsers.map(value => [value, false])),
          pids: Object.fromEntries(saved.hiddenPids.map(value => [value, false])) });
        setSavedHidden(saved.hiddenElements);
      }
    }).catch(err => {
      if (selectionGeneration.current === generation) setViewError(`Could not restore saved view: ${err.message}`);
    }).finally(() => {
      if (selectionGeneration.current === generation) setViewLoading(false);
    });
    setPlaybackEntry(null);
    setPlaybackReadyId(null);
    setPlaybackError(null);
  }, []);

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
    selectionGeneration.current += 1;
    setActiveDataset(null);
    setPlaybackEntry(null);
    setPlaybackReadyId(null);
    setPlaybackError(null);
    setGraphFilters(emptyGraphFilters());
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
    <div className="relative flex h-screen w-screen overflow-hidden bg-white dark:bg-slate-900 transition-colors duration-200">
      <Sidebar
        datasets={datasets}
        activeDataset={activeDataset}
        setActiveDataset={selectDataset}
        fetchDatasets={fetchDatasets}
        isUploading={isUploading}
        setIsUploading={setIsUploading}
        isOpen={isSidebarOpen}
        setIsOpen={setIsSidebarOpen}
        username={authState.username}
        onLogout={handleLogout}
        theme={theme}
        onCycleTheme={cycleTheme}
      />
      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        <div className="flex items-center gap-1 px-3 py-1.5 border-b border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900">
          <button
            onClick={() => { setView('graph'); setPlaybackEntry(null); setPlaybackReadyId(null); }}
            aria-pressed={view === 'graph'}
            className={`flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded transition-colors ${
              view === 'graph'
                ? 'bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white'
                : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            <Network size={14} />
            Graph
          </button>
          <button
            onClick={() => setView('timeline')}
            aria-pressed={view === 'timeline'}
            className={`flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded transition-colors ${
              view === 'timeline'
                ? 'bg-slate-200 dark:bg-slate-700 text-slate-900 dark:text-white'
                : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            <Clock size={14} />
            Timeline
          </button>
        </div>
        <div className="flex-1 flex flex-col min-h-0 min-w-0">
          <div className="flex-1 min-h-0 min-w-0">
            {viewLoading ? <div className="p-4 text-slate-500" role="status">Loading saved view…</div> : <GraphView
              key={activeDataset}
              datasetId={activeDataset}
              graphFilters={graphFilters}
              setGraphFilters={setGraphFilters}
              initialHidden={savedHidden}
              initialViewError={viewError}
              playbackEntry={view === 'timeline' ? playbackEntry : null}
              onPlaybackReady={handlePlaybackReady}
              onPlaybackError={handlePlaybackError}
            />}
          </div>
          {view === 'timeline' && (
            <div className="h-[38vh] max-h-[50%] min-h-44 min-w-0 border-t border-slate-200 dark:border-slate-700">
              <TimelineView
                datasetId={activeDataset}
                graphFilters={graphFilters}
                onSelectElement={handleSelectTimelineElement}
                playbackReadyId={playbackReadyId}
                playbackError={playbackError}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
