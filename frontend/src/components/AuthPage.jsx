import React, { useState } from 'react';
import { Database, Lock } from 'lucide-react';
import { api } from '../api/client';

/**
 * Full-screen authentication gate.
 *
 * Shows the first-run "create admin" form while no user exists, and the regular
 * login form afterwards. On success it hands the authenticated user back to the
 * app so it can load the datasets.
 */
export default function AuthPage({ needsSetup, onAuthenticated }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const isSetup = needsSetup;

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(null);

    if (isSetup && password !== confirm) {
      setError('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      const user = isSetup
        ? await api.setup(username, password)
        : await api.login(username, password);
      onAuthenticated(user);
    } catch (err) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const inputClass =
    'w-full bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded p-2 focus:ring-1 focus:ring-blue-500 outline-none';

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-slate-50 dark:bg-slate-900 px-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow p-6 space-y-4"
      >
        <div className="flex items-center gap-2">
          <Database size={24} className="text-blue-500" />
          <h1 className="text-xl font-bold">EDR Analyzer</h1>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {isSetup
            ? 'Create the administrator account to get started.'
            : 'Sign in to continue.'}
        </p>

        <div>
          <label className="font-semibold text-xs text-slate-500 uppercase mb-1 block">
            Username
          </label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className={inputClass}
          />
        </div>

        <div>
          <label className="font-semibold text-xs text-slate-500 uppercase mb-1 block">
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={isSetup ? 'new-password' : 'current-password'}
            required
            minLength={isSetup ? 12 : undefined}
            className={inputClass}
          />
          {isSetup && (
            <p className="mt-1 text-[10px] text-slate-500 dark:text-slate-400">
              At least 12 characters.
            </p>
          )}
        </div>

        {isSetup && (
          <div>
            <label className="font-semibold text-xs text-slate-500 uppercase mb-1 block">
              Confirm password
            </label>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              required
              className={inputClass}
            />
          </div>
        )}

        {error && (
          <p className="text-xs text-red-600 dark:text-red-400 break-words">{error}</p>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-3 py-2 rounded font-semibold transition-colors"
        >
          <Lock size={16} />
          {submitting ? 'Please wait…' : isSetup ? 'Create admin account' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
