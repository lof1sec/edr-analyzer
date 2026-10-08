const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

/**
 * Perform a request against the backend API and normalise errors.
 *
 * Sends cookies (the session is an httpOnly cookie) and turns non-2xx
 * responses into an Error carrying the backend `detail` message, so callers can
 * show something meaningful to the user. A 401 is surfaced with `status` so the
 * app can react to an expired session.
 */
async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    credentials: 'include',
    ...options,
  });

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (body && body.detail) detail = body.detail;
    } catch {
      // Not a JSON error body; keep the generic message.
    }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }

  if (response.status === 204) {
    return null;
  }
  return response.json();
}

function postJson(path, body) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export const api = {
  // Authentication
  authStatus: () => request('/api/auth/status'),

  setup: (username, password) => postJson('/api/auth/setup', { username, password }),

  login: (username, password) => postJson('/api/auth/login', { username, password }),

  logout: () => request('/api/auth/logout', { method: 'POST' }),

  me: () => request('/api/auth/me'),

  changePassword: (currentPassword, newPassword) =>
    postJson('/api/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),

  // Datasets
  listDatasets: () => request('/api/datasets'),

  uploadDataset: (formData) =>
    request('/api/datasets/upload', { method: 'POST', body: formData }),

  deleteDataset: (id) =>
    request(`/api/datasets/${id}`, { method: 'DELETE' }),

  // Graph
  getGraph: (id) => request(`/api/graph/${id}`),

  getGraphElements: (id, { offset = 0, limit = 500 } = {}) =>
    request(`/api/graph/${id}/elements?offset=${offset}&limit=${limit}`),


  getElementLogs: (id, elementId) =>
    request(`/api/graph/${id}/element-logs?element_id=${encodeURIComponent(elementId)}`),

  searchGraph: (id, query) =>
    request(`/api/graph/${id}/search?q=${encodeURIComponent(query)}`),

  getCluster: (id, clusterId) =>
    request(`/api/graph/${id}/clusters/${encodeURIComponent(clusterId)}`),

  getNeighbors: (id, elementId, depth = 1) =>
    request(
      `/api/graph/${id}/neighbors?element_id=${encodeURIComponent(elementId)}&depth=${depth}`
    ),

  getLayout: (id) => request(`/api/graph/${id}/layout`),

  saveLayout: (id, positions) =>
    request(`/api/graph/${id}/layout`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ positions }),
    }),

  getTimeline: (id, { offset = 0, limit = 200, eventType = '', q = '' } = {}) => {
    const params = new URLSearchParams();
    params.set('offset', String(offset));
    params.set('limit', String(limit));
    if (eventType) params.set('event_type', eventType);
    if (q) params.set('q', q);
    return request(`/api/graph/${id}/timeline?${params.toString()}`);
  },
};

export { API_URL };
