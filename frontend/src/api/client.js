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

  getElementLogs: (id, elementId) =>
    request(`/api/graph/${id}/element-logs?element_id=${encodeURIComponent(elementId)}`),

  searchGraph: (id, query) =>
    request(`/api/graph/${id}/search?q=${encodeURIComponent(query)}`),
};

export { API_URL };
