const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

/**
 * Perform a request against the backend API and normalise errors.
 *
 * Non-2xx responses are turned into an Error carrying the backend `detail`
 * message, so callers can show something meaningful to the user.
 */
async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, options);

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (body && body.detail) detail = body.detail;
    } catch {
      // Not a JSON error body; keep the generic message.
    }
    throw new Error(detail);
  }

  if (response.status === 204) {
    return null;
  }
  return response.json();
}

export const api = {
  listDatasets: () => request('/api/datasets'),

  uploadDataset: (formData) =>
    request('/api/datasets/upload', { method: 'POST', body: formData }),

  deleteDataset: (id) =>
    request(`/api/datasets/${id}`, { method: 'DELETE' }),

  getGraph: (id) => request(`/api/graph/${id}`),

  getElementLogs: (id, elementId) =>
    request(`/api/graph/${id}/element-logs?element_id=${encodeURIComponent(elementId)}`),

  searchGraph: (id, query) =>
    request(`/api/graph/${id}/search?q=${encodeURIComponent(query)}`),
};

export { API_URL };
