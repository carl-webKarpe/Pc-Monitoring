window.MSTApi = (() => {
  const baseUrl = window.MST_API_BASE || 'http://localhost:8081/api';

  async function apiRequest(path, options = {}) {
    const response = await fetch(`${baseUrl}${path}`, { credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options });
    const payload = await response.json().catch(() => ({ success: false, message: 'Invalid API response' }));
    if (!response.ok || payload.success === false) { const error = new Error(payload.message || 'API request failed'); error.status = response.status; error.payload = payload; throw error; }
    return payload;
  }
  // Phase 7: pages load MySQL data through the API. If the API cannot be reached at all (network error),
  // the page keeps its built-in demo data so the UI still works offline. HTTP errors (401/403/500) are not hidden.
  async function apiGetOrDemo(path, demoData) {
    try {
      const { data } = await apiRequest(path);
      return { data, demo: false };
    } catch (error) {
      if (error.status) throw error;
      return { data: demoData, demo: true };
    }
  }
  return { apiRequest, apiGetOrDemo, apiGet: (path) => apiRequest(path), apiPost: (path, data) => apiRequest(path, { method: 'POST', body: JSON.stringify(data) }), apiPut: (path, data) => apiRequest(path, { method: 'PUT', body: JSON.stringify(data) }), apiDelete: (path) => apiRequest(path, { method: 'DELETE' }), authMe: () => apiRequest('/auth/me'), logout: () => apiRequest('/auth/logout', { method: 'POST' }) };
})();
