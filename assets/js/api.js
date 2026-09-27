window.MSTApi = (() => {
  const baseUrl = window.MST_API_BASE || 'http://localhost:8081/api';

  async function apiRequest(path, options = {}) {
    const response = await fetch(`${baseUrl}${path}`, { credentials: 'include', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options });
    const payload = await response.json().catch(() => ({ success: false, message: 'Invalid API response' }));
    if (!response.ok || payload.success === false) { const error = new Error(payload.message || 'API request failed'); error.status = response.status; error.payload = payload; throw error; }
    return payload;
  }
  return { apiRequest, apiGet: (path) => apiRequest(path), apiPost: (path, data) => apiRequest(path, { method: 'POST', body: JSON.stringify(data) }), apiPut: (path, data) => apiRequest(path, { method: 'PUT', body: JSON.stringify(data) }), apiDelete: (path) => apiRequest(path, { method: 'DELETE' }), authMe: () => apiRequest('/auth/me') };
})();
