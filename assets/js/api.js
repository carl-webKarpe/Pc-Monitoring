window.MSTApi = (() => {
  const baseUrl = window.MST_API_BASE || 'http://localhost:8081/api';
  const CSRF_KEY = 'mstCsrf';
  const readToken = () => { try { return sessionStorage.getItem(CSRF_KEY) || ''; } catch { return ''; } };
  const saveToken = (token) => { try { if (token) sessionStorage.setItem(CSRF_KEY, token); else sessionStorage.removeItem(CSRF_KEY); } catch { /* storage unavailable */ } };

  // Signed-in pages go to the login page when the server says the session is gone (expired or signed out).
  // A page sends several requests at once: only the first one the server handles says SESSION_EXPIRED (the
  // others just find no session), so an "expired" answer always wins and a plain 401 waits briefly for one.
  let leaving = false;
  let plainTimer = null;
  function goToLogin(expired) {
    if (leaving) return;
    leaving = true;
    window.clearTimeout(plainTimer);
    saveToken('');
    try { sessionStorage.removeItem('mstRole'); } catch { /* storage unavailable */ }
    const prefix = window.location.pathname.includes('/management/') ? '../' : '';
    window.location.replace(`${prefix}login.html${expired ? '?expired=1' : ''}`);
  }
  function sessionEnded(code) {
    if (!document.getElementById('sidebar')) return;
    if (code === 'SESSION_EXPIRED') goToLogin(true);
    else if (!plainTimer) plainTimer = window.setTimeout(() => goToLogin(false), 500);
  }

  async function send(path, options) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    // Every change (POST/PUT/DELETE) carries this session's CSRF token; the server rejects it otherwise.
    if (method !== 'GET' && readToken()) headers['X-CSRF-Token'] = readToken();
    const response = await fetch(`${baseUrl}${path}`, { ...options, method, credentials: 'include', headers });
    const payload = await response.json().catch(() => ({ success: false, message: 'Invalid API response' }));
    if (path === '/auth/me' || path === '/auth/login') saveToken(payload?.data?.csrfToken || (response.ok ? readToken() : ''));
    return { response, payload };
  }

  async function apiRequest(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const isAuthCall = path.startsWith('/auth/');
    if (method !== 'GET' && !isAuthCall && !readToken()) await send('/auth/me', {});
    let { response, payload } = await send(path, options);
    // A stale token (e.g. after signing in again in another tab): refresh it once and retry.
    if (response.status === 403 && payload?.error?.code === 'CSRF_INVALID' && !isAuthCall) {
      await send('/auth/me', {});
      ({ response, payload } = await send(path, options));
    }
    if (response.status === 401 && !isAuthCall) sessionEnded(payload?.error?.code);
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
  return { apiRequest, apiGetOrDemo, sessionEnded, apiGet: (path) => apiRequest(path), apiPost: (path, data) => apiRequest(path, { method: 'POST', body: JSON.stringify(data) }), apiPut: (path, data) => apiRequest(path, { method: 'PUT', body: JSON.stringify(data) }), apiDelete: (path) => apiRequest(path, { method: 'DELETE' }), authMe: () => apiRequest('/auth/me'), logout: () => apiRequest('/auth/logout', { method: 'POST' }).finally(() => saveToken('')) };
})();
