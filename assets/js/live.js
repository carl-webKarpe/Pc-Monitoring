// Live pages: every second a page asks the API for a tiny fingerprint of its data (/api/changes?scope=...) and reloads
// only when it changed, so a heartbeat, file event, scan, threat or log entry shows within about a second without
// loading everything every second. A full reload still runs every minute (times such as "2 min ago" move on).
// Usage: MSTLive.start('files', async () => { await loadFiles({ quiet: true }); return true; });
// The page shows the state in its <div class="live-status" data-live-status></div> badge.
window.MSTLive = (() => {
  const CHECK_MS = 1000;        // how often the page checks for changes
  const FULL_RELOAD_MS = 60000; // full reload at least this often
  const RETRY_MAX_MS = 15000;   // when the API cannot be reached, check at most this rarely
  const clock = () => new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' });

  function badge() {
    const element = document.querySelector('[data-live-status]');
    if (element && !element.dataset.ready) {
      element.dataset.ready = '1';
      element.classList.add('live-status');
      element.title = 'This page updates by itself within about a second';
      element.innerHTML = '<span class="live-dot"></span><span class="live-label">LIVE</span><small>Updated <b class="live-time">just now</b></small>';
    }
    return element;
  }

  function show(connected) {
    const element = badge();
    if (!element) return;
    element.classList.toggle('offline', !connected);
    element.querySelector('.live-label').textContent = connected ? 'LIVE' : 'RECONNECTING';
    if (connected) element.querySelector('.live-time').textContent = clock();
  }

  function start(scope, reload) {
    const state = { version: null, loadedAt: Date.now(), busy: false, delay: CHECK_MS, timer: null };
    badge();
    const check = async () => {
      if (state.busy) return;
      state.busy = true;
      try {
        const { data } = await window.MSTApi.apiGet(`/changes?scope=${encodeURIComponent(scope)}`);
        // The first answer only records the version: the page has just loaded its data.
        const changed = state.version !== null && data.version !== state.version;
        if (changed || Date.now() - state.loadedAt >= FULL_RELOAD_MS) {
          if ((await reload()) !== false) { state.version = data.version; state.loadedAt = Date.now(); }
        } else {
          state.version = data.version;
        }
        show(true);
        state.delay = CHECK_MS;
      } catch (error) {
        if (error.status === 401) return; // signed out: api.js goes to the login page
        show(false);
        state.delay = Math.min(RETRY_MAX_MS, state.delay * 2); // the API is down: try less often
      } finally {
        state.busy = false;
      }
    };
    const schedule = () => {
      window.clearTimeout(state.timer);
      state.timer = window.setTimeout(async () => { if (!document.hidden) await check(); schedule(); }, state.delay);
    };
    // Back to the tab: check at once instead of waiting.
    document.addEventListener('visibilitychange', () => { if (!document.hidden) { state.delay = CHECK_MS; check(); } });
    check().finally(schedule);
    return { check };
  }

  return { start };
})();
