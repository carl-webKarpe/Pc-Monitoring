// Demo summary, only used when the MST API cannot be reached.
const dashboardData = {
  totalComputers: 24,
  onlineComputers: 18,
  offlineComputers: 6,
  threatsDetected: 7,
  filesScanned: 1284,
  safeFiles: 1261
};

// Normalizes the MySQL-backed /api/dashboard summary into the fields the stat cards use.
function fromApiSummary(summary) {
  return {
    totalComputers: summary.totalComputers,
    onlineComputers: summary.onlineComputers,
    offlineComputers: summary.offlineComputers,
    threatsDetected: summary.openThreats,
    totalThreats: summary.totalThreats,
    filesScanned: summary.totalScans,
    safeFiles: summary.safeScans
  };
}

async function fetchDashboardData() {
  const { data, demo } = await window.MSTApi.apiGetOrDemo('/dashboard', dashboardData);
  return { summary: demo ? data : fromApiSummary(data), demo };
}

async function fetchComputerStatus() { return (await window.MSTApi.apiGet('/computers?limit=5')).data; }
async function fetchThreatActivity() { return (await window.MSTApi.apiGet('/threats')).data; }
async function fetchNetworkActivity() { return Promise.resolve([]); }
async function fetchRecentScans() { return (await window.MSTApi.apiGet('/scans?limit=4')).data; }
async function fetchNotifications() { return Promise.resolve([]); }

async function fetchAccountCounts() {
  const count = (path) => window.MSTApi.apiGet(path).then(({ data }) => data.length).catch(() => '—');
  const [users, admins] = await Promise.all([count('/users'), count('/admins')]);
  return { users, admins };
}

function animateCounter(element, target) {
  const start = performance.now();
  const duration = 1200;

  const update = (now) => {
    const progress = Math.min((now - start) / duration, 1);
    element.textContent = Math.floor(progress * target).toLocaleString();
    if (progress < 1) requestAnimationFrame(update);
  };

  requestAnimationFrame(update);
}

const dashboardPercent = (part, total) => (total ? Math.round((part / total) * 100) : 0);

function renderDashboardStats(summary, accounts) {
  const statsGrid = document.getElementById('statsGrid');
  if (!statsGrid) return;
  const isAdmin = sessionStorage.getItem('mstRole') === 'admin';
  const onlineMeta = `${dashboardPercent(summary.onlineComputers, summary.totalComputers)}% of monitored PCs`;
  const stats = isAdmin ? [
    ['TOTAL COMPUTERS', summary.totalComputers, 'Monitored devices', 'fa-desktop', 'cyan'],
    ['ONLINE', summary.onlineComputers, onlineMeta, 'fa-circle-check', 'green'],
    ['OFFLINE', summary.offlineComputers, 'Requires attention', 'fa-circle-minus', 'gray'],
    ['THREATS DETECTED', summary.threatsDetected, 'Open threats', 'fa-shield-halved', 'red'],
    ['FILES SCANNED', summary.filesScanned, 'Scan records', 'fa-file-circle-check', 'cyan'],
    ['SAFE FILES', summary.safeFiles, `${dashboardPercent(summary.safeFiles, summary.filesScanned)}% clean`, 'fa-check', 'green']
  ] : [
    ['MONITORED PCs', summary.totalComputers, 'Authorized devices', 'fa-desktop', 'cyan'],
    ['ONLINE', summary.onlineComputers, onlineMeta, 'fa-circle-check', 'green'],
    ['THREATS', summary.threatsDetected, 'Requires oversight', 'fa-shield-halved', 'red'],
    ['FILES SCANNED', summary.filesScanned, 'Scan records', 'fa-file-circle-check', 'cyan'],
    ['SYSTEM USERS', accounts.users, 'Managed accounts', 'fa-users', 'cyan'],
    ['ADMINS', accounts.admins, 'Administrative accounts', 'fa-user-gear', 'blue']
  ];

  statsGrid.innerHTML = stats.map((item) => `
      <article class="metric-card card-surface">
        <div class="metric-header"><span class="metric-label">${item[0]}</span><span class="metric-icon ${item[4]}"><i class="fa-solid ${item[3]}"></i></span></div>
        <strong class="metric-value" data-value="${mstEscape(item[1])}">0</strong>
        <span class="metric-meta">${mstEscape(item[2])}</span>
      </article>
    `).join('');
  statsGrid.querySelectorAll('[data-value]').forEach((element) => {
    const value = Number(element.dataset.value);
    if (Number.isFinite(value)) animateCounter(element, value); else element.textContent = element.dataset.value;
  });
}

const dashboardStatus = { online: ['online', 'ONLINE'], warning: ['warning', 'WARNING'], offline: ['offline', 'OFFLINE'], threat: ['danger', 'THREAT'] };
const dashboardSeverity = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', SAFE: 'resolved' };

function renderDashboardComputers(computers) {
  const body = document.querySelector('#dashboard-page .table-section tbody');
  if (!body) return;
  const esc = mstEscape;
  body.innerHTML = computers.length ? computers.map((computer) => {
    const [pill, label] = dashboardStatus[computer.status] || ['offline', String(computer.status).toUpperCase()];
    const threats = Number(computer.activeThreats || 0);
    const threatClass = threats ? (computer.status === 'threat' ? ' class="danger-text"' : ' class="warning-text"') : '';
    return `<tr><td><i class="fa-solid fa-desktop table-icon"></i> ${esc(computer.hostname)}</td><td>${esc(computer.ipAddress)}</td><td><span class="status-pill ${pill}">● ${esc(label)}</span></td><td${threatClass}>${threats}</td><td>${esc(computer.lastHeartbeatAt ? mstTimeAgo(computer.lastHeartbeatAt) : computer.lastSeen)}</td></tr>`;
  }).join('') : '<tr><td colspan="5">No computers recorded yet.</td></tr>';
}

function renderDashboardThreats(threats) {
  const list = document.querySelector('#dashboard-page .threat-list');
  if (!list) return;
  const esc = mstEscape;
  list.innerHTML = threats.length ? threats.slice(0, 4).map((threat) => {
    const resolved = threat.status === 'Resolved';
    const badge = resolved ? 'resolved' : (dashboardSeverity[threat.severity] || 'medium');
    return `<div class="threat-item"><span class="severity ${badge}">${esc(resolved ? 'RESOLVED' : threat.severity)}</span><div><strong>${esc(threat.threatName)}</strong><small>${esc(threat.computerHostname || 'Unassigned')} · ${esc(mstTimeAgo(threat.detectedAt))}</small></div></div>`;
  }).join('') : '<div class="threat-item"><div><strong>No threats recorded</strong><small>Threat records will appear here.</small></div></div>';
}

function renderDashboardRisk(threats) {
  const open = threats.filter((threat) => !['Resolved', 'Ignored'].includes(threat.status));
  const count = (severity) => open.filter((threat) => threat.severity === severity).length;
  const counts = { critical: count('CRITICAL'), high: count('HIGH'), medium: count('MEDIUM'), low: count('LOW') };
  const [label, percent] = counts.critical ? ['HIGH RISK', 85] : counts.high ? ['ELEVATED RISK', 60] : counts.medium ? ['MODERATE RISK', 40] : ['LOW RISK', 15];
  const box = document.querySelector('#dashboard-page .threat-level-box');
  if (!box) return;
  const title = box.querySelector('.risk-title strong');
  const value = box.querySelector('.risk-title span');
  const fill = box.querySelector('.risk-fill');
  if (title) title.textContent = label;
  if (value) value.textContent = `${percent}%`;
  if (fill) fill.style.width = `${percent}%`;
  Object.entries(counts).forEach(([severity, total]) => { const node = box.querySelector(`.risk-${severity}`); if (node) node.textContent = total; });
  const needsAttention = counts.critical > 0;
  const status = box.querySelector('.status-row strong');
  if (status) { status.className = needsAttention ? 'danger-text' : 'success-text'; status.innerHTML = `<span class="status-dot ${needsAttention ? 'status-offline' : 'status-online'}"></span> ${needsAttention ? 'Attention required' : 'Protected'}`; }
  const banner = document.querySelector('#dashboard-page .security-banner');
  if (banner) {
    const heading = banner.querySelector('h3');
    const text = banner.querySelector('p:not(.eyebrow)');
    if (heading) heading.innerHTML = `<span class="status-dot ${needsAttention ? 'status-offline' : 'status-online'}"></span> ${needsAttention ? 'Attention required' : 'Protected'}`;
    if (text) text.textContent = needsAttention ? `${counts.critical} critical threat${counts.critical === 1 ? '' : 's'} require${counts.critical === 1 ? 's' : ''} immediate attention.` : 'No critical threats currently require immediate attention.';
  }
}

function renderDashboardScans(scans) {
  const list = document.querySelector('#dashboard-page .scan-list');
  if (!list) return;
  const esc = mstEscape;
  list.innerHTML = scans.length ? scans.map((scan) => `<div><strong>${esc(scan.fileName || scan.scanType)}</strong><span>${esc(scan.computerHostname || '—')}</span><b class="${scan.status === 'SAFE' ? 'scan-safe' : 'scan-suspicious'}">${esc(scan.status)}</b><small>${esc(mstTimeAgo(scan.completedAt || scan.startedAt || scan.createdAt))}</small></div>`).join('') : '<div><strong>No scans recorded</strong></div>';
}

async function loadDashboard() {
  let result;
  try {
    result = await fetchDashboardData();
  } catch (error) {
    showMSTToast(mstApiErrorMessage(error, 'Unable to load the dashboard from the database.'), 'dashboardToast');
    return false;
  }
  const isAdmin = sessionStorage.getItem('mstRole') === 'admin';
  const accounts = result.demo ? { users: 12, admins: 4 } : (isAdmin ? { users: '—', admins: '—' } : await fetchAccountCounts());
  renderDashboardStats(result.summary, accounts);
  if (result.demo) {
    // Keep the built-in demo tables when the API is offline.
    showMSTToast('API unavailable — showing demo dashboard data', 'dashboardToast');
    return false;
  }
  const [computers, threats, scans] = await Promise.all([
    fetchComputerStatus().catch(() => null),
    fetchThreatActivity().catch(() => null),
    fetchRecentScans().catch(() => null)
  ]);
  if (computers) renderDashboardComputers(computers);
  if (threats) { renderDashboardThreats(threats); renderDashboardRisk(threats); }
  if (scans) renderDashboardScans(scans);
  return true;
}

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('dashboard-page')) return;

  loadDashboard();

  const refreshButton = document.getElementById('refreshDashboard');
  const lastUpdated = document.getElementById('lastUpdated');

  if (refreshButton) {
    refreshButton.addEventListener('click', async () => {
      refreshButton.classList.add('loading');
      refreshButton.disabled = true;
      refreshButton.innerHTML = '<i class="fa-solid fa-spinner"></i> Refreshing';
      const loaded = await loadDashboard();
      if (lastUpdated) lastUpdated.textContent = 'Just now';
      refreshButton.classList.remove('loading');
      refreshButton.disabled = false;
      refreshButton.innerHTML = '<i class="fa-solid fa-rotate"></i> Refresh';
      if (loaded) showMSTToast('Dashboard updated', 'dashboardToast');
    });
  }
});

window.fetchDashboardData = fetchDashboardData;
window.fetchComputerStatus = fetchComputerStatus;
window.fetchThreatActivity = fetchThreatActivity;
window.fetchNetworkActivity = fetchNetworkActivity;
window.fetchRecentScans = fetchRecentScans;
window.fetchNotifications = fetchNotifications;
