// Dashboard: every number and list comes from the MST database (/api/dashboard and the resource APIs).
// When the API cannot be reached the page says so instead of showing example numbers.
const DASHBOARD_REFRESH_MS = 30000;
const dashboardStatus = { online: ['online', 'ONLINE'], warning: ['warning', 'WARNING'], offline: ['offline', 'OFFLINE'], threat: ['danger', 'THREAT'] };
const dashboardSeverity = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', SAFE: 'resolved' };
const dashboardPercent = (part, total) => (total ? Math.round((part / total) * 100) : 0);
let dashboardTimer = null;

async function fetchDashboardData() { return (await window.MSTApi.apiGet('/dashboard')).data; }
async function fetchComputerStatus() { return (await window.MSTApi.apiGet('/computers?limit=5')).data; }
async function fetchThreatActivity() { return (await window.MSTApi.apiGet('/threats?limit=100')).data; }
async function fetchRecentScans() { return (await window.MSTApi.apiGet('/scans?limit=5&sort=id&dir=desc')).data; }
async function fetchRecentFileEvents() { return (await window.MSTApi.apiGet('/file-events?limit=4')).data; }
async function fetchAccountCounts() {
  const count = (path) => window.MSTApi.apiGet(path).then(({ data }) => data.length).catch(() => '—');
  const [users, admins] = await Promise.all([count('/users'), count('/admins')]);
  return { users, admins };
}

function animateCounter(element, target) {
  const start = performance.now();
  const update = (now) => {
    const progress = Math.min((now - start) / 900, 1);
    element.textContent = Math.floor(progress * target).toLocaleString();
    if (progress < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

function renderDashboardStats(summary, accounts, animate) {
  const statsGrid = document.getElementById('statsGrid');
  if (!statsGrid) return;
  const isAdmin = sessionStorage.getItem('mstRole') === 'admin';
  const onlineMeta = `${dashboardPercent(summary.onlineComputers, summary.totalComputers)}% of monitored PCs`;
  const first = isAdmin ? [
    ['TOTAL COMPUTERS', summary.totalComputers, 'Registered lab PCs', 'fa-desktop', 'cyan'],
    ['ONLINE', summary.onlineComputers, onlineMeta, 'fa-circle-check', 'green'],
    ['OFFLINE', summary.offlineComputers, 'No recent heartbeat', 'fa-circle-minus', 'gray'],
    ['OPEN THREATS', summary.openThreats, 'Detected, not resolved', 'fa-shield-halved', 'red'],
    ['FILE EVENTS (24H)', summary.fileEventsLastDay, `${summary.fileEvents} recorded in total`, 'fa-file-circle-plus', 'cyan'],
    ['QUARANTINED', summary.quarantinedFiles, 'Files isolated on lab PCs', 'fa-box-archive', 'yellow']
  ] : [
    ['MONITORED PCs', summary.totalComputers, 'Registered lab PCs', 'fa-desktop', 'cyan'],
    ['ONLINE', summary.onlineComputers, onlineMeta, 'fa-circle-check', 'green'],
    ['OFFLINE', summary.offlineComputers, 'No recent heartbeat', 'fa-circle-minus', 'gray'],
    ['OPEN THREATS', summary.openThreats, 'Requires oversight', 'fa-shield-halved', 'red'],
    ['SYSTEM USERS', accounts.users, 'Managed accounts', 'fa-users', 'cyan'],
    ['ADMINS', accounts.admins, 'Administrative accounts', 'fa-user-gear', 'blue']
  ];
  const scans = [
    ['FILES SCANNED', summary.filesScanned, `${summary.scansInProgress} scan(s) in progress`, 'fa-file-circle-check', 'cyan'],
    ['SAFE', summary.safeScans, 'No threat found by the scanners', 'fa-check', 'green'],
    ['MEDIUM RISK', summary.mediumScans, 'Needs investigation', 'fa-circle-exclamation', 'yellow'],
    ['HIGH RISK', summary.highScans, 'Confirmed or strong evidence', 'fa-triangle-exclamation', 'red'],
    ['UNKNOWN', summary.unknownScans, 'No engine could check them', 'fa-circle-question', 'gray'],
    ['FAILED SCANS', summary.failedScans, 'Scan could not complete', 'fa-circle-xmark', 'gray']
  ];
  statsGrid.innerHTML = [...first, ...scans].map((item) => `
      <article class="metric-card card-surface">
        <div class="metric-header"><span class="metric-label">${item[0]}</span><span class="metric-icon ${item[4]}"><i class="fa-solid ${item[3]}"></i></span></div>
        <strong class="metric-value" data-value="${mstEscape(item[1])}">${animate ? '0' : mstEscape(Number(item[1]).toLocaleString?.() ?? item[1])}</strong>
        <span class="metric-meta">${mstEscape(item[2])}</span>
      </article>`).join('');
  statsGrid.querySelectorAll('[data-value]').forEach((element) => {
    const value = Number(element.dataset.value);
    if (!Number.isFinite(value)) element.textContent = element.dataset.value;
    else if (animate) animateCounter(element, value);
    else element.textContent = value.toLocaleString();
  });
}

function renderDisconnected(message) {
  const statsGrid = document.getElementById('statsGrid');
  if (statsGrid) statsGrid.innerHTML = `<article class="metric-card card-surface" style="grid-column:1/-1;min-height:0"><div class="metric-header"><span class="metric-label">DISCONNECTED</span><span class="metric-icon red"><i class="fa-solid fa-plug-circle-xmark"></i></span></div><span class="metric-meta">${mstEscape(message)}</span></article>`;
  ['#dashboard-page .threat-list', '#dashboard-page .scan-list', '#recentFileEvents', '#trendChart'].forEach((selector) => { const node = document.querySelector(selector); if (node) node.innerHTML = `<p class="panel-state error">${mstEscape(message)}</p>`; });
  const body = document.querySelector('#dashboard-page .table-section tbody');
  if (body) body.innerHTML = `<tr><td colspan="5">${mstEscape(message)}</td></tr>`;
}

function renderDashboardComputers(computers) {
  const body = document.querySelector('#dashboard-page .table-section tbody');
  if (body) {
    body.innerHTML = computers.length ? computers.map((computer) => {
      const [pill, label] = dashboardStatus[computer.status] || ['offline', String(computer.status).toUpperCase()];
      const threats = Number(computer.activeThreats || 0);
      const threatClass = threats ? (computer.status === 'threat' ? ' class="danger-text"' : ' class="warning-text"') : '';
      return `<tr><td><i class="fa-solid fa-desktop table-icon"></i> ${mstEscape(computer.hostname)}</td><td>${mstEscape(computer.ipAddress)}</td><td><span class="status-pill ${pill}">● ${mstEscape(label)}</span></td><td${threatClass}>${threats}</td><td>${mstEscape(computer.lastHeartbeatAt ? mstTimeAgo(computer.lastHeartbeatAt) : computer.lastSeen)}</td></tr>`;
    }).join('') : '<tr><td colspan="5">No computers registered yet. Register a lab PC with backend/tools/register-agent.php.</td></tr>';
  }
  // Network topology: the first four registered computers with their real status.
  document.querySelectorAll('#dashboard-page .topology-node.pc-node').forEach((node, index) => {
    const computer = computers[index];
    const online = computer && computer.status !== 'offline';
    node.querySelector('strong').textContent = computer ? computer.hostname : '—';
    node.querySelector('small').innerHTML = computer ? `<span class="status-dot ${online ? 'status-online' : 'status-offline'}"></span> ${online ? 'ONLINE' : 'OFFLINE'}` : 'Not registered';
    node.style.opacity = computer ? '' : '0.45';
  });
}

function renderDashboardThreats(threats) {
  const list = document.querySelector('#dashboard-page .threat-list');
  if (!list) return;
  list.innerHTML = threats.length ? threats.slice(0, 4).map((threat) => {
    const resolved = threat.status === 'Resolved';
    const badge = resolved ? 'resolved' : (dashboardSeverity[threat.severity] || 'medium');
    return `<div class="threat-item"><span class="severity ${badge}">${mstEscape(resolved ? 'RESOLVED' : threat.severity)}</span><div><strong>${mstEscape(threat.threatName)}</strong><small>${mstEscape(threat.computerHostname || 'File Scanner upload')} · ${mstEscape(threat.status)} · ${mstEscape(mstTimeAgo(threat.detectedAt))}</small></div></div>`;
  }).join('') : '<div class="threat-item"><div><strong>No threats recorded</strong><small>High-risk scan results create threat records here.</small></div></div>';
}

function renderDashboardRisk(threats, summary) {
  const open = threats.filter((threat) => !['Resolved', 'Ignored'].includes(threat.status));
  const count = (severity) => open.filter((threat) => threat.severity === severity).length;
  const counts = { critical: count('CRITICAL'), high: count('HIGH'), medium: count('MEDIUM'), low: count('LOW') };
  // The meter shows the share of open threats by severity, not a probability.
  const [label, tone] = counts.critical ? ['CRITICAL THREATS OPEN', 'danger'] : counts.high ? ['HIGH THREATS OPEN', 'danger'] : counts.medium ? ['MEDIUM THREATS OPEN', 'warning'] : open.length ? ['LOW THREATS OPEN', 'success'] : ['NO OPEN THREATS', 'success'];
  const weight = Math.min(100, counts.critical * 40 + counts.high * 25 + counts.medium * 10 + counts.low * 5);
  const box = document.querySelector('#dashboard-page .threat-level-box');
  if (box) {
    box.querySelector('.risk-title strong').textContent = label;
    box.querySelector('.risk-title span').textContent = `${open.length} open`;
    box.querySelector('.risk-fill').style.width = `${weight}%`;
    Object.entries(counts).forEach(([severity, total]) => { const node = box.querySelector(`.risk-${severity}`); if (node) node.textContent = total; });
    const status = box.querySelector('.status-row strong');
    status.className = tone === 'danger' ? 'danger-text' : 'success-text';
    status.innerHTML = `<span class="status-dot ${tone === 'danger' ? 'status-offline' : 'status-online'}"></span> ${tone === 'danger' ? 'Attention required' : 'Protected'}`;
  }
  const attention = counts.critical + counts.high;
  const banner = document.querySelector('#dashboard-page .security-banner');
  if (banner) {
    banner.querySelector('h3').innerHTML = `<span class="status-dot ${attention ? 'status-offline' : 'status-online'}"></span> ${attention ? 'Attention required' : 'Protected'}`;
    banner.querySelector('p:not(.eyebrow)').textContent = attention ? `${attention} critical/high threat${attention === 1 ? '' : 's'} need${attention === 1 ? 's' : ''} attention.` : 'No critical or high threats are open.';
  }
  const check = document.getElementById('bannerCheck');
  if (check) check.textContent = `Last check: ${new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`;
  const radar = document.getElementById('radarStatus');
  if (radar) radar.innerHTML = `<strong>${mstEscape(summary.agentConnectedComputers)} of ${mstEscape(summary.totalComputers)} agents connected</strong><span class="${attention ? 'danger-text' : 'success-text'}"><span class="status-dot ${attention ? 'status-offline' : 'status-online'}"></span> ${attention ? `${attention} critical/high threat(s) open` : 'No critical threat detected'}</span>`;
}

function renderDashboardScans(scans) {
  const list = document.querySelector('#dashboard-page .scan-list');
  if (!list) return;
  list.innerHTML = scans.length ? scans.map((scan) => `<div><strong><a href="scan-history.html?scan=${mstEscape(scan.id)}">${mstEscape(scan.fileName || scan.scanType)}</a></strong><span>${mstEscape(scan.computerHostname || 'Upload')}</span>${mstRiskBadge(mstRiskOf(scan), scan.scanState)}<small>${mstEscape(mstTimeAgo(scan.completedAt || scan.createdAt))}</small></div>`).join('') : '<p class="panel-state">No scans recorded yet.</p>';
}

function renderRecentFileEvents(events) {
  const target = document.getElementById('recentFileEvents');
  if (!target) return;
  const tone = { created: 'cyan', modified: 'blue', renamed: 'blue', deleted: 'red' };
  const label = { created: 'New file', modified: 'Modified', renamed: 'Renamed', deleted: 'Deleted' };
  target.innerHTML = events.length ? events.map((event) => `<div><span class="timeline-dot ${tone[event.eventType] || 'cyan'}"></span><time>${mstEscape(mstTimeAgo(event.detectedAt))}</time><strong>${mstEscape(label[event.eventType] || event.eventType)}${event.origin === 'internet' ? ' (downloaded)' : event.origin === 'browser_download' ? ' (browser download)' : ''}: ${mstEscape(event.fileName)}</strong><small>${mstEscape(event.computerHostname)}</small></div>`).join('') : '<p class="panel-state">No file activity reported yet. Start the agent on a lab PC.</p>';
}

// 14 days of completed scans with High / Medium results, as bars (real counts from the database).
function renderTrend(trend) {
  const target = document.getElementById('trendChart');
  if (!target) return;
  const width = 700, height = 220, left = 34, bottom = 196, top = 18;
  const max = Math.max(1, ...trend.map((day) => day.scans));
  const step = (width - left - 10) / trend.length;
  const y = (value) => bottom - ((bottom - top) * value) / max;
  const bars = trend.map((day, index) => {
    const x = left + index * step + step * 0.18;
    const w = step * 0.64;
    const label = new Date(`${day.date}T00:00:00`).toLocaleDateString([], { month: 'short', day: 'numeric' });
    return `<g><title>${mstEscape(label)}: ${day.scans} scan(s), ${day.high} high, ${day.medium} medium, ${day.threats} threat record(s)</title>
      <rect class="bar-scans" x="${x}" y="${y(day.scans)}" width="${w}" height="${bottom - y(day.scans)}" rx="3"></rect>
      <rect class="bar-medium" x="${x}" y="${y(day.medium + day.high)}" width="${w}" height="${bottom - y(day.medium)}" rx="3"></rect>
      <rect class="bar-high" x="${x}" y="${y(day.high)}" width="${w}" height="${bottom - y(day.high)}" rx="3"></rect>
      ${index % 2 === 0 || index === trend.length - 1 ? `<text x="${x + w / 2}" y="${height - 6}" text-anchor="middle">${mstEscape(label)}</text>` : ''}</g>`;
  }).join('');
  const total = trend.reduce((sum, day) => sum + day.scans, 0);
  target.innerHTML = `<svg class="trend-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Scans and detections per day for the last 14 days"><g class="chart-grid"><path d="M${left} ${top}H${width - 10}M${left} ${(top + bottom) / 2}H${width - 10}M${left} ${bottom}H${width - 10}"/></g><text x="4" y="${top + 4}">${max}</text><text x="4" y="${bottom}">0</text>${bars}</svg>${total ? '' : '<p class="panel-state">No scans completed in the last 14 days.</p>'}`;
}

async function loadDashboard({ animate = true } = {}) {
  let summary;
  try {
    summary = await fetchDashboardData();
  } catch (error) {
    renderDisconnected(error.status ? mstApiErrorMessage(error, 'Unable to load the dashboard from the database.') : 'Disconnected: the MST API is not reachable. Start the PHP backend and refresh.');
    return false;
  }
  const isAdmin = sessionStorage.getItem('mstRole') === 'admin';
  renderDashboardStats(summary, isAdmin ? {} : await fetchAccountCounts(), animate);
  renderTrend(summary.trend || []);
  const failed = (selector, message) => { const node = document.querySelector(selector); if (node) node.innerHTML = `<p class="panel-state error">${mstEscape(message)}</p>`; };
  const [computers, threats, scans, events] = await Promise.all([fetchComputerStatus().catch(() => null), fetchThreatActivity().catch(() => null), fetchRecentScans().catch(() => null), fetchRecentFileEvents().catch(() => null)]);
  if (computers) renderDashboardComputers(computers);
  if (threats) { renderDashboardThreats(threats); renderDashboardRisk(threats, summary); } else failed('#dashboard-page .threat-list', 'Unable to load threats.');
  if (scans) renderDashboardScans(scans); else failed('#dashboard-page .scan-list', 'Unable to load scans.');
  if (events) renderRecentFileEvents(events); else failed('#recentFileEvents', 'Unable to load file activity.');
  const lastUpdated = document.getElementById('lastUpdated');
  if (lastUpdated) lastUpdated.textContent = new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' });
  return true;
}

function scheduleDashboardRefresh() {
  window.clearTimeout(dashboardTimer);
  // New events and scans appear without reloading the page.
  dashboardTimer = window.setTimeout(async () => { if (!document.hidden) await loadDashboard({ animate: false }); scheduleDashboardRefresh(); }, DASHBOARD_REFRESH_MS);
}

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('dashboard-page')) return;
  loadDashboard().then(scheduleDashboardRefresh);
  const refreshButton = document.getElementById('refreshDashboard');
  refreshButton?.addEventListener('click', async () => {
    refreshButton.classList.add('loading');
    refreshButton.disabled = true;
    refreshButton.innerHTML = '<i class="fa-solid fa-spinner"></i> Refreshing';
    const loaded = await loadDashboard({ animate: false });
    refreshButton.classList.remove('loading');
    refreshButton.disabled = false;
    refreshButton.innerHTML = '<i class="fa-solid fa-rotate"></i> Refresh';
    if (loaded) showMSTToast('Dashboard updated', 'dashboardToast');
    scheduleDashboardRefresh();
  });
});

window.fetchDashboardData = fetchDashboardData;
window.fetchComputerStatus = fetchComputerStatus;
window.fetchThreatActivity = fetchThreatActivity;
window.fetchRecentScans = fetchRecentScans;
