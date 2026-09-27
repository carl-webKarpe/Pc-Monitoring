const monitoredComputers = [
  { id: 'MST-PC-001', name: 'LAB-PC-01', ip: '192.168.1.20', mac: 'AA:BB:CC:DD:EE:01', status: 'online', threatLevel: 'safe', cpu: 24, memory: 42, disk: 61, network: '12.4 Mbps', agentVersion: '1.0.0', lastSeen: '5 sec ago', threats: 0, files: 127, events: 1, scan: '10 min ago' },
  { id: 'MST-PC-002', name: 'LAB-PC-02', ip: '192.168.1.21', mac: 'AA:BB:CC:DD:EE:02', status: 'warning', threatLevel: 'warning', cpu: 58, memory: 61, disk: 48, network: '8.2 Mbps', agentVersion: '1.0.0', lastSeen: '10 sec ago', threats: 1, files: 184, events: 3, scan: '12 min ago' },
  { id: 'MST-PC-003', name: 'LAB-PC-03', ip: '192.168.1.22', mac: 'AA:BB:CC:DD:EE:03', status: 'offline', threatLevel: 'unknown', cpu: null, memory: null, disk: null, network: '—', agentVersion: '1.0.0', lastSeen: '12 min ago', threats: 0, files: 96, events: 0, scan: '18 min ago' },
  { id: 'MST-PC-004', name: 'LAB-PC-04', ip: '192.168.1.23', mac: 'AA:BB:CC:DD:EE:04', status: 'threat', threatLevel: 'high', cpu: 78, memory: 83, disk: 72, network: '18.7 Mbps', agentVersion: '1.0.0', lastSeen: '3 sec ago', threats: 2, files: 204, events: 5, scan: '3 min ago' },
  { id: 'MST-PC-005', name: 'LAB-PC-05', ip: '192.168.1.24', mac: 'AA:BB:CC:DD:EE:05', status: 'online', threatLevel: 'safe', cpu: 31, memory: 46, disk: 55, network: '10.1 Mbps', agentVersion: '1.0.0', lastSeen: '7 sec ago', threats: 0, files: 142, events: 1, scan: '25 min ago' }
];

// Demo records are only shown when the MST API cannot be reached (see MSTApi.apiGetOrDemo).
let computerRows = [];
let computerDataIsDemo = false;

// Maps a MySQL-backed /api/computers record onto the structure the existing UI already renders.
// Values the database does not store yet (MAC, disk, network, agent version) are filled by the future Python Agent phase.
function fromApiComputer(computer) {
  return { dbId: computer.id, id: computer.deviceId, name: computer.hostname, ip: computer.ipAddress, mac: null, os: computer.operatingSystem, status: computer.status, threatLevel: computer.threatLevel, cpu: computer.cpuUsage ?? null, memory: computer.memoryUsage ?? null, disk: null, network: null, agentVersion: null, agentStatus: computer.agentStatus, lastSeen: computer.lastSeen, threats: Number(computer.activeThreats || 0), files: Number(computer.scanCount || 0), events: null, scan: computer.lastScanAt ? mstTimeAgo(computer.lastScanAt) : 'No scans recorded' };
}

async function fetchComputers() {
  const { data, demo } = await window.MSTApi.apiGetOrDemo('/computers', monitoredComputers);
  computerDataIsDemo = demo;
  return demo ? data : data.map(fromApiComputer);
}
async function fetchComputerDetails(id) { return (computerRows.length ? computerRows : await fetchComputers()).find((computer) => computer.id === id); }
async function fetchNetworkStatus() { return Promise.resolve({ status: 'connected', connection: 'Ethernet', gateway: '192.168.1.1' }); }
async function fetchAgentStatus(id) { const computer = await fetchComputerDetails(id); return { id, status: computer?.agentStatus || 'unknown' }; }

const statusText = { online: 'ONLINE', offline: 'OFFLINE', warning: 'WARNING', threat: 'THREAT' };
const threatText = { safe: 'SAFE', warning: 'WARNING', high: 'HIGH', unknown: 'UNKNOWN' };

function renderComputerStats(computers) {
  const stats = [
    ['TOTAL COMPUTERS', computers.length, 'Monitored devices', 'fa-desktop', 'cyan'],
    ['ONLINE', computers.filter((computer) => computer.status === 'online').length, `${computers.length ? Math.round((computers.filter((computer) => computer.status === 'online').length / computers.length) * 100) : 0}% online`, 'fa-circle-check', 'green'],
    ['OFFLINE', computers.filter((computer) => computer.status === 'offline').length, 'Requires attention', 'fa-circle-minus', 'gray'],
    ['WARNING', computers.filter((computer) => computer.status === 'warning').length, 'Needs review', 'fa-triangle-exclamation', 'yellow'],
    ['THREAT DETECTED', computers.filter((computer) => computer.status === 'threat').length, 'Active threats', 'fa-shield-halved', 'red'],
    ['RECENTLY CONNECTED', computers.filter((computer) => (computer.agentStatus || (computer.status === 'offline' ? 'disconnected' : 'connected')) === 'connected').length, 'Agent connected', 'fa-plug-circle-check', 'cyan']
  ];
  const target = document.querySelector('#computers-page #computerStats');
  if (!target) return;
  target.innerHTML = stats.map((item) => `<article class="metric-card card-surface"><div class="metric-header"><span class="metric-label">${item[0]}</span><span class="metric-icon ${item[4]}"><i class="fa-solid ${item[3]}"></i></span></div><strong class="metric-value" data-value="${item[1]}">0</strong><span class="metric-meta">${item[2]}</span></article>`).join('');
  target.querySelectorAll('[data-value]').forEach((element) => {
    const value = Number(element.dataset.value);
    let current = 0;
    const timer = window.setInterval(() => { current += Math.max(1, Math.ceil(value / 18)); element.textContent = Math.min(current, value).toLocaleString(); if (current >= value) window.clearInterval(timer); }, 55);
  });
}

function renderComputers(computers) {
  const body = document.querySelector('#computers-page #computerTableBody');
  const empty = document.querySelector('#computers-page #computerEmpty');
  if (!body || !empty) return;
  empty.classList.toggle('hidden', computers.length > 0);
  const esc = mstEscape;
  body.innerHTML = computers.map((computer) => `<tr><td><i class="fa-solid fa-desktop table-icon"></i><strong>${esc(computer.name)}</strong></td><td>${esc(computer.id)}</td><td>${esc(computer.ip)}</td><td><span class="status-pill ${esc(computer.status)}">● ${esc(statusText[computer.status] || computer.status)}</span></td><td><span class="computer-threat ${esc(computer.threatLevel)}">${esc(threatText[computer.threatLevel] || computer.threatLevel)}</span></td><td>${computer.cpu === null ? '—' : `${esc(computer.cpu)}%`}</td><td>${computer.memory === null ? '—' : `${esc(computer.memory)}%`}</td><td>${esc(computer.lastSeen)}</td><td><button class="link-button view-computer" data-computer-id="${esc(computer.id)}">View</button></td></tr>`).join('');
  document.querySelector('#computers-page #computerCount').textContent = computers.length ? `Showing 1-${computers.length} of ${computerRows.length} computers${computerDataIsDemo ? ' (demo data)' : ''}` : 'Showing 0 computers';
  body.querySelectorAll('.view-computer').forEach((button) => button.addEventListener('click', () => showComputerDetails(button.dataset.computerId)));
}

function renderNetworkTopology() {
  document.querySelectorAll('#computers-page .computer-node[data-computer-id]').forEach((node) => {
    node.addEventListener('click', () => { if (node.dataset.computerId !== 'MST-SERVER') showComputerDetails(node.dataset.computerId); });
  });
}

function showComputerDetails(id) {
  const computer = computerRows.find((item) => item.id === id);
  const modal = document.getElementById('computerDetailsModal');
  const content = document.getElementById('computerDetailContent');
  const title = document.getElementById('computerDetailTitle');
  if (!computer || !modal || !content || !title) return;
  title.textContent = computer.name;
  const offline = computer.status === 'offline';
  const esc = mstEscape;
  const unavailable = (value) => (value === null || value === undefined || value === '' ? 'Unavailable' : value);
  const agentConnected = (computer.agentStatus || (offline ? 'disconnected' : 'connected')) === 'connected';
  // Recent activity, gateway and throughput are demo-only until the Python Agent phase reports them.
  const activity = computerDataIsDemo ? '<p><time>10:42 PM</time> Agent heartbeat received</p><p><time>10:41 PM</time> File scan completed</p><p><time>10:39 PM</time> Network activity recorded</p><p><time>10:35 PM</time> System information updated</p>' : '<p><time>—</time> Agent activity will be recorded once the monitoring agent is connected (future phase).</p>';
  content.innerHTML = `<div class="detail-grid"><div class="detail-section"><h4>DEVICE INFORMATION</h4><p><span>Computer Name</span><strong>${esc(computer.name)}</strong></p><p><span>Device ID</span><strong>${esc(computer.id)}</strong></p><p><span>IP Address</span><strong>${esc(computer.ip)}</strong></p><p><span>MAC Address</span><strong>${esc(unavailable(computer.mac))}</strong></p><p><span>Operating System</span><strong>${esc(computer.os || 'Windows')}</strong></p><p><span>Agent Version</span><strong>${esc(unavailable(computer.agentVersion))}</strong></p><p><span>Status</span><strong class="status-pill ${esc(computer.status)}">● ${esc(statusText[computer.status] || computer.status)}</strong></p><p><span>Last Seen</span><strong>${esc(computer.lastSeen)}</strong></p></div><div class="detail-section"><h4>SYSTEM RESOURCES</h4>${resourceBar('CPU Usage', computer.cpu)}${resourceBar('Memory Usage', computer.memory)}${resourceBar('Disk Usage', computer.disk)}<p><span>Network</span><strong>${esc(unavailable(computer.network))}</strong></p><h4>SECURITY STATUS</h4><p><span>Threat Level</span><strong class="computer-threat ${esc(computer.threatLevel)}">${esc(threatText[computer.threatLevel] || computer.threatLevel)}</strong></p><p><span>Active Threats</span><strong>${esc(computer.threats)}</strong></p><p><span>Files Scanned</span><strong>${esc(computer.files)}</strong></p><p><span>Suspicious Events</span><strong>${esc(unavailable(computer.events))}</strong></p><p><span>Last Security Scan</span><strong>${esc(computer.scan)}</strong></p></div></div><div class="detail-bottom"><div><h4>NETWORK INFORMATION</h4><p>Gateway <strong>${computerDataIsDemo ? '192.168.1.1' : 'Unavailable'}</strong></p><p>Connection <strong>${computerDataIsDemo ? 'Ethernet' : 'Unavailable'}</strong></p><p>Network status <strong class="${offline ? 'danger-text' : 'success-text'}">● ${offline ? 'Disconnected' : 'Connected'}</strong></p></div><div><h4>AGENT STATUS</h4><p>Agent status <strong class="${agentConnected ? 'success-text' : 'danger-text'}">● ${esc((computer.agentStatus || (agentConnected ? 'connected' : 'disconnected')).toUpperCase())}</strong></p><p>Last heartbeat <strong>${offline ? 'Unavailable' : esc(computer.lastSeen)}</strong></p><p>Upload / Download <strong>${computerDataIsDemo ? `2.4 / ${esc(computer.network)}` : 'Unavailable'}</strong></p></div></div><div class="detail-activity"><h4>RECENT ACTIVITY</h4>${activity}</div>${computer.status === 'threat' ? '<a class="btn-primary detail-threat-link" href="threats.html">View Threats</a>' : ''}`;
  modal.classList.remove('hidden');
}

function resourceBar(label, value) { const percent = value === null || value === undefined ? null : Math.max(0, Math.min(100, Number(value) || 0)); return `<div class="resource-bar"><div><span>${label}</span><strong>${percent === null ? 'Unavailable' : `${percent}%`}</strong></div><div class="resource-track"><span style="width:${percent || 0}%"></span></div></div>`; }

function filterComputers() {
  const query = document.getElementById('computerSearch')?.value.toLowerCase().trim() || '';
  const status = document.getElementById('statusFilter')?.value || 'all';
  const threat = document.getElementById('threatFilter')?.value || 'all';
  const sort = document.getElementById('sortFilter')?.value || 'name';
  const filtered = computerRows.filter((computer) => `${computer.name} ${computer.id} ${computer.ip}`.toLowerCase().includes(query) && (status === 'all' || computer.status === status) && (threat === 'all' || computer.threatLevel === threat)).sort((first, second) => sort === 'threats' ? second.threats - first.threats : sort === 'status' ? first.status.localeCompare(second.status) : first.name.localeCompare(second.name));
  renderComputers(filtered);
}

async function loadComputers() {
  try {
    computerRows = await fetchComputers();
  } catch (error) {
    computerRows = [];
    showMSTToast(mstApiErrorMessage(error, 'Unable to load computers from the database.'), 'computerToast');
  }
  renderComputerStats(computerRows);
  filterComputers();
  if (computerDataIsDemo) showMSTToast('API unavailable — showing demo computer data', 'computerToast');
  const lastUpdated = document.getElementById('computerLastUpdated');
  if (lastUpdated) lastUpdated.textContent = 'Just now';
}

async function refreshMonitoring() {
  const button = document.getElementById('refreshComputers');
  if (!button) return;
  button.disabled = true;
  button.innerHTML = '<i class="fa-solid fa-spinner"></i> Refreshing';
  await loadComputers();
  button.disabled = false;
  button.innerHTML = '<i class="fa-solid fa-rotate"></i> Refresh';
  if (!computerDataIsDemo) showMSTToast('Monitoring data updated', 'computerToast');
}

function initializeComputerMonitoring() {
  const page = document.getElementById('computers-page');
  if (!page) return;
  const body = document.querySelector('#computers-page #computerTableBody');
  if (body) body.innerHTML = '<tr><td colspan="9">Loading computers…</td></tr>';
  renderNetworkTopology();
  ['computerSearch', 'statusFilter', 'threatFilter', 'sortFilter'].forEach((id) => document.getElementById(id)?.addEventListener(id === 'computerSearch' ? 'input' : 'change', filterComputers));
  document.getElementById('refreshComputers')?.addEventListener('click', refreshMonitoring);
  document.getElementById('emptyRefresh')?.addEventListener('click', filterComputers);
  document.querySelectorAll('#computers-page [data-close-modal]').forEach((button) => button.addEventListener('click', () => document.getElementById('computerDetailsModal')?.classList.add('hidden')));
  loadComputers();
}

document.addEventListener('DOMContentLoaded', initializeComputerMonitoring);
window.fetchComputers = fetchComputers;
window.fetchComputerDetails = fetchComputerDetails;
window.fetchNetworkStatus = fetchNetworkStatus;
window.fetchAgentStatus = fetchAgentStatus;
