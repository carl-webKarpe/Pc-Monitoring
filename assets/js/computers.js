const monitoredComputers = [
  { id: 'MST-PC-001', name: 'LAB-PC-01', ip: '192.168.1.20', mac: 'AA:BB:CC:DD:EE:01', status: 'online', threatLevel: 'safe', cpu: 24, memory: 42, disk: 61, network: '12.4 Mbps', agentVersion: '1.0.0', lastSeen: '5 sec ago', threats: 0, files: 127, events: 1, scan: '10 min ago' },
  { id: 'MST-PC-002', name: 'LAB-PC-02', ip: '192.168.1.21', mac: 'AA:BB:CC:DD:EE:02', status: 'warning', threatLevel: 'warning', cpu: 58, memory: 61, disk: 48, network: '8.2 Mbps', agentVersion: '1.0.0', lastSeen: '10 sec ago', threats: 1, files: 184, events: 3, scan: '12 min ago' },
  { id: 'MST-PC-003', name: 'LAB-PC-03', ip: '192.168.1.22', mac: 'AA:BB:CC:DD:EE:03', status: 'offline', threatLevel: 'unknown', cpu: null, memory: null, disk: null, network: '—', agentVersion: '1.0.0', lastSeen: '12 min ago', threats: 0, files: 96, events: 0, scan: '18 min ago' },
  { id: 'MST-PC-004', name: 'LAB-PC-04', ip: '192.168.1.23', mac: 'AA:BB:CC:DD:EE:04', status: 'threat', threatLevel: 'high', cpu: 78, memory: 83, disk: 72, network: '18.7 Mbps', agentVersion: '1.0.0', lastSeen: '3 sec ago', threats: 2, files: 204, events: 5, scan: '3 min ago' },
  { id: 'MST-PC-005', name: 'LAB-PC-05', ip: '192.168.1.24', mac: 'AA:BB:CC:DD:EE:05', status: 'online', threatLevel: 'safe', cpu: 31, memory: 46, disk: 55, network: '10.1 Mbps', agentVersion: '1.0.0', lastSeen: '7 sec ago', threats: 0, files: 142, events: 1, scan: '25 min ago' }
];

async function fetchComputers() { return Promise.resolve(monitoredComputers); }
async function fetchComputerDetails(id) { return Promise.resolve(monitoredComputers.find((computer) => computer.id === id)); }
async function fetchNetworkStatus() { return Promise.resolve({ status: 'connected', connection: 'Ethernet', gateway: '192.168.1.1' }); }
async function fetchAgentStatus(id) { return Promise.resolve({ id, status: 'connected', version: '1.0.0', heartbeat: '5 seconds ago' }); }

const statusText = { online: 'ONLINE', offline: 'OFFLINE', warning: 'WARNING', threat: 'THREAT' };
const threatText = { safe: 'SAFE', warning: 'WARNING', high: 'HIGH', unknown: 'UNKNOWN' };

function renderComputerStats(computers) {
  const stats = [
    ['TOTAL COMPUTERS', computers.length, 'Monitored devices', 'fa-desktop', 'cyan'],
    ['ONLINE', computers.filter((computer) => computer.status === 'online').length, '75% online', 'fa-circle-check', 'green'],
    ['OFFLINE', computers.filter((computer) => computer.status === 'offline').length, 'Requires attention', 'fa-circle-minus', 'gray'],
    ['WARNING', computers.filter((computer) => computer.status === 'warning').length, 'Needs review', 'fa-triangle-exclamation', 'yellow'],
    ['THREAT DETECTED', computers.filter((computer) => computer.status === 'threat').length, 'Active threats', 'fa-shield-halved', 'red'],
    ['RECENTLY CONNECTED', 3, 'Last 24 hours', 'fa-plug-circle-check', 'cyan']
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
  body.innerHTML = computers.map((computer) => `<tr><td><i class="fa-solid fa-desktop table-icon"></i><strong>${computer.name}</strong></td><td>${computer.id}</td><td>${computer.ip}</td><td><span class="status-pill ${computer.status}">● ${statusText[computer.status]}</span></td><td><span class="computer-threat ${computer.threatLevel}">${threatText[computer.threatLevel]}</span></td><td>${computer.cpu === null ? '—' : `${computer.cpu}%`}</td><td>${computer.memory === null ? '—' : `${computer.memory}%`}</td><td>${computer.lastSeen}</td><td><button class="link-button view-computer" data-computer-id="${computer.id}">View</button></td></tr>`).join('');
  document.querySelector('#computers-page #computerCount').textContent = computers.length ? `Showing 1-${computers.length} of ${monitoredComputers.length} computers` : 'Showing 0 computers';
  body.querySelectorAll('.view-computer').forEach((button) => button.addEventListener('click', () => showComputerDetails(button.dataset.computerId)));
}

function renderNetworkTopology() {
  document.querySelectorAll('#computers-page .computer-node[data-computer-id]').forEach((node) => {
    node.addEventListener('click', () => { if (node.dataset.computerId !== 'MST-SERVER') showComputerDetails(node.dataset.computerId); });
  });
}

function showComputerDetails(id) {
  const computer = monitoredComputers.find((item) => item.id === id);
  const modal = document.getElementById('computerDetailsModal');
  const content = document.getElementById('computerDetailContent');
  const title = document.getElementById('computerDetailTitle');
  if (!computer || !modal || !content || !title) return;
  title.textContent = computer.name;
  const offline = computer.status === 'offline';
  content.innerHTML = `<div class="detail-grid"><div class="detail-section"><h4>DEVICE INFORMATION</h4><p><span>Computer Name</span><strong>${computer.name}</strong></p><p><span>Device ID</span><strong>${computer.id}</strong></p><p><span>IP Address</span><strong>${computer.ip}</strong></p><p><span>MAC Address</span><strong>${computer.mac}</strong></p><p><span>Operating System</span><strong>Windows</strong></p><p><span>Agent Version</span><strong>${computer.agentVersion}</strong></p><p><span>Status</span><strong class="status-pill ${computer.status}">● ${statusText[computer.status]}</strong></p><p><span>Last Seen</span><strong>${computer.lastSeen}</strong></p></div><div class="detail-section"><h4>SYSTEM RESOURCES</h4>${resourceBar('CPU Usage', computer.cpu)}${resourceBar('Memory Usage', computer.memory)}${resourceBar('Disk Usage', computer.disk)}<p><span>Network</span><strong>${computer.network}</strong></p><h4>SECURITY STATUS</h4><p><span>Threat Level</span><strong class="computer-threat ${computer.threatLevel}">${threatText[computer.threatLevel]}</strong></p><p><span>Active Threats</span><strong>${computer.threats}</strong></p><p><span>Files Scanned</span><strong>${computer.files}</strong></p><p><span>Suspicious Events</span><strong>${computer.events}</strong></p><p><span>Last Security Scan</span><strong>${computer.scan}</strong></p></div></div><div class="detail-bottom"><div><h4>NETWORK INFORMATION</h4><p>Gateway <strong>192.168.1.1</strong></p><p>Connection <strong>Ethernet</strong></p><p>Network status <strong class="success-text">● Connected</strong></p></div><div><h4>AGENT STATUS</h4><p>Agent status <strong class="${offline ? 'danger-text' : 'success-text'}">● ${offline ? 'DISCONNECTED' : 'CONNECTED'}</strong></p><p>Last heartbeat <strong>${offline ? 'Unavailable' : computer.lastSeen}</strong></p><p>Upload / Download <strong>2.4 / ${computer.network}</strong></p></div></div><div class="detail-activity"><h4>RECENT ACTIVITY</h4><p><time>10:42 PM</time> Agent heartbeat received</p><p><time>10:41 PM</time> File scan completed</p><p><time>10:39 PM</time> Network activity recorded</p><p><time>10:35 PM</time> System information updated</p></div>${computer.status === 'threat' ? '<a class="btn-primary detail-threat-link" href="threats.html">View Threats</a>' : ''}`;
  modal.classList.remove('hidden');
}

function resourceBar(label, value) { return `<div class="resource-bar"><div><span>${label}</span><strong>${value === null ? 'Unavailable' : `${value}%`}</strong></div><div class="resource-track"><span style="width:${value || 0}%"></span></div></div>`; }

function filterComputers() {
  const query = document.getElementById('computerSearch')?.value.toLowerCase().trim() || '';
  const status = document.getElementById('statusFilter')?.value || 'all';
  const threat = document.getElementById('threatFilter')?.value || 'all';
  const sort = document.getElementById('sortFilter')?.value || 'name';
  const filtered = monitoredComputers.filter((computer) => `${computer.name} ${computer.id} ${computer.ip}`.toLowerCase().includes(query) && (status === 'all' || computer.status === status) && (threat === 'all' || computer.threatLevel === threat)).sort((first, second) => sort === 'threats' ? second.threats - first.threats : sort === 'status' ? first.status.localeCompare(second.status) : first.name.localeCompare(second.name));
  renderComputers(filtered);
}

function refreshMonitoring() {
  const button = document.getElementById('refreshComputers');
  const toast = document.getElementById('computerToast');
  if (!button) return;
  button.disabled = true;
  button.innerHTML = '<i class="fa-solid fa-spinner"></i> Refreshing';
  window.setTimeout(() => { button.disabled = false; button.innerHTML = '<i class="fa-solid fa-rotate"></i> Refresh'; document.getElementById('computerLastUpdated').textContent = 'Just now'; toast?.classList.add('show'); window.setTimeout(() => toast?.classList.remove('show'), 2800); }, 900);
}

function updateDemoMetrics() {
  monitoredComputers.forEach((computer) => { if (computer.cpu !== null) computer.cpu = Math.max(10, Math.min(95, computer.cpu + Math.round((Math.random() - 0.5) * 6))); if (computer.memory !== null) computer.memory = Math.max(20, Math.min(95, computer.memory + Math.round((Math.random() - 0.5) * 4))); });
}

function initializeComputerMonitoring() {
  const page = document.getElementById('computers-page');
  if (!page) return;
  renderComputerStats(monitoredComputers);
  renderComputers(monitoredComputers);
  renderNetworkTopology();
  ['computerSearch', 'statusFilter', 'threatFilter', 'sortFilter'].forEach((id) => document.getElementById(id)?.addEventListener(id === 'computerSearch' ? 'input' : 'change', filterComputers));
  document.getElementById('refreshComputers')?.addEventListener('click', refreshMonitoring);
  document.getElementById('emptyRefresh')?.addEventListener('click', filterComputers);
  document.querySelectorAll('#computers-page [data-close-modal]').forEach((button) => button.addEventListener('click', () => document.getElementById('computerDetailsModal')?.classList.add('hidden')));
  window.setInterval(() => { updateDemoMetrics(); filterComputers(); }, 7000);
}

document.addEventListener('DOMContentLoaded', initializeComputerMonitoring);
window.fetchComputers = fetchComputers;
window.fetchComputerDetails = fetchComputerDetails;
window.fetchNetworkStatus = fetchNetworkStatus;
window.fetchAgentStatus = fetchAgentStatus;
