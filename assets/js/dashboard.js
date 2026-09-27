const dashboardData = {
  totalComputers: 24,
  onlineComputers: 18,
  offlineComputers: 6,
  threatsDetected: 7,
  filesScanned: 1284,
  safeFiles: 1261
};

function fetchDashboardData() {
  return Promise.resolve(dashboardData);
}

function fetchComputerStatus() {
  return Promise.resolve([
    { name: 'LAB-PC-01', ip: '192.168.1.20', status: 'online', threats: 0 },
    { name: 'LAB-PC-02', ip: '192.168.1.21', status: 'warning', threats: 1 },
    { name: 'LAB-PC-03', ip: '192.168.1.22', status: 'offline', threats: 0 },
    { name: 'LAB-PC-04', ip: '192.168.1.23', status: 'threat', threats: 3 },
    { name: 'LAB-PC-05', ip: '192.168.1.24', status: 'online', threats: 0 }
  ]);
}

function fetchThreatActivity() {
  return Promise.resolve([]);
}

function fetchNetworkActivity() {
  return Promise.resolve([]);
}

function fetchRecentScans() {
  return Promise.resolve([]);
}

function fetchNotifications() {
  return Promise.resolve([]);
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

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('dashboard-page')) return;

  const isAdmin = sessionStorage.getItem('mstRole') === 'admin';
  const stats = isAdmin ? [
    ['TOTAL COMPUTERS', dashboardData.totalComputers, 'Monitored devices', 'fa-desktop', 'cyan'],
    ['ONLINE', dashboardData.onlineComputers, '75% of monitored PCs', 'fa-circle-check', 'green'],
    ['OFFLINE', dashboardData.offlineComputers, 'Requires attention', 'fa-circle-minus', 'gray'],
    ['THREATS DETECTED', dashboardData.threatsDetected, '+2 today', 'fa-shield-halved', 'red'],
    ['FILES SCANNED', dashboardData.filesScanned, 'This month', 'fa-file-circle-check', 'cyan'],
    ['SAFE FILES', dashboardData.safeFiles, '98.2% clean', 'fa-check', 'green']
  ] : [
    ['MONITORED PCs', dashboardData.totalComputers, 'Authorized devices', 'fa-desktop', 'cyan'],
    ['ONLINE', dashboardData.onlineComputers, '75% of monitored PCs', 'fa-circle-check', 'green'],
    ['THREATS', dashboardData.threatsDetected, 'Requires oversight', 'fa-shield-halved', 'red'],
    ['FILES SCANNED', dashboardData.filesScanned, 'This month', 'fa-file-circle-check', 'cyan'],
    ['SYSTEM USERS', 12, 'Managed accounts', 'fa-users', 'cyan'],
    ['ADMINS', 4, 'Administrative accounts', 'fa-user-gear', 'blue']
  ];
  const statsGrid = document.getElementById('statsGrid');

  if (statsGrid) {
    statsGrid.innerHTML = stats.map((item) => `
      <article class="metric-card card-surface">
        <div class="metric-header"><span class="metric-label">${item[0]}</span><span class="metric-icon ${item[4]}"><i class="fa-solid ${item[3]}"></i></span></div>
        <strong class="metric-value" data-value="${item[1]}">0</strong>
        <span class="metric-meta">${item[2]}</span>
      </article>
    `).join('');
    statsGrid.querySelectorAll('[data-value]').forEach((element) => animateCounter(element, Number(element.dataset.value)));
  }

  const refreshButton = document.getElementById('refreshDashboard');
  const lastUpdated = document.getElementById('lastUpdated');
  const toast = document.getElementById('dashboardToast');

  if (refreshButton) {
    refreshButton.addEventListener('click', () => {
      refreshButton.classList.add('loading');
      refreshButton.disabled = true;
      refreshButton.innerHTML = '<i class="fa-solid fa-spinner"></i> Refreshing';
      window.setTimeout(() => {
        if (lastUpdated) lastUpdated.textContent = 'Just now';
        refreshButton.classList.remove('loading');
        refreshButton.disabled = false;
        refreshButton.innerHTML = '<i class="fa-solid fa-rotate"></i> Refresh';
        if (toast) {
          toast.classList.add('show');
          window.setTimeout(() => toast.classList.remove('show'), 2800);
        }
      }, 900);
    });
  }
});

window.fetchDashboardData = fetchDashboardData;
window.fetchComputerStatus = fetchComputerStatus;
window.fetchThreatActivity = fetchThreatActivity;
window.fetchNetworkActivity = fetchNetworkActivity;
window.fetchRecentScans = fetchRecentScans;
window.fetchNotifications = fetchNotifications;
