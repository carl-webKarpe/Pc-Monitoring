// Download Detections: files downloaded on the lab PCs (/api/file-events?downloads=1) and their scan verdicts, kept
// apart from everyday file activity (File Activity page). Updates by itself (assets/js/live.js).
const downloadState = { rows: [] };
const downloadEsc = (value) => mstEscape(String(value ?? ''));

// The verdict of the file's latest scan, as one of: High, Medium, Safe, Unknown, Failed, scanning, none.
function downloadResult(file) {
  if (['Pending', 'Scanning'].includes(file.scanState)) return 'scanning';
  if (!file.scanId) return 'none';
  if (file.scanState === 'Failed') return 'Failed';
  return mstRiskOf({ riskLevel: file.riskLevel }) || 'Unknown';
}

const DOWNLOAD_RESULTS = {
  High: ['threat', 'fa-triangle-exclamation', 'High risk'],
  Medium: ['warning', 'fa-circle-exclamation', 'Medium risk'],
  Safe: ['safe', 'fa-circle-check', 'No threat detected'],
  Unknown: ['pending', 'fa-circle-question', 'Unknown'],
  Failed: ['failed', 'fa-circle-xmark', 'Scan failed'],
  scanning: ['pending', 'fa-spinner', 'Scanning…'],
  none: ['pending', 'fa-minus', 'Not scanned']
};

function downloadResultBadge(file) {
  const [tone, icon, label] = DOWNLOAD_RESULTS[downloadResult(file)];
  return `<span class="scan-result-status ${tone}"><i class="fa-solid ${icon}"></i> ${downloadEsc(label.toUpperCase())}</span>`;
}

// VirusTotal: "flagged / engines" when the hash is known; otherwise what the local engines said.
function downloadEngines(file) {
  if (file.vtStatus === 'found' && Number(file.vtTotal) > 0) {
    const flagged = Number(file.vtMalicious) + Number(file.vtSuspicious || 0);
    return `<strong class="${flagged ? 'danger-text' : ''}">${flagged} / ${downloadEsc(file.vtTotal)}</strong><small class="table-subtext">VirusTotal</small>`;
  }
  const engines = mstScanDetails(file).engines || [];
  if (engines.length) {
    const detected = engines.filter((engine) => engine.result === 'detected').length;
    return `<strong class="${detected ? 'danger-text' : ''}">${detected} / ${engines.length}</strong><small class="table-subtext">on-PC antivirus</small>`;
  }
  return '<span class="table-subtext">—</span>';
}

function downloadSource(file) {
  if (file.origin === 'internet' && file.downloadUrl) {
    const url = String(file.downloadUrl);
    return `<span class="download-source" title="${downloadEsc(url)}"><i class="fa-solid fa-globe"></i> ${downloadEsc(url.replace(/^https?:\/\//i, ''))}</span>`;
  }
  if (file.origin === 'internet') return '<span class="download-source"><i class="fa-solid fa-globe"></i> Internet (site not recorded)</span>';
  return '<span class="download-source muted"><i class="fa-solid fa-download"></i> Browser download (site unknown)</span>';
}

function renderDownloadStats() {
  const rows = downloadState.rows;
  const count = (result) => rows.filter((file) => downloadResult(file) === result).length;
  const stats = [
    ['DOWNLOADS', rows.length, 'Files downloaded on lab PCs', 'fa-cloud-arrow-down', 'cyan'],
    ['HIGH RISK', count('High'), 'Confirmed or strong evidence', 'fa-triangle-exclamation', 'red'],
    ['MEDIUM RISK', count('Medium'), 'Needs investigation', 'fa-circle-exclamation', 'yellow'],
    ['NO THREAT', count('Safe'), 'No threat detected', 'fa-circle-check', 'green'],
    ['NOT CHECKED', count('none') + count('scanning') + count('Unknown') + count('Failed'), 'Not scanned, scanning, unknown or failed', 'fa-circle-question', 'gray'],
    ['FROM THE INTERNET', rows.filter((file) => file.origin === 'internet').length, 'Confirmed by Windows (Mark of the Web)', 'fa-globe', 'cyan']
  ];
  document.getElementById('downloadStats').innerHTML = stats.map(([label, value, meta, icon, tone]) => `<article class="metric-card card-surface"><div class="metric-header"><span class="metric-label">${label}</span><span class="metric-icon ${tone}"><i class="fa-solid ${icon}"></i></span></div><strong class="metric-value">${Number(value).toLocaleString()}</strong><span class="metric-meta">${meta}</span></article>`).join('');
}

function populateDownloadComputers() {
  const select = document.getElementById('downloadComputerFilter');
  const current = select.value;
  const names = new Map(downloadState.rows.map((file) => [String(file.computerId), file.computerHostname || file.computerDeviceId]));
  select.innerHTML = '<option value="all">All computers</option>' + [...names.entries()].sort((a, b) => String(a[1]).localeCompare(String(b[1])))
    .map(([id, name]) => `<option value="${downloadEsc(id)}">${downloadEsc(name)}</option>`).join('');
  select.value = names.has(current) ? current : 'all';
}

function renderDownloads() {
  const query = document.getElementById('downloadSearch').value.trim().toLowerCase();
  const computer = document.getElementById('downloadComputerFilter').value;
  const result = document.getElementById('downloadResultFilter').value;
  const source = document.getElementById('downloadSourceFilter').value;
  const days = Number(document.getElementById('downloadDateFilter').value) || 0;
  const since = days ? new Date(Date.now() - (days === 1 ? 0 : days * 86400000)) : null;
  if (since && days === 1) since.setHours(0, 0, 0, 0);
  const rows = downloadState.rows.filter((file) => (!query || `${file.fileName} ${file.sha256 || ''} ${file.downloadUrl || ''} ${file.filePath}`.toLowerCase().includes(query))
    && (computer === 'all' || String(file.computerId) === computer)
    && (result === 'all' || downloadResult(file) === result)
    && (source === 'all' || file.origin === source)
    && (!since || (mstParseDate(file.detectedAt) || 0) >= since));
  document.getElementById('downloadTableBody').innerHTML = rows.map((file) => `<tr>
      <td><strong>${downloadEsc(file.fileName)}</strong><small class="table-subtext">${downloadEsc(mstFileSize(file.fileSize))} · ${downloadEsc(file.filePath)}</small></td>
      <td>${downloadEsc(file.computerHostname)}<small class="table-subtext">${downloadEsc(file.computerDeviceId)}</small></td>
      <td>${downloadSource(file)}</td>
      <td>${downloadResultBadge(file)}</td>
      <td>${downloadEngines(file)}</td>
      <td>${downloadEsc(mstFormatDate(file.detectedAt))}<small class="table-subtext">${downloadEsc(mstTimeAgo(file.detectedAt))}</small></td>
      <td>${file.sha256 ? `<code class="hash-short" title="${downloadEsc(file.sha256)}">${downloadEsc(file.sha256.slice(0, 12))}…</code>` : '<span class="table-subtext">—</span>'}</td>
      <td><a class="link-button" href="files.html?file=${downloadEsc(file.id)}">View</a>${file.scanId ? ` <a class="link-button" href="scan-history.html?scan=${downloadEsc(file.scanId)}">Report</a>` : ''}</td>
    </tr>`).join('');
  document.getElementById('downloadCount').textContent = `Showing ${rows.length} of ${downloadState.rows.length} downloads`;
  document.getElementById('downloadEmpty').classList.toggle('hidden', rows.length > 0);
}

async function loadDownloads({ quiet = false } = {}) {
  try {
    downloadState.rows = (await window.MSTApi.apiGet('/file-events?downloads=1&limit=500')).data;
  } catch (error) {
    if (!quiet) showMSTToast(mstApiErrorMessage(error, 'Unable to load downloads.'), 'downloadToast');
    return false;
  }
  populateDownloadComputers();
  renderDownloadStats();
  renderDownloads();
  return true;
}

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('downloads-page') || !window.MSTApi) return;
  ['downloadSearch', 'downloadComputerFilter', 'downloadResultFilter', 'downloadSourceFilter', 'downloadDateFilter']
    .forEach((id) => document.getElementById(id).addEventListener(id === 'downloadSearch' ? 'input' : 'change', renderDownloads));
  document.getElementById('downloadTableBody').innerHTML = '<tr><td colspan="8">Loading downloads…</td></tr>';
  loadDownloads().then(() => window.MSTLive?.start('downloads', () => loadDownloads({ quiet: true })));
});
