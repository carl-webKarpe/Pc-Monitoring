// Detected Files: files reported by the lab-PC agents (/api/file-events), classification and on-PC scans.
// ?computer=<id> (from a computer's details window) preselects that computer once.
const fileState = { rows: [], openId: null, timer: null, linkedComputer: new URLSearchParams(window.location.search).get('computer') };
const FILE_REFRESH_MS = 10000;
const fileEsc = (value) => mstEscape(value);
const fileRiskClass = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Safe: 'safe', Unknown: 'unknown' };
const fileStatusClass = (status) => String(status).toLowerCase().replace(/\s+/g, '-');
const fileCanScan = () => sessionStorage.getItem('mstRole') === 'admin'; // File Scanner is an Admin module; the server enforces it too.

function fileSize(bytes) {
  if (bytes === null || bytes === undefined) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

// "Confidential"/"Normal" once the admin decides; until then the system's suggestion.
function fileClassification(file) {
  if (file.classification) return file.classification;
  return file.suggestedConfidential ? 'Possibly confidential' : 'Normal';
}

function fileClassBadge(file) {
  const label = fileClassification(file);
  const tone = label === 'Confidential' ? 'confidential' : label === 'Possibly confidential' ? 'possible' : 'normal';
  return `<span class="file-class ${tone}"><i class="fa-solid ${tone === 'normal' ? 'fa-file' : 'fa-user-lock'}"></i> ${fileEsc(label.toUpperCase())}</span>`;
}

function fileRiskBadge(file) {
  const risk = file.riskLevel || 'Unknown';
  const scanned = file.status === 'Scanned';
  const label = risk === 'Unknown' ? (file.eventType === 'deleted' ? 'N/A' : 'NOT SCANNED') : `${risk.toUpperCase()}${scanned ? '' : ' (PRE-SCAN)'}`;
  return `<span class="severity-level ${fileRiskClass[risk] || 'unknown'}">${fileEsc(label)}</span>`;
}

function fileActivityBadge(file) {
  return file.eventType === 'created' ? '<span class="scan-result-status warning"><i class="fa-solid fa-file-circle-plus"></i> NEW FILE</span>' : '<span class="severity-level unknown"><i class="fa-solid fa-trash-can"></i> DELETED</span>';
}

function fileStatusBadge(file) {
  const pending = file.status === 'Scan Requested' && file.scanStatus === 'PENDING';
  return `<span class="threat-status ${fileStatusClass(file.status)}">${pending ? '<i class="fa-solid fa-spinner"></i> ' : ''}${fileEsc(String(file.status).toUpperCase())}</span>`;
}

function renderFileStats() {
  const target = document.getElementById('fileStats');
  if (!target) return;
  const rows = fileState.rows;
  const count = (test) => rows.filter(test).length;
  const values = [
    ['FILES DETECTED', count((file) => file.eventType === 'created'), 'New files reported', 'fa-file-circle-plus', 'cyan'],
    ['DELETED', count((file) => file.eventType === 'deleted'), 'Deleted files reported', 'fa-trash-can', 'gray'],
    ['NOT YET REVIEWED', count((file) => file.status === 'New'), 'Waiting for review', 'fa-eye', 'yellow'],
    ['SCANS PENDING', count((file) => file.status === 'Scan Requested'), 'Waiting for the agent', 'fa-spinner', 'cyan'],
    ['HIGH RISK', count((file) => ['High', 'Critical'].includes(file.riskLevel)), 'High or critical', 'fa-shield-halved', 'red'],
    ['CONFIDENTIAL', count((file) => fileClassification(file) !== 'Normal'), 'Confirmed or suggested', 'fa-user-lock', 'yellow']
  ];
  target.innerHTML = values.map((item) => `<article class="metric-card card-surface"><div class="metric-header"><span class="metric-label">${item[0]}</span><span class="metric-icon ${item[4]}"><i class="fa-solid ${item[3]}"></i></span></div><strong class="metric-value">${item[1]}</strong><span class="metric-meta">${item[2]}</span></article>`).join('');
}

function populateFileComputerFilter() {
  const select = document.getElementById('fileComputerFilter');
  if (!select) return;
  const current = fileState.linkedComputer || select.value || 'all';
  fileState.linkedComputer = null;
  const computers = [...new Map(fileState.rows.map((file) => [String(file.computerId), file.computerHostname])).entries()].sort((a, b) => a[1].localeCompare(b[1]));
  select.innerHTML = `<option value="all">All computers</option>${computers.map(([id, name]) => `<option value="${fileEsc(id)}">${fileEsc(name)}</option>`).join('')}`;
  select.value = computers.some(([id]) => id === current) ? current : 'all';
}

function renderFiles() {
  const body = document.getElementById('fileTableBody');
  if (!body) return;
  const value = (id) => document.getElementById(id)?.value || 'all';
  const query = (document.getElementById('fileSearch')?.value || '').toLowerCase().trim();
  const [computer, activity, risk, classification, days] = ['fileComputerFilter', 'fileActivityFilter', 'fileRiskFilter', 'fileClassFilter', 'fileDateFilter'].map(value);
  const since = days === 'all' ? null : (() => { const start = new Date(); start.setHours(0, 0, 0, 0); start.setDate(start.getDate() - (Number(days) - 1)); return start; })();
  const rows = fileState.rows.filter((file) => `${file.fileName} ${file.filePath} ${file.computerHostname} ${file.computerDeviceId}`.toLowerCase().includes(query)
    && (computer === 'all' || String(file.computerId) === computer)
    && (activity === 'all' || file.eventType === activity)
    && (risk === 'all' || (file.riskLevel || 'Unknown') === risk)
    && (classification === 'all' || fileClassification(file) === classification)
    && (!since || (mstParseDate(file.detectedAt) || 0) >= since));
  body.innerHTML = rows.map((file) => {
    const scanButton = fileCanScan() && file.eventType === 'created' ? `<button class="link-button scan-file" data-id="${fileEsc(file.id)}" ${file.status === 'Scan Requested' ? 'disabled' : ''}>Scan</button>` : '';
    return `<tr><td><strong>${fileEsc(file.fileName)}</strong><small class="table-subtext">${fileEsc(file.filePath)}</small></td><td>${fileEsc(file.computerHostname)}<small class="table-subtext">${fileEsc(file.computerDeviceId)}</small></td><td>${fileActivityBadge(file)}</td><td>${fileEsc(fileSize(file.fileSize))}</td><td>${fileRiskBadge(file)}</td><td>${fileClassBadge(file)}</td><td>${fileEsc(mstFormatDate(file.detectedAt))}<small class="table-subtext">${fileEsc(mstTimeAgo(file.detectedAt))}</small></td><td>${fileStatusBadge(file)}</td><td><button class="link-button view-file" data-id="${fileEsc(file.id)}">View</button>${scanButton}</td></tr>`;
  }).join('');
  document.getElementById('fileCount').textContent = `Showing ${rows.length} of ${fileState.rows.length} files`;
  document.getElementById('fileEmpty')?.classList.toggle('hidden', rows.length > 0);
  body.querySelectorAll('.view-file').forEach((button) => button.addEventListener('click', () => showFileDetails(Number(button.dataset.id))));
  body.querySelectorAll('.scan-file').forEach((button) => button.addEventListener('click', () => requestFileScan(Number(button.dataset.id))));
}

async function loadFiles({ quiet = false } = {}) {
  try {
    fileState.rows = (await window.MSTApi.apiGet('/file-events?limit=500')).data;
  } catch (error) {
    if (!quiet) showMSTToast(mstApiErrorMessage(error, 'Unable to load detected files.'), 'fileToast');
    return;
  }
  populateFileComputerFilter();
  renderFileStats();
  renderFiles();
  if (fileState.openId !== null) showFileDetails(fileState.openId, { refresh: true });
}

function scanFindings(scan) {
  let details = null;
  try { details = scan.scanDetails ? JSON.parse(scan.scanDetails) : null; } catch { details = null; }
  if (!details) return '';
  if (details.error) return `<p><time>FAILED</time> ${fileEsc(details.error)}</p>`;
  if (!details.findings?.length) return '<p><time>SAFE</time> No risk indicators found.</p>';
  return details.findings.map((finding) => `<p><time>${fileEsc(finding.severity)}</time> <strong>${fileEsc(finding.title)}</strong> — ${fileEsc(finding.detail)}</p>`).join('');
}

async function showFileDetails(id, { refresh = false } = {}) {
  const modal = document.getElementById('fileDetailsModal');
  const content = document.getElementById('fileDetailsContent');
  if (!modal || !content) return;
  let file;
  try {
    file = (await window.MSTApi.apiGet(`/file-events/${id}`)).data;
  } catch (error) {
    if (!refresh) showMSTToast(mstApiErrorMessage(error, 'Unable to load file details.'), 'fileToast');
    return;
  }
  if (refresh && fileState.openId !== id) return;
  fileState.openId = id;
  document.getElementById('fileDetailsTitle').textContent = file.fileName;
  const latest = file.scans?.[0];
  const pending = file.status === 'Scan Requested' && file.scanStatus === 'PENDING';
  const offlineNote = pending && file.computerStatus === 'offline' ? `<p class="file-note">${fileEsc(file.computerHostname)} is offline. The scan will run when its agent reconnects.</p>` : '';
  const scanAction = file.eventType !== 'created' ? '<p class="file-note">This file was deleted, so it can no longer be scanned.</p>'
    : fileCanScan() ? `<button class="btn-primary file-action" data-action="scan" ${pending ? 'disabled' : ''}><i class="fa-solid fa-magnifying-glass"></i> ${pending ? 'Waiting for the agent…' : `Scan on ${fileEsc(file.computerHostname)}`}</button>`
    : '<p class="file-note">Scanning is done by Admin accounts (File Scanner). Super Admin can review and classify files.</p>';
  const suggestion = !file.classification && file.suggestedConfidential ? '<small class="table-subtext">Suggested by MST from the file name or folder — confirm or change it below.</small>' : '';
  const history = file.scans?.length ? file.scans.map((scan) => `<p><time>${fileEsc(mstFormatDate(scan.completedAt || scan.createdAt))}</time> <span class="scan-result-status ${fileEsc(String(scan.status).toLowerCase())}">${fileEsc(scan.status)}</span> ${fileEsc(scan.riskLevel || '')} · ${fileEsc(scan.duration || '—')} · requested by ${fileEsc(scan.createdByUsername || '—')}</p>`).join('') : '<p><time>—</time> This file has not been scanned yet.</p>';
  content.innerHTML = `<div class="phase5-detail-grid">
      <div><span>File Name</span><strong>${fileEsc(file.fileName)}</strong></div>
      <div><span>Activity</span><strong>${fileActivityBadge(file)}</strong></div>
      <div class="file-wide"><span>Location</span><strong>${fileEsc(file.filePath)}</strong></div>
      <div><span>File Size</span><strong>${fileEsc(fileSize(file.fileSize))}</strong></div>
      <div><span>Detected</span><strong>${fileEsc(mstFormatDate(file.detectedAt))}</strong></div>
      <div><span>Risk Level</span><strong>${fileRiskBadge(file)}</strong></div>
      <div><span>Classification</span><strong>${fileClassBadge(file)}</strong>${suggestion}</div>
      <div><span>Status</span><strong>${fileStatusBadge(file)}</strong></div>
      <div><span>Last Scan</span><strong>${latest ? fileEsc(mstFormatDate(latest.completedAt || latest.createdAt)) : 'Never'}</strong></div>
      <div class="file-wide"><span>SHA-256</span><strong>${fileEsc(file.sha256 || 'Not available (file too large or deleted)')}</strong></div>
    </div>
    <div class="relationship-panel"><h4>DETECTED ON</h4><strong>${fileEsc(file.computerHostname)}</strong><p>Device ID: ${fileEsc(file.computerDeviceId)} · IP: ${fileEsc(file.computerIpAddress)}</p><a class="text-link" href="computers.html">View Computer <i class="fa-solid fa-arrow-right"></i></a></div>
    <h4 class="phase5-subheading">SCAN RESULT</h4><div class="phase5-timeline">${latest ? scanFindings(latest) || (pending ? '<p><time>…</time> Waiting for the agent to scan the file.</p>' : '') : '<p><time>—</time> Not scanned yet.</p>'}</div>
    <h4 class="phase5-subheading">SCAN HISTORY</h4><div class="phase5-timeline">${history}</div>
    <div class="threat-actions">${scanAction}${offlineNote}
      <button class="btn-secondary file-action" data-action="Confidential"><i class="fa-solid fa-user-lock"></i> Mark Confidential</button>
      <button class="btn-secondary file-action" data-action="Normal"><i class="fa-solid fa-file"></i> Mark Normal</button>
      ${file.status === 'New' ? '<button class="btn-secondary file-action" data-action="Reviewed"><i class="fa-solid fa-eye"></i> Mark Reviewed</button>' : ''}
    </div>`;
  content.querySelectorAll('.file-action').forEach((button) => button.addEventListener('click', () => {
    const action = button.dataset.action;
    if (action === 'scan') requestFileScan(file.id);
    else updateFile(file.id, action === 'Reviewed' ? { status: 'Reviewed' } : { classification: action });
  }));
  modal.classList.remove('hidden');
}

async function updateFile(id, payload) {
  try {
    await window.MSTApi.apiPut(`/file-events/${id}`, payload);
    showMSTToast(payload.status ? 'File marked as reviewed' : `File marked ${payload.classification}`, 'fileToast');
    await loadFiles();
  } catch (error) {
    const fieldErrors = error.payload?.errors ? Object.values(error.payload.errors).join(' ') : '';
    showMSTToast(fieldErrors || mstApiErrorMessage(error, 'Unable to update the file.'), 'fileToast');
  }
}

async function requestFileScan(id) {
  try {
    const { message } = await window.MSTApi.apiPost(`/file-events/${id}/scan`, {});
    showMSTToast(message, 'fileToast');
    await loadFiles();
  } catch (error) {
    showMSTToast(mstApiErrorMessage(error, 'Unable to request the scan.'), 'fileToast');
  }
}

function closeFileDetails() {
  fileState.openId = null;
  document.getElementById('fileDetailsModal')?.classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('files-page') || !window.MSTApi) return;
  ['fileSearch', 'fileComputerFilter', 'fileActivityFilter', 'fileRiskFilter', 'fileClassFilter', 'fileDateFilter'].forEach((id) => document.getElementById(id)?.addEventListener(id === 'fileSearch' ? 'input' : 'change', renderFiles));
  document.getElementById('refreshFiles')?.addEventListener('click', () => loadFiles());
  document.querySelectorAll('[data-files-close]').forEach((button) => button.addEventListener('click', closeFileDetails));
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeFileDetails(); });
  const body = document.getElementById('fileTableBody');
  if (body) body.innerHTML = '<tr><td colspan="9">Loading detected files…</td></tr>';
  loadFiles();
  // Keep the list current so new files and scan results appear without reloading the page.
  fileState.timer = window.setInterval(() => { if (!document.hidden) loadFiles({ quiet: true }); }, FILE_REFRESH_MS);
});
