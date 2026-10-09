// Detected Files: file activity reported by the lab-PC agents (/api/file-events), classification, scans and quarantine.
// ?computer=<id> (from a computer's details window) preselects that computer once.
const fileState = { rows: [], openId: null, timer: null, linkedComputer: new URLSearchParams(window.location.search).get('computer') };
const FILE_REFRESH_MS = 10000;
const fileEsc = (value) => mstEscape(value);
const fileStatusClass = (status) => String(status).toLowerCase().replace(/\s+/g, '-');
const fileIsAdmin = () => sessionStorage.getItem('mstRole') === 'admin'; // File Scanner is an Admin module; the server enforces it too.
const fileActiveQuarantine = (file) => ['Quarantine Requested', 'Quarantined', 'Release Requested', 'Delete Requested'].includes(file.quarantineStatus);
const fileScanRunning = (file) => ['Pending', 'Scanning'].includes(file.scanState);
const fileExists = (file) => file.eventType !== 'deleted' && file.quarantineStatus !== 'Deleted' && !fileActiveQuarantine(file);
const fileDownloaded = (file) => ['internet', 'browser_download'].includes(file.origin);

function fileSize(bytes) { return mstFileSize(bytes); }

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

// Risk levels only come from a scan; a file that was never scanned is "Not scanned", not "Safe".
function fileRiskBadge(file) {
  if (fileScanRunning(file)) return mstRiskBadge(null, file.scanState);
  if (!file.scanId) return `<span class="risk-badge unknown">${file.eventType === 'deleted' ? 'N/A' : 'NOT SCANNED'}</span>`;
  return mstRiskBadge(mstRiskOf({ riskLevel: file.riskLevel }));
}

function fileOrigin(file) {
  if (file.origin === 'internet') return `<span class="origin-tag" title="Windows Mark of the Web confirms the file came from the internet"><i class="fa-solid fa-globe"></i> Downloaded${file.downloadUrl ? ` from ${fileEsc(String(file.downloadUrl).replace(/^https?:\/\/([^/:]+).*$/i, '$1'))}` : ''} (confirmed)</span>`;
  if (file.origin === 'browser_download') return '<span class="origin-tag" title="A browser finished writing the file (temporary download file renamed). The source is not known."><i class="fa-solid fa-download"></i> Browser download completed</span>';
  return '';
}

function fileActivityBadge(file) {
  const badge = {
    created: '<span class="scan-result-status warning"><i class="fa-solid fa-file-circle-plus"></i> NEW FILE</span>',
    modified: '<span class="scan-result-status pending"><i class="fa-solid fa-pen"></i> MODIFIED</span>',
    renamed: '<span class="scan-result-status pending"><i class="fa-solid fa-i-cursor"></i> RENAMED</span>',
    deleted: '<span class="severity-level unknown"><i class="fa-solid fa-trash-can"></i> DELETED</span>'
  }[file.eventType] || fileEsc(file.eventType);
  return badge + (fileOrigin(file) ? `<br>${fileOrigin(file)}` : '');
}

function fileStatusBadge(file) {
  if (file.quarantineStatus && file.quarantineStatus !== 'Released') return `<span class="quarantine-tag"><i class="fa-solid fa-box-archive"></i> ${fileEsc(file.quarantineStatus.toUpperCase())}</span>`;
  return `<span class="threat-status ${fileStatusClass(file.status)}">${fileScanRunning(file) ? '<i class="fa-solid fa-spinner"></i> ' : ''}${fileEsc(String(file.status).toUpperCase())}</span>`;
}

function renderFileStats() {
  const target = document.getElementById('fileStats');
  if (!target) return;
  const rows = fileState.rows;
  const count = (test) => rows.filter(test).length;
  const values = [
    ['FILES DETECTED', count((file) => file.eventType === 'created'), 'New files reported', 'fa-file-circle-plus', 'cyan'],
    ['DOWNLOADS', count(fileDownloaded), 'Browser downloads / internet files', 'fa-download', 'cyan'],
    ['SCANS RUNNING', count(fileScanRunning), 'Waiting for the agent', 'fa-spinner', 'cyan'],
    ['HIGH RISK', count((file) => file.scanId && ['High', 'Critical'].includes(file.riskLevel)), 'From scan results', 'fa-shield-halved', 'red'],
    ['IN QUARANTINE', count((file) => file.quarantineStatus === 'Quarantined'), 'Isolated on lab PCs', 'fa-box-archive', 'yellow'],
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

function fileMatchesRisk(file, risk) {
  if (risk === 'all') return true;
  if (risk === 'none') return !file.scanId && file.eventType !== 'deleted';
  if (risk === 'quarantined') return file.quarantineStatus === 'Quarantined';
  return Boolean(file.scanId) && !fileScanRunning(file) && mstRiskOf({ riskLevel: file.riskLevel }) === risk;
}

function renderFiles() {
  const body = document.getElementById('fileTableBody');
  if (!body) return;
  const value = (id) => document.getElementById(id)?.value || 'all';
  const query = (document.getElementById('fileSearch')?.value || '').toLowerCase().trim();
  const [computer, activity, risk, classification, days] = ['fileComputerFilter', 'fileActivityFilter', 'fileRiskFilter', 'fileClassFilter', 'fileDateFilter'].map(value);
  const since = days === 'all' ? null : (() => { const start = new Date(); start.setHours(0, 0, 0, 0); start.setDate(start.getDate() - (Number(days) - 1)); return start; })();
  const rows = fileState.rows.filter((file) => `${file.fileName} ${file.filePath} ${file.previousPath || ''} ${file.computerHostname} ${file.computerDeviceId} ${file.sha256 || ''}`.toLowerCase().includes(query)
    && (computer === 'all' || String(file.computerId) === computer)
    && (activity === 'all' || (activity === 'downloaded' ? fileDownloaded(file) : file.eventType === activity))
    && fileMatchesRisk(file, risk)
    && (classification === 'all' || fileClassification(file) === classification)
    && (!since || (mstParseDate(file.detectedAt) || 0) >= since));
  body.innerHTML = rows.map((file) => {
    const scanButton = fileIsAdmin() && fileExists(file) ? `<button class="link-button scan-file" data-id="${fileEsc(file.id)}" ${fileScanRunning(file) ? 'disabled' : ''}>Scan</button>` : '';
    const previous = file.previousPath ? `<small class="table-subtext">was: ${fileEsc(file.previousPath)}</small>` : '';
    return `<tr><td><strong>${fileEsc(file.fileName)}</strong><small class="table-subtext">${fileEsc(file.filePath)}</small>${previous}</td><td>${fileEsc(file.computerHostname)}<small class="table-subtext">${fileEsc(file.computerDeviceId)}</small></td><td>${fileActivityBadge(file)}</td><td>${fileEsc(fileSize(file.fileSize))}</td><td>${fileRiskBadge(file)}</td><td>${fileClassBadge(file)}</td><td>${fileEsc(mstFormatDate(file.detectedAt))}<small class="table-subtext">${fileEsc(mstTimeAgo(file.detectedAt))}</small></td><td>${fileStatusBadge(file)}</td><td><button class="link-button view-file" data-id="${fileEsc(file.id)}">View</button>${scanButton}</td></tr>`;
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

function fileLatestScanSummary(scan) {
  if (!scan) return '<p class="file-note">This file has not been scanned yet.</p>';
  if (['Pending', 'Scanning'].includes(scan.scanState)) return `<p class="file-note"><i class="fa-solid fa-spinner"></i> ${scan.scanState === 'Pending' ? 'Waiting for the agent to pick up the scan…' : 'The agent is scanning the file…'}</p>`;
  const details = mstScanDetails(scan);
  const engines = (details.engines || []).map((engine) => `${fileEsc(engine.name)}: ${engine.result === 'detected' ? `<b>detected ${fileEsc(engine.signature || '')}</b>` : fileEsc(engine.result === 'clean' ? 'no threat' : engine.result)}`).join(' · ') || 'No antivirus engine result';
  return `<div class="phase5-detail-grid">
      <div><span>Risk Level</span><strong>${mstRiskBadge(mstRiskOf(scan), scan.scanState)}</strong></div>
      <div><span>Evidence Strength</span><strong>${mstStrength(scan)}</strong></div>
      <div class="file-wide"><span>Detection</span><strong>${fileEsc(scan.detection || '—')}</strong></div>
      <div class="file-wide"><span>Antivirus</span><strong>${engines}</strong></div>
      <div class="file-wide"><span>VirusTotal</span><strong>${mstVirusTotalText(details.virusTotal)}</strong></div>
    </div>
    ${mstRiskOf(scan) === 'Safe' ? '<p class="safe-note">Safe means the configured scanners found no threat; it does not guarantee the file is completely safe.</p>' : ''}
    <p><a class="text-link" href="scan-history.html?scan=${fileEsc(scan.id)}">Open the full scan report (${fileEsc(mstScanCode(scan.id))}) <i class="fa-solid fa-arrow-right"></i></a></p>`;
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
  const running = fileScanRunning(file);
  const admin = fileIsAdmin();
  const latestRisk = latest ? mstRiskOf(latest) : null;
  const offlineNote = running && file.computerStatus === 'offline' ? `<p class="file-note">${fileEsc(file.computerHostname)} is offline. The scan will run when its agent reconnects.</p>` : '';
  const buttons = [];
  if (!admin) buttons.push('<p class="file-note">Scanning and quarantine are done by Admin accounts (File Scanner). Super Admin can review and classify files.</p>');
  else if (file.eventType === 'deleted') buttons.push('<p class="file-note">This file was deleted, so it can no longer be scanned.</p>');
  else if (fileActiveQuarantine(file)) buttons.push(`<p class="file-note">The file is ${fileEsc(file.quarantineStatus.toLowerCase())}.</p>`);
  else {
    buttons.push(`<button class="btn-primary file-action" data-action="scan" ${running ? 'disabled' : ''}><i class="fa-solid fa-magnifying-glass"></i> ${running ? 'Scan in progress…' : `Scan on ${fileEsc(file.computerHostname)}`}</button>`);
    if (latest && !running && file.quarantineStatus !== 'Deleted') buttons.push('<button class="btn-danger file-action" data-action="quarantine"><i class="fa-solid fa-box-archive"></i> Quarantine</button>');
  }
  if (admin && file.quarantineStatus === 'Quarantined') {
    if (latestRisk !== 'High') buttons.push('<button class="btn-secondary file-action" data-action="release"><i class="fa-solid fa-box-open"></i> Release from Quarantine</button>');
    buttons.push('<button class="btn-danger file-action" data-action="delete"><i class="fa-solid fa-trash-can"></i> Delete permanently</button>');
  }
  const suggestion = !file.classification && file.suggestedConfidential ? '<small class="table-subtext">Suggested by MST from the file name or folder — confirm or change it below.</small>' : '';
  const history = file.scans?.length ? file.scans.map((scan) => `<p><time>${fileEsc(mstFormatDate(scan.completedAt || scan.createdAt))}</time> ${mstRiskBadge(mstRiskOf(scan), scan.scanState)} <a class="text-link" href="scan-history.html?scan=${fileEsc(scan.id)}">${fileEsc(mstScanCode(scan.id))}</a> · ${fileEsc(scan.source === 'Auto' ? 'automatic' : `requested by ${scan.createdByUsername || '—'}`)}</p>`).join('') : '<p><time>—</time> This file has not been scanned yet.</p>';
  const origin = file.origin === 'internet' ? `Downloaded from the internet — confirmed by Windows (Mark of the Web)${file.downloadUrl ? `. Source: ${fileEsc(file.downloadUrl)}` : '. The browser did not record the source.'}`
    : file.origin === 'browser_download' ? 'A browser finished downloading it (its temporary download file was renamed). Windows did not confirm the source.'
    : file.eventType === 'deleted' ? '—' : 'Created on the computer (no download evidence)';
  content.innerHTML = `<div class="phase5-detail-grid">
      <div><span>File Name</span><strong>${fileEsc(file.fileName)}</strong></div>
      <div><span>Activity</span><strong>${fileActivityBadge(file)}</strong></div>
      <div class="file-wide"><span>Location</span><strong>${fileEsc(file.filePath)}</strong></div>
      ${file.previousPath ? `<div class="file-wide"><span>Previous Location (renamed from)</span><strong>${fileEsc(file.previousPath)}</strong></div>` : ''}
      <div class="file-wide"><span>How It Arrived</span><strong>${origin}</strong></div>
      <div><span>File Size</span><strong>${fileEsc(fileSize(file.fileSize))}</strong></div>
      <div><span>Detected</span><strong>${fileEsc(mstFormatDate(file.detectedAt))}</strong></div>
      <div><span>Classification</span><strong>${fileClassBadge(file)}</strong>${suggestion}</div>
      <div><span>Status</span><strong>${fileStatusBadge(file)}</strong></div>
      <div class="file-wide"><span>SHA-256</span><strong class="hash-cell">${fileEsc(file.sha256 || 'Not available (file too large or deleted)')}</strong></div>
    </div>
    <div class="relationship-panel"><h4>DETECTED ON</h4><strong>${fileEsc(file.computerHostname)}</strong><p>Device ID: ${fileEsc(file.computerDeviceId)} · IP: ${fileEsc(file.computerIpAddress)}</p><a class="text-link" href="computers.html?device=${encodeURIComponent(file.computerDeviceId)}">View Computer <i class="fa-solid fa-arrow-right"></i></a></div>
    ${file.quarantineError ? `<p class="scan-note danger">Last quarantine action failed: ${fileEsc(file.quarantineError)}</p>` : ''}
    <h4 class="phase5-subheading">LATEST SCAN RESULT</h4>${fileLatestScanSummary(latest)}
    <h4 class="phase5-subheading">SCAN HISTORY</h4><div class="phase5-timeline">${history}</div>
    <div class="threat-actions">${buttons.join('')}${offlineNote}
      <button class="btn-secondary file-action" data-action="Confidential"><i class="fa-solid fa-user-lock"></i> Mark Confidential</button>
      <button class="btn-secondary file-action" data-action="Normal"><i class="fa-solid fa-file"></i> Mark Normal</button>
      ${file.status === 'New' ? '<button class="btn-secondary file-action" data-action="Reviewed"><i class="fa-solid fa-eye"></i> Mark Reviewed</button>' : ''}
    </div>`;
  const item = { id: file.quarantineId, fileName: file.fileName, originalPath: file.filePath, computerHostname: file.computerHostname };
  content.querySelectorAll('.file-action').forEach((button) => button.addEventListener('click', () => {
    const action = button.dataset.action;
    if (action === 'scan') requestFileScan(file.id);
    else if (action === 'quarantine') window.MSTScanActions.quarantine(file.fileName, `/file-events/${file.id}/quarantine`);
    else if (action === 'release') window.MSTScanActions.release(item);
    else if (action === 'delete') window.MSTScanActions.deleteQuarantined(item);
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
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { closeFileDetails(); window.MSTScanActions?.close(); } });
  document.addEventListener('mst:scans-changed', () => loadFiles({ quiet: true }));
  const body = document.getElementById('fileTableBody');
  if (body) body.innerHTML = '<tr><td colspan="9">Loading detected files…</td></tr>';
  loadFiles();
  // Keep the list current so new files and scan results appear without reloading the page.
  fileState.timer = window.setInterval(() => { if (!document.hidden) loadFiles({ quiet: true }); }, FILE_REFRESH_MS);
});
