// Scan History: every scan in the MST database with server-side search, filters, sorting and paging.
// ?scan=<id> opens that scan's report (links from the File Scanner and Detected Files pages).
const scanHistory = { rows: [], total: 0, offset: 0, limit: 25, sort: 'id', dir: 'desc', timer: null, openId: null, searchTimer: null };
const SCAN_REFRESH_MS = 15000;

function scanFilters() {
  const value = (id) => document.getElementById(id)?.value.trim() || '';
  return { q: value('scanSearch'), risk: value('scanRiskFilter'), state: value('scanStateFilter'), computerId: value('scanComputerFilter'), source: value('scanSourceFilter'), from: value('scanFromFilter'), to: value('scanToFilter') };
}
function scanQuery(extra = {}) {
  const params = new URLSearchParams();
  Object.entries({ ...scanFilters(), sort: scanHistory.sort, dir: scanHistory.dir, ...extra }).forEach(([key, value]) => { if (value !== '' && value !== null && value !== undefined) params.set(key, value); });
  return params.toString();
}

async function loadScanStats() {
  const target = document.getElementById('scanStats');
  if (!target) return;
  try {
    const { data } = await window.MSTApi.apiGet('/dashboard');
    const cards = [
      ['FILES SCANNED', data.filesScanned, `${data.scansInProgress} in progress`, 'fa-layer-group', 'cyan'],
      ['HIGH RISK', data.highScans, 'Confirmed or strong evidence', 'fa-triangle-exclamation', 'red'],
      ['MEDIUM RISK', data.mediumScans, 'Needs investigation', 'fa-circle-exclamation', 'yellow'],
      ['SAFE', data.safeScans, 'No threat found by the scanners', 'fa-circle-check', 'green'],
      ['UNKNOWN', data.unknownScans, 'No engine could check them', 'fa-circle-question', 'gray'],
      ['FAILED', data.failedScans, 'Scan could not complete', 'fa-circle-xmark', 'gray']
    ];
    target.innerHTML = cards.map((card) => `<article class="metric-card card-surface"><div class="metric-header"><span class="metric-label">${card[0]}</span><span class="metric-icon ${card[4]}"><i class="fa-solid ${card[3]}"></i></span></div><strong class="metric-value">${mstEscape(card[1])}</strong><span class="metric-meta">${mstEscape(card[2])}</span></article>`).join('');
  } catch (error) {
    target.innerHTML = `<p class="panel-state error">${mstEscape(mstApiErrorMessage(error, 'Unable to load scan statistics.'))}</p>`;
  }
}

async function loadScanComputers() {
  const select = document.getElementById('scanComputerFilter');
  if (!select) return;
  try {
    const { data } = await window.MSTApi.apiGet('/computers');
    select.insertAdjacentHTML('beforeend', data.map((computer) => `<option value="${mstEscape(computer.id)}">${mstEscape(computer.hostname)} (${mstEscape(computer.deviceId)})</option>`).join(''));
  } catch { /* the filter simply stays at "All computers" */ }
}

function scanRowActions(scan) {
  const admin = window.MSTScanActions.isAdmin();
  const buttons = [`<button class="link-button scan-action" data-action="view" data-id="${scan.id}">View Details</button>`];
  if (scan.computerId) buttons.push(`<a class="link-button" href="computers.html?device=${encodeURIComponent(scan.computerDeviceId)}">View on Computer</a>`);
  if (admin && ['High', 'Medium'].includes(mstRiskOf(scan)) && scan.scanState === 'Completed') buttons.push(`<button class="link-button scan-action" data-action="investigate" data-id="${scan.id}">Investigate</button>`);
  return `<div class="row-actions">${buttons.join('')}</div>`;
}

function renderScanTable() {
  const body = document.getElementById('scanTableBody');
  if (!body) return;
  const esc = mstEscape;
  body.innerHTML = scanHistory.rows.map((scan) => `<tr>
      <td><strong>${esc(mstScanCode(scan.id))}</strong><small class="table-subtext">${esc({ Agent: 'Requested', Auto: 'Automatic', Upload: 'Upload' }[scan.source] || scan.source)}</small></td>
      <td><strong>${esc(scan.fileName || '—')}</strong><small class="table-subtext">${esc(scan.fileType || '')}</small>${scan.quarantineStatus ? `<small class="quarantine-tag"><i class="fa-solid fa-box-archive"></i> ${esc(scan.quarantineStatus.toUpperCase())}</small>` : ''}</td>
      <td>${esc(scan.computerHostname || 'MST server')}<small class="table-subtext">${esc(scan.computerDeviceId || 'File Scanner upload')}</small></td>
      <td class="hash-cell" title="${esc(scan.fileHash || '')}">${esc(scan.fileHash && scan.fileHash.length === 64 ? `${scan.fileHash.slice(0, 12)}…${scan.fileHash.slice(-6)}` : (scan.fileHash || '—'))}</td>
      <td>${mstRiskBadge(mstRiskOf(scan), scan.scanState)}</td>
      <td>${esc(scan.detection || '—')}</td>
      <td>${mstStrength(scan)}</td>
      <td>${esc(mstFormatDate(scan.completedAt || scan.createdAt))}<small class="table-subtext">${esc(scan.completedAt ? 'completed' : 'requested')}</small></td>
      <td><small>${esc(scan.scanner || '—')}</small></td>
      <td>${mstStateBadge(scan.scanState)}</td>
      <td>${scanRowActions(scan)}</td></tr>`).join('');
  const first = scanHistory.total ? scanHistory.offset + 1 : 0;
  const last = scanHistory.offset + scanHistory.rows.length;
  document.getElementById('scanCount').textContent = `${scanHistory.total} scan${scanHistory.total === 1 ? '' : 's'}`;
  document.getElementById('scanPageInfo').textContent = scanHistory.total ? `Showing ${first}-${last} of ${scanHistory.total}` : '';
  document.getElementById('scanPrev').disabled = scanHistory.offset === 0;
  document.getElementById('scanNext').disabled = last >= scanHistory.total;
  document.getElementById('scanEmpty')?.classList.toggle('hidden', scanHistory.rows.length > 0);
  document.querySelectorAll('.scan-table th button').forEach((button) => {
    const active = button.dataset.sort === scanHistory.sort;
    button.classList.toggle('sorted', active);
    button.querySelector('i')?.remove();
    if (active) button.insertAdjacentHTML('beforeend', ` <i class="fa-solid fa-sort-${scanHistory.dir === 'asc' ? 'up' : 'down'}"></i>`);
  });
  body.querySelectorAll('.scan-action').forEach((button) => button.addEventListener('click', () => (button.dataset.action === 'investigate' ? investigateScan(Number(button.dataset.id)) : showScanReport(Number(button.dataset.id)))));
}

async function loadScanHistory({ quiet = false } = {}) {
  const body = document.getElementById('scanTableBody');
  if (!quiet && body) body.innerHTML = '<tr><td colspan="11">Loading scans…</td></tr>';
  try {
    const payload = await window.MSTApi.apiGet(`/scans?${scanQuery({ limit: scanHistory.limit, offset: scanHistory.offset })}`);
    scanHistory.rows = payload.data;
    scanHistory.total = payload.meta?.total ?? payload.data.length;
    if (!scanHistory.rows.length && scanHistory.offset > 0) { scanHistory.offset = 0; return loadScanHistory({ quiet }); }
    renderScanTable();
  } catch (error) {
    if (quiet) return;
    scanHistory.rows = []; scanHistory.total = 0;
    renderScanTable();
    document.getElementById('scanEmptyText').textContent = mstApiErrorMessage(error, 'Unable to load scan history from the database.');
  }
  window.clearTimeout(scanHistory.timer);
  // Keep scans that are still running up to date without reloading the page.
  if (scanHistory.rows.some((scan) => ['Pending', 'Scanning'].includes(scan.scanState))) scanHistory.timer = window.setTimeout(() => { if (!document.hidden) loadScanHistory({ quiet: true }); }, SCAN_REFRESH_MS);
}

function reportActions(scan) {
  const actions = window.MSTScanActions;
  const admin = actions.isAdmin();
  const risk = mstRiskOf(scan);
  const done = ['Completed', 'Failed'].includes(scan.scanState);
  const quarantine = scan.quarantineStatus;
  const buttons = [];
  if (scan.computerId) buttons.push(['computer', 'View on Computer', 'fa-desktop', 'btn-secondary']);
  if (admin && done && ['High', 'Medium'].includes(risk)) buttons.push(['investigate', 'Investigate', 'fa-magnifying-glass-chart', 'btn-secondary']);
  if (admin && done && (scan.source === 'Upload' ? scan.storedCopy : scan.fileEventType && scan.fileEventType !== 'deleted' && !['Quarantined', 'Quarantine Requested', 'Release Requested', 'Delete Requested'].includes(quarantine))) buttons.push(['rescan', 'Scan Again', 'fa-rotate', 'btn-secondary']);
  if (admin && done && scan.fileEventId && scan.fileEventType !== 'deleted' && (!quarantine || ['Released', 'Failed', 'Deleted'].includes(quarantine)) && quarantine !== 'Deleted') buttons.push(['quarantine', 'Quarantine', 'fa-box-archive', 'btn-danger']);
  if (admin && quarantine === 'Quarantined') { if (risk !== 'High') buttons.push(['release', 'Release from Quarantine', 'fa-box-open', 'btn-secondary']); buttons.push(['delete-quarantined', 'Delete', 'fa-trash-can', 'btn-danger']); }
  if (admin && scan.source === 'Upload' && scan.storedCopy) buttons.push(['delete-copy', 'Delete', 'fa-trash-can', 'btn-danger']);
  buttons.push(['report', 'Export Report', 'fa-file-arrow-down', 'btn-secondary']);
  const notes = [];
  if (quarantine) notes.push(`<p class="scan-note"><i class="fa-solid fa-box-archive"></i> Quarantine: <b>${mstEscape(quarantine)}</b>${scan.quarantineError ? ` — ${mstEscape(scan.quarantineError)}` : ''}${quarantine === 'Quarantined' && risk === 'High' ? '. High-risk files cannot be released; delete the file, or scan it again after the investigation.' : ''}</p>`);
  if (scan.source === 'Upload') notes.push(`<p class="file-note">${scan.storedCopy ? `The uploaded copy is kept in protected storage until ${mstEscape(mstFormatDate(scan.storedUntil))} (retention policy), then deleted automatically.` : 'The uploaded copy is no longer stored.'}</p>`);
  if (!admin) notes.push('<p class="file-note">Scanning, quarantine and investigation actions are done by Admin accounts. Super Admin can review and export reports.</p>');
  return `${notes.join('')}<div class="threat-actions">${buttons.map(([action, label, icon, style]) => `<button class="${style} report-action" data-action="${action}"><i class="fa-solid ${icon}"></i> ${mstEscape(label)}</button>`).join('')}</div>`;
}

async function showScanReport(id, { refresh = false } = {}) {
  let scan;
  try {
    scan = (await window.MSTApi.apiGet(`/scans/${id}`)).data;
  } catch (error) {
    if (!refresh) showMSTToast(mstApiErrorMessage(error, 'Unable to load the scan report.'));
    return;
  }
  if (refresh && scanHistory.openId !== id) return;
  scanHistory.openId = id;
  document.getElementById('scanDetailsTitle').textContent = `${mstScanCode(scan.id)} · ${scan.fileName || ''}`;
  const related = scan.sameHash?.length ? `<h4 class="phase5-subheading">SAME FILE ELSEWHERE (SAME SHA-256)</h4><ul class="evidence-list">${scan.sameHash.map((other) => `<li><b>${mstEscape(mstScanCode(other.id))}</b> · ${mstEscape(other.computerHostname || 'MST server upload')} · ${mstRiskBadge(mstRiskOf(other), other.scanState)} · ${mstEscape(mstFormatDate(other.completedAt || other.createdAt))}</li>`).join('')}</ul>` : '';
  const threat = scan.threat ? `<p class="scan-note danger"><i class="fa-solid fa-shield-halved"></i> Threat record THR-${String(scan.threat.id).padStart(3, '0')} (${mstEscape(scan.threat.severity)}) is <b>${mstEscape(scan.threat.status)}</b>. <a class="text-link" href="threats.html">View threats</a></p>` : '';
  const content = document.getElementById('scanDetailsContent');
  content.innerHTML = mstScanReportHtml(scan) + threat + related + reportActions(scan);
  content.querySelectorAll('.report-action').forEach((button) => button.addEventListener('click', () => runReportAction(button.dataset.action, scan)));
  document.getElementById('scanDetailsModal').classList.remove('hidden');
  if (['Pending', 'Scanning'].includes(scan.scanState)) window.setTimeout(() => showScanReport(id, { refresh: true }), SCAN_REFRESH_MS);
}

async function runReportAction(action, scan) {
  const actions = window.MSTScanActions;
  const item = { id: scan.quarantineId, fileName: scan.fileName, originalPath: scan.filePath, computerHostname: scan.computerHostname };
  if (action === 'computer') window.location.href = `computers.html?device=${encodeURIComponent(scan.computerDeviceId)}`;
  if (action === 'investigate') investigateScan(scan.id);
  if (action === 'report') window.MSTApi.download(`/scans/${scan.id}/report`, `MST-${mstScanCode(scan.id)}-report.txt`).catch((error) => showMSTToast(mstApiErrorMessage(error, 'Unable to download the report.')));
  if (action === 'rescan') { const result = await actions.rescan(scan); if (result) showScanReport(result.id); }
  if (action === 'quarantine') actions.quarantine(scan.fileName, `/scans/${scan.id}/quarantine`);
  if (action === 'release') actions.release(item);
  if (action === 'delete-quarantined') actions.deleteQuarantined(item);
  if (action === 'delete-copy') actions.deleteStoredCopy(scan);
}

// Investigate: marks the related threat "Investigating" (recorded in the Activity Log) and shows the evidence trail.
async function investigateScan(id) {
  let data;
  try {
    data = (await window.MSTApi.apiPost(`/scans/${id}/investigate`, {})).data;
  } catch (error) {
    showMSTToast(window.MSTScanActions.errorText(error, 'Unable to open the investigation.'));
    return;
  }
  await showScanReport(id);
  const esc = mstEscape;
  const events = data.nearbyFileEvents.length ? data.nearbyFileEvents.map((event) => `<li><b>${esc(mstFormatDate(event.detectedAt))}</b> · ${esc(event.eventType)} · ${esc(event.fileName)}<small class="table-subtext">${esc(event.filePath)}</small></li>`).join('') : '<li>No other file activity on this computer within an hour of the scan.</li>';
  const copies = data.sameHash.length ? `${data.sameHash.length} other scan(s) of the same file: ${data.sameHash.map((other) => esc(`${mstScanCode(other.id)} (${other.computerHostname || 'upload'})`)).join(', ')}` : 'No other scans of the same file (same SHA-256).';
  document.getElementById('scanDetailsContent').insertAdjacentHTML('afterbegin', `<div class="scan-note danger"><b>INVESTIGATION</b> — ${data.threat ? `threat THR-${String(data.threat.id).padStart(3, '0')} is now <b>${esc(data.threat.status)}</b>` : 'no threat record is linked to this scan'}. ${copies}<h4 class="phase5-subheading">FILE ACTIVITY AROUND THE SCAN</h4><ul class="evidence-list">${events}</ul></div>`);
  loadScanHistory({ quiet: true });
}

function closeScanReport() { scanHistory.openId = null; document.getElementById('scanDetailsModal')?.classList.add('hidden'); }

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('scan-history-page') || !window.MSTApi) return;
  const reload = () => { scanHistory.offset = 0; loadScanHistory(); };
  ['scanRiskFilter', 'scanStateFilter', 'scanComputerFilter', 'scanSourceFilter', 'scanFromFilter', 'scanToFilter'].forEach((id) => document.getElementById(id)?.addEventListener('change', reload));
  document.getElementById('scanSearch')?.addEventListener('input', () => { window.clearTimeout(scanHistory.searchTimer); scanHistory.searchTimer = window.setTimeout(reload, 350); });
  ['clearScanFilters', 'emptyScanClear'].forEach((id) => document.getElementById(id)?.addEventListener('click', () => {
    ['scanSearch', 'scanRiskFilter', 'scanStateFilter', 'scanComputerFilter', 'scanSourceFilter', 'scanFromFilter', 'scanToFilter'].forEach((field) => { const element = document.getElementById(field); if (element) element.value = ''; });
    reload();
  }));
  document.querySelectorAll('.scan-table th button').forEach((button) => button.addEventListener('click', () => {
    scanHistory.dir = scanHistory.sort === button.dataset.sort && scanHistory.dir === 'desc' ? 'asc' : 'desc';
    scanHistory.sort = button.dataset.sort;
    reload();
  }));
  document.getElementById('scanPrev')?.addEventListener('click', () => { scanHistory.offset = Math.max(0, scanHistory.offset - scanHistory.limit); loadScanHistory(); });
  document.getElementById('scanNext')?.addEventListener('click', () => { scanHistory.offset += scanHistory.limit; loadScanHistory(); });
  document.getElementById('exportScans')?.addEventListener('click', () => window.MSTApi.download(`/scans/export?${scanQuery()}`, `MST-scan-history-${new Date().toISOString().slice(0, 10)}.csv`).then(() => showMSTToast('Scan history exported')).catch((error) => showMSTToast(mstApiErrorMessage(error, 'Unable to export scan history.'))));
  document.querySelectorAll('[data-scan-close]').forEach((button) => button.addEventListener('click', closeScanReport));
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { closeScanReport(); window.MSTScanActions.close(); } });
  document.addEventListener('mst:scans-changed', () => { loadScanHistory({ quiet: true }); loadScanStats(); if (scanHistory.openId) showScanReport(scanHistory.openId, { refresh: true }); });
  loadScanStats();
  loadScanComputers();
  loadScanHistory();
  const linked = new URLSearchParams(window.location.search).get('scan');
  if (linked && /^\d+$/.test(linked)) showScanReport(Number(linked));
});
