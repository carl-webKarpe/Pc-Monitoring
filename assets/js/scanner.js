// File Scanner (Admin): uploads one file to the MST server, which scans it with the installed antivirus engines,
// VirusTotal and static analysis. Everything shown here comes from the server's real result.
document.addEventListener('DOMContentLoaded', () => {
  const scannerPage = document.getElementById('scanner-page');
  if (!scannerPage || scannerPage.dataset.restricted === 'true' || !window.MSTApi) return;

  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const scanProgress = document.getElementById('scanProgress');
  const scanResult = document.getElementById('scanResult');
  const bar = document.getElementById('uploadBar');
  const state = { maxBytes: null, pollTimer: null, lastFile: null };
  const show = (element) => [dropZone, scanProgress, scanResult].forEach((node) => node?.classList.toggle('hidden', node !== element));

  async function loadCapabilities() {
    const limits = document.getElementById('scannerLimits');
    const chips = document.getElementById('engineChips');
    try {
      const { data } = await window.MSTApi.apiGet('/file-scanner');
      state.maxBytes = data.maxUploadBytes;
      limits.innerHTML = `Any file type · Maximum size: <b>${mstEscape(mstFileSize(data.maxUploadBytes))}</b> · Uploaded copies are kept ${mstEscape(data.retentionDays)} day(s) for “Scan Again”, then deleted`;
      const engines = data.engines.map((engine) => `<span class="engine-chip ${engine.available ? 'ok' : 'off'}" title="${mstEscape(engine.detail)}"><i class="fa-solid ${engine.available ? 'fa-circle-check' : 'fa-circle-minus'}"></i> ${mstEscape(engine.name)} ${mstEscape(engine.version || '')}${engine.available ? '' : ' — unavailable'}</span>`);
      engines.push(`<span class="engine-chip ${data.virusTotal.configured ? 'ok' : 'off'}"><i class="fa-solid ${data.virusTotal.configured ? 'fa-circle-check' : 'fa-circle-minus'}"></i> VirusTotal${data.virusTotal.configured ? '' : ' — no API key'}</span>`);
      engines.push('<span class="engine-chip ok"><i class="fa-solid fa-circle-check"></i> MST static analysis</span>');
      chips.innerHTML = engines.join('');
      if (!data.engines.some((engine) => engine.available) && !data.virusTotal.configured) chips.insertAdjacentHTML('afterend', '<p class="scan-note">No antivirus engine or VirusTotal key is available, so results will be <b>Unknown</b> unless static analysis finds something. See SCANNER.md.</p>');
      const vtOption = document.getElementById('submitToVirusTotal');
      if (vtOption) vtOption.disabled = !data.virusTotal.configured;
    } catch (error) {
      limits.textContent = mstApiErrorMessage(error, 'Unable to reach the scanner. Is the API running?');
    }
  }

  function setProgress(title, text, fraction) {
    document.getElementById('progressTitle').textContent = title;
    document.getElementById('progressText').textContent = text;
    bar.classList.toggle('indeterminate', fraction === null);
    bar.querySelector('span').style.width = fraction === null ? '' : `${Math.round(fraction * 100)}%`;
  }

  async function scan(file, force = false) {
    if (!file) return;
    window.clearTimeout(state.pollTimer);
    state.lastFile = file;
    if (state.maxBytes && file.size > state.maxBytes) { showError(`${file.name} is ${mstFileSize(file.size)}. The maximum is ${mstFileSize(state.maxBytes)}.`); return; }
    if (file.size === 0) { showError(`${file.name} is empty, so there is nothing to scan.`); return; }
    show(scanProgress);
    setProgress('UPLOADING FILE', `Sending ${file.name} (${mstFileSize(file.size)}) to the MST server…`, 0);
    const form = new FormData();
    form.append('file', file);
    form.append('submitToVirusTotal', document.getElementById('submitToVirusTotal')?.checked ? '1' : '0');
    if (force) form.append('force', '1');
    try {
      const payload = await window.MSTApi.upload('/file-scanner', form, (fraction) => {
        if (fraction < 1) setProgress('UPLOADING FILE', `Sending ${file.name}… ${Math.round(fraction * 100)}%`, fraction);
        else setProgress('SCANNING FILE', 'Hashing, identifying the file type and running the antivirus engines and VirusTotal…', null);
      });
      showResult(payload.data.scan, payload.data.duplicate);
    } catch (error) {
      showError(mstApiErrorMessage(error, 'The scan could not be completed.'));
    } finally {
      if (fileInput) fileInput.value = '';
    }
  }

  function showError(message) {
    show(scanResult);
    document.getElementById('resultIcon').innerHTML = '<i class="fa-solid fa-circle-xmark"></i>';
    document.getElementById('resultTitle').textContent = 'SCAN NOT COMPLETED';
    document.getElementById('resultSubtitle').textContent = message;
    document.getElementById('resultReport').innerHTML = '';
    actions([['again', 'Scan another file', 'fa-file-circle-plus', 'btn-primary']]);
  }

  function showResult(scan, duplicate) {
    show(scanResult);
    const risk = mstRiskOf(scan);
    const pending = scan.scanState === 'Scanning' || scan.scanState === 'Pending';
    const icon = pending ? 'fa-spinner' : { High: 'fa-triangle-exclamation', Medium: 'fa-circle-exclamation', Safe: 'fa-check', Unknown: 'fa-circle-question', Failed: 'fa-circle-xmark' }[risk] || 'fa-circle-question';
    document.getElementById('resultIcon').innerHTML = `<i class="fa-solid ${icon}"></i>`;
    document.getElementById('resultTitle').textContent = duplicate ? 'ALREADY SCANNED' : pending ? 'WAITING FOR VIRUSTOTAL' : 'SCAN RESULT';
    document.getElementById('resultSubtitle').textContent = duplicate
      ? `The same file (same SHA-256) was scanned ${mstTimeAgo(scan.completedAt)} as ${mstScanCode(scan.id)}. This is that result.`
      : pending ? 'The file was uploaded to VirusTotal; this page updates automatically when its analysis is finished.' : `Completed ${mstFormatDate(scan.completedAt)}`;
    document.getElementById('resultReport').innerHTML = mstScanReportHtml(scan);
    const buttons = [['history', 'View in Scan History', 'fa-clock-rotate-left', 'btn-secondary'], ['report', 'Download report', 'fa-file-arrow-down', 'btn-secondary']];
    if (duplicate) buttons.unshift(['force', 'Scan again anyway', 'fa-rotate', 'btn-secondary']);
    buttons.push(['again', 'Scan another file', 'fa-file-circle-plus', 'btn-primary']);
    actions(buttons, scan);
    if (pending) state.pollTimer = window.setTimeout(() => refresh(scan.id), 10000);
  }

  async function refresh(id) {
    try {
      const { data } = await window.MSTApi.apiGet(`/scans/${id}`);
      showResult(data, false);
    } catch (error) {
      state.pollTimer = window.setTimeout(() => refresh(id), 15000);
    }
  }

  function actions(buttons, record) {
    const target = document.getElementById('resultActions');
    target.innerHTML = buttons.map(([action, label, icon, style]) => `<button class="${style}" data-action="${action}"><i class="fa-solid ${icon}"></i> ${mstEscape(label)}</button>`).join('');
    target.querySelectorAll('button').forEach((button) => button.addEventListener('click', () => {
      const action = button.dataset.action;
      if (action === 'again') { window.clearTimeout(state.pollTimer); show(dropZone); }
      if (action === 'force') scan(state.lastFile, true);
      if (action === 'history') window.location.href = `scan-history.html?scan=${encodeURIComponent(record.id)}`;
      if (action === 'report') window.MSTApi.download(`/scans/${record.id}/report`, `MST-${mstScanCode(record.id)}-report.txt`).catch((error) => showMSTToast(mstApiErrorMessage(error, 'Unable to download the report.')));
    }));
  }

  fileInput?.addEventListener('change', () => scan(fileInput.files?.[0]));
  if (dropZone) {
    ['dragenter', 'dragover'].forEach((type) => dropZone.addEventListener(type, (event) => { event.preventDefault(); dropZone.style.borderColor = 'rgba(0,217,255,0.7)'; }));
    ['dragleave', 'drop'].forEach((type) => dropZone.addEventListener(type, (event) => { event.preventDefault(); dropZone.style.borderColor = 'rgba(0,217,255,0.3)'; }));
    dropZone.addEventListener('drop', (event) => { const files = event.dataTransfer?.files; if (files?.length) scan(files[0]); });
  }
  loadCapabilities();
});
