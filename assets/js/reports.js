// Reports: security overview from the MySQL-backed summary (/api/reports). Charts are plain HTML (no chart library):
// summary cards, 14-day column charts (with a table view and hover details) and labelled bar lists. Refreshes itself.
const reportState = { data: null };
const reportEsc = (value) => mstEscape(String(value ?? ''));
const reportNumber = (value) => Number(value || 0).toLocaleString();
const reportPercent = (part, total) => (total ? Math.round((part / total) * 100) : 0);

function reportDay(date, long = false) {
  const day = new Date(`${date}T00:00:00`);
  return Number.isNaN(day.getTime()) ? date : day.toLocaleDateString('en-US', long ? { weekday: 'short', month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric' });
}

// A clean axis maximum: 1, 2, 5 x 10^n at or above the largest value (at least 4, so small counts stay readable).
function reportNiceMax(value) {
  if (value <= 4) return 4;
  const power = 10 ** Math.floor(Math.log10(value));
  return [1, 2, 2.5, 5, 10].map((step) => step * power).find((step) => step >= value);
}

function renderStats(report) {
  const values = [
    [report.filesScanned, `${reportNumber(report.safeScans)} safe · ${reportNumber(report.highScans)} high risk · ${reportNumber(report.mediumScans)} medium`, 'neutral'],
    [report.totalThreats, `${reportNumber(report.openThreats)} still open`, report.openThreats ? 'negative' : 'positive'],
    [report.resolvedThreats, `${reportPercent(report.resolvedThreats, report.totalThreats)}% of all threats`, 'positive'],
    [report.criticalThreats, report.openCriticalThreats ? `${reportNumber(report.openCriticalThreats)} need review` : 'None open', report.openCriticalThreats ? 'negative' : 'positive'],
    [report.onlineComputers, `${reportPercent(report.onlineComputers, report.totalComputers)}% of ${reportNumber(report.totalComputers)} computers`, 'positive'],
    [report.offlineComputers, `${reportPercent(report.offlineComputers, report.totalComputers)}% of ${reportNumber(report.totalComputers)} computers`, 'neutral']
  ];
  document.querySelectorAll('#reportStats .metric-card').forEach((card, index) => {
    const [value, meta, tone] = values[index];
    card.querySelector('.metric-value').textContent = reportNumber(value);
    const metaElement = card.querySelector('.metric-meta');
    metaElement.textContent = meta;
    metaElement.className = `metric-meta ${tone}`;
  });
}

// Column chart: one series, 14 days. Gridlines at clean values, the largest day labelled, details on hover/focus.
function renderColumns(containerId, tableId, days, valueOf, detailOf, colorClass, unit) {
  const container = document.getElementById(containerId);
  const values = days.map(valueOf);
  const max = reportNiceMax(Math.max(0, ...values));
  const ticks = [0, max / 2, max];
  const peak = values.indexOf(Math.max(...values));
  container.innerHTML = `
    <div class="column-axis">${ticks.slice().reverse().map((tick) => `<span>${reportNumber(tick)}</span>`).join('')}</div>
    <div class="column-plot">
      ${ticks.map((tick) => `<i class="column-grid" style="bottom:calc(1.4rem + (100% - 1.4rem) * ${tick / max})"></i>`).join('')}
      ${days.map((day, index) => `
        <button type="button" class="column-slot" data-index="${index}" aria-label="${reportEsc(`${reportDay(day.date, true)}: ${values[index]} ${unit}`)}">
          <span class="column-bar ${colorClass}${values[index] ? '' : ' empty'}" style="height:${values[index] ? Math.max(2, (values[index] / max) * 100) : 0}%">
            ${index === peak && values[index] > 0 ? `<b class="column-peak">${reportNumber(values[index])}</b>` : ''}
          </span>
          <small class="column-label">${index % 2 === (days.length - 1) % 2 ? reportEsc(reportDay(day.date)) : ''}</small>
        </button>`).join('')}
    </div>`;
  const tooltip = document.getElementById('chartTooltip');
  container.querySelectorAll('.column-slot').forEach((slot) => {
    const show = () => {
      const index = Number(slot.dataset.index);
      tooltip.innerHTML = `<strong>${reportEsc(reportDay(days[index].date, true))}</strong>${detailOf(days[index]).map(([label, value]) => `<span>${reportEsc(label)}<b>${reportNumber(value)}</b></span>`).join('')}`;
      tooltip.classList.remove('hidden');
      const box = slot.querySelector('.column-bar').getBoundingClientRect();
      const left = Math.min(window.innerWidth - tooltip.offsetWidth - 8, Math.max(8, box.left + box.width / 2 - tooltip.offsetWidth / 2));
      tooltip.style.left = `${left + window.scrollX}px`;
      tooltip.style.top = `${Math.max(8, box.top - tooltip.offsetHeight - 10) + window.scrollY}px`;
    };
    const hide = () => tooltip.classList.add('hidden');
    slot.addEventListener('mouseenter', show); slot.addEventListener('focus', show);
    slot.addEventListener('mouseleave', hide); slot.addEventListener('blur', hide);
  });
  const header = ['Day', ...detailOf(days[0]).map(([label]) => label)];
  document.getElementById(tableId).innerHTML = `<table class="data-table"><thead><tr>${header.map((cell) => `<th>${reportEsc(cell)}</th>`).join('')}</tr></thead>
    <tbody>${days.slice().reverse().map((day) => `<tr><td>${reportEsc(reportDay(day.date, true))}</td>${detailOf(day).map(([, value]) => `<td>${reportNumber(value)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  return values.reduce((sum, value) => sum + value, 0);
}

// Labelled horizontal bars: name, count and share are text; the bar only shows the size.
function renderBars(containerId, rows, total, emptyText) {
  const container = document.getElementById(containerId);
  if (!total) { container.innerHTML = `<p class="report-empty"><i class="fa-solid fa-circle-check"></i> ${reportEsc(emptyText)}</p>`; return; }
  container.innerHTML = rows.map(([label, value, colorClass, icon]) => `
    <div class="hbar-row">
      <div class="hbar-text"><span><i class="fa-solid ${icon}"></i> ${reportEsc(label)}</span><b>${reportNumber(value)} <small>${reportPercent(value, total)}%</small></b></div>
      <div class="hbar-track"><span class="hbar-fill ${colorClass}" style="width:${value ? Math.max(1.5, reportPercent(value, total)) : 0}%"></span></div>
    </div>`).join('');
}

function renderReport(report) {
  reportState.data = report;
  const generated = mstParseDate(report.generatedAt);
  document.getElementById('reportGenerated').textContent = `Generated ${generated ? mstFormatDate(report.generatedAt) : 'just now'} · updates by itself`;
  renderStats(report);
  const days = report.trend || [];
  const detections = (day) => day.high + day.medium + day.threats;
  document.getElementById('detectionTotal').textContent = reportNumber(renderColumns('detectionChart', 'detectionTable', days, detections,
    (day) => [['High risk scans', day.high], ['Medium risk scans', day.medium], ['Threat records', day.threats], ['Total', detections(day)]], 'red', 'detections'));
  document.getElementById('scanTotal').textContent = reportNumber(renderColumns('scanChart', 'scanTable', days, (day) => day.scans,
    (day) => [['Files scanned', day.scans]], 'cyan', 'files scanned'));

  const severityTotal = report.criticalThreats + report.highThreats + report.mediumThreats + report.lowThreats;
  document.getElementById('severityTotal').textContent = reportNumber(severityTotal);
  renderBars('severityBars', [['Critical', report.criticalThreats, 'red', 'fa-circle-exclamation'], ['High', report.highThreats, 'orange', 'fa-triangle-exclamation'],
    ['Medium', report.mediumThreats, 'yellow', 'fa-circle-half-stroke'], ['Low', report.lowThreats, 'green', 'fa-circle-info']], severityTotal, 'No threats recorded.');

  const resultTotal = report.safeScans + report.mediumScans + report.highScans + report.unknownScans + report.failedScans;
  document.getElementById('resultTotal').textContent = reportNumber(resultTotal);
  renderBars('resultBars', [['Safe', report.safeScans, 'green', 'fa-shield-halved'], ['Medium risk', report.mediumScans, 'yellow', 'fa-circle-half-stroke'],
    ['High risk', report.highScans, 'red', 'fa-triangle-exclamation'], ['Unknown', report.unknownScans, 'gray', 'fa-circle-question'], ['Scan failed', report.failedScans, 'gray', 'fa-circle-xmark']],
    resultTotal, 'No completed scans yet.');

  document.getElementById('computerTotal').textContent = reportNumber(report.totalComputers);
  renderBars('computerBars', [['Online', report.onlineComputers, 'green', 'fa-circle-check'], ['Offline', report.offlineComputers, 'gray', 'fa-power-off'],
    ['Warning', report.warningComputers, 'yellow', 'fa-triangle-exclamation'], ['Threat', report.threatComputers, 'red', 'fa-bug']], report.totalComputers, 'No computers registered.');

  const mini = [['fa-plug-circle-check', 'Agents connected', report.agentConnectedComputers, `of ${reportNumber(report.totalComputers)} computers`],
    ['fa-folder-open', 'File activity recorded', report.fileEvents, 'new, edited, renamed and deleted files'],
    ['fa-clock', 'File activity, last 24 hours', report.fileEventsLastDay, 'reported by the agents'],
    ['fa-box-archive', 'Files in quarantine', report.quarantinedFiles, 'isolated on lab PCs'],
    ['fa-spinner', 'Scans in progress', report.scansInProgress, 'waiting for a result']];
  document.getElementById('monitoringStats').innerHTML = mini.map(([icon, label, value, note]) => `
    <div class="report-mini"><i class="fa-solid ${icon}"></i><div><span>${reportEsc(label)}</span><strong>${reportNumber(value)}</strong><small>${reportEsc(note)}</small></div></div>`).join('');
}

async function loadReport({ quiet = false } = {}) {
  try {
    const { data, demo } = await window.MSTApi.apiGetOrDemo('/reports', null);
    if (demo || !data) { if (!quiet) showMSTToast('API unavailable — the report cannot be shown right now'); return false; }
    renderReport(data);
    return true;
  } catch (error) {
    if (!quiet) showMSTToast(mstApiErrorMessage(error, 'Unable to load reports from the database.'));
    return false;
  }
}

function exportReportCsv() {
  const report = reportState.data;
  if (!report) return;
  const cell = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
  const rows = [['MST Security Report'], ['Generated', report.generatedAt], [],
    ['Summary', 'Value'],
    ['Files scanned', report.filesScanned], ['Safe', report.safeScans], ['Medium risk', report.mediumScans], ['High risk', report.highScans], ['Unknown', report.unknownScans], ['Scan failed', report.failedScans],
    ['Total threats', report.totalThreats], ['Open threats', report.openThreats], ['Resolved threats', report.resolvedThreats], ['Critical', report.criticalThreats], ['High', report.highThreats], ['Medium', report.mediumThreats], ['Low', report.lowThreats],
    ['Computers', report.totalComputers], ['Online', report.onlineComputers], ['Offline', report.offlineComputers], ['Warning', report.warningComputers], ['Threat', report.threatComputers], ['Agents connected', report.agentConnectedComputers],
    ['File activity recorded', report.fileEvents], ['File activity, last 24 hours', report.fileEventsLastDay], ['Files in quarantine', report.quarantinedFiles], [],
    ['Day', 'Files scanned', 'High risk scans', 'Medium risk scans', 'Threat records'],
    ...(report.trend || []).map((day) => [day.date, day.scans, day.high, day.medium, day.threats])];
  const blob = new Blob([`﻿${rows.map((row) => row.map(cell).join(',')).join('\r\n')}\r\n`], { type: 'text/csv;charset=utf-8' });
  const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `MST-security-report-${new Date().toISOString().slice(0, 10)}.csv` });
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  showMSTToast('Report exported');
}

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('reportStats') || !window.MSTApi) return;
  document.getElementById('reportExport').addEventListener('click', exportReportCsv);
  document.getElementById('reportPrint').addEventListener('click', () => window.print());
  // Updates by itself within about a second (assets/js/live.js).
  loadReport().then(() => window.MSTLive?.start('reports', () => loadReport({ quiet: true })));
});
