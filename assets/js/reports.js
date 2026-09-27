// Reports: fills the existing report cards and charts from the MySQL-backed summary (/api/reports).
// The static values in reports.html remain as the demo fallback when the API cannot be reached.
document.addEventListener('DOMContentLoaded', async () => {
  const cards = document.querySelectorAll('.page-content .stats-grid .metric-card');
  if (!cards.length || !window.MSTApi) return;
  let report;
  try {
    const { data, demo } = await window.MSTApi.apiGetOrDemo('/reports', null);
    if (demo) { showMSTToast('API unavailable — showing demo report data'); return; }
    report = data;
  } catch (error) {
    showMSTToast(mstApiErrorMessage(error, 'Unable to load reports from the database.'));
    return;
  }
  const percent = (part, total) => (total ? Math.round((part / total) * 100) : 0);
  const values = [
    [report.totalScans, `${report.safeScans} safe · ${report.threatScans} threat`],
    [report.totalThreats, `${report.openThreats} open`],
    [report.resolvedThreats, `${percent(report.resolvedThreats, report.totalThreats)}% of all threats`],
    [report.criticalThreats, report.openCriticalThreats ? 'Needs review' : 'None open'],
    [report.onlineComputers, `${percent(report.onlineComputers, report.totalComputers)}% of computers`],
    [report.offlineComputers, `${report.totalComputers} computers total`]
  ];
  cards.forEach((card, index) => {
    if (!values[index]) return;
    const value = card.querySelector('.metric-value');
    const meta = card.querySelector('.metric-meta');
    if (value) value.textContent = Number(values[index][0]).toLocaleString();
    if (meta) meta.textContent = values[index][1];
  });

  const donutTotal = document.querySelector('.donut-chart span');
  if (donutTotal) donutTotal.textContent = report.totalThreats;
  const legend = document.querySelectorAll('.legend-list > div');
  [['Critical', report.criticalThreats], ['High', report.highThreats], ['Medium', report.mediumThreats], ['Low', report.lowThreats]].forEach(([label, total], index) => {
    const dot = legend[index]?.querySelector('.dot');
    if (legend[index]) legend[index].innerHTML = `${dot ? dot.outerHTML : ''} ${label} ${Number(total)}`;
  });

  const ringCenter = document.querySelector('.status-ring .ring-center');
  if (ringCenter) ringCenter.textContent = report.totalComputers;
  const onlinePercent = percent(report.onlineComputers, report.totalComputers);
  document.querySelector('.status-ring .ring-segment.green')?.style.setProperty('--pct', `${onlinePercent}%`);
  document.querySelector('.status-ring .ring-segment.gray')?.style.setProperty('--pct', `${100 - onlinePercent}%`);
});
