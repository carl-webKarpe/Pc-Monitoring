// Activity Logs: renders the MySQL-backed audit trail (/api/activity) into the existing table.
const activityDemoRows = null; // The static rows in activity-logs.html remain the demo fallback.
let activityRows = [];

const activityLabels = {
  LOGIN: ['Logged in', 'Authentication'], LOGIN_FAILED: ['Failed login attempt', 'Authentication'], LOGOUT: ['Logged out', 'Authentication'],
  USER_CREATED: ['Created user', 'User Management'], USER_UPDATED: ['Updated user', 'User Management'], USER_DELETED: ['Deleted user', 'User Management'],
  ADMIN_CREATED: ['Added administrator', 'Access Control'], ADMIN_UPDATED: ['Updated administrator', 'Access Control'], ADMIN_DELETED: ['Removed administrator', 'Access Control'],
  PERMISSIONS_UPDATED: ['Changed permissions', 'Access Control'], AGENT_REGISTERED: ['Registered monitoring agent', 'Monitoring'], AGENT_TOKEN_ROTATED: ['Issued new agent token', 'Monitoring'], THREAT_STATUS_UPDATED: ['Changed threat status', 'Threat Management'], SETTINGS_UPDATED: ['Changed settings', 'Settings']
};

const activityUser = (row) => row.username || (String(row.action).startsWith('AGENT_') ? 'System' : 'Unknown account');

function activityDay(value) {
  const date = mstParseDate(value);
  if (!date) return '';
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const day = new Date(date); day.setHours(0, 0, 0, 0);
  const diff = Math.round((today - day) / 86400000);
  return diff === 0 ? 'Today' : diff === 1 ? 'Yesterday' : '';
}

function renderActivity(filters) {
  const body = document.querySelector('.log-table tbody');
  if (!body) return;
  const [dateFilter, userFilter, actionFilter] = filters.map((select) => (select && select.selectedIndex > 0 ? select.value : ''));
  const rows = activityRows.filter((row) => (!dateFilter || activityDay(row.createdAt) === dateFilter) && (!userFilter || activityUser(row) === userFilter) && (!actionFilter || (activityLabels[row.action]?.[0] || row.action) === actionFilter));
  const esc = mstEscape;
  body.innerHTML = rows.length ? rows.map((row) => {
    const [label, category] = activityLabels[row.action] || [row.action, 'System'];
    const date = mstParseDate(row.createdAt);
    const time = date ? `${activityDay(row.createdAt) || date.toLocaleDateString('en-US', { month: 'short', day: '2-digit' })} ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}` : '—';
    return `<tr><td>${esc(time)}</td><td>${esc(activityUser(row))}</td><td>${esc(row.description || label)}</td><td>${esc(category)}</td></tr>`;
  }).join('') : '<tr><td colspan="4">No activity recorded for the selected filters.</td></tr>';
}

function fillActivityFilter(select, placeholder, values) {
  if (!select) return;
  select.innerHTML = `<option>${mstEscape(placeholder)}</option>${values.map((value) => `<option>${mstEscape(value)}</option>`).join('')}`;
}

document.addEventListener('DOMContentLoaded', async () => {
  const table = document.querySelector('.log-table');
  if (!table || !window.MSTApi) return;
  const filters = [...document.querySelectorAll('.table-filter')].slice(0, 3);
  try {
    const { data, demo } = await window.MSTApi.apiGetOrDemo('/activity?limit=200', activityDemoRows);
    if (demo) { showMSTToast('API unavailable — showing demo activity'); return; }
    activityRows = data;
  } catch (error) {
    showMSTToast(mstApiErrorMessage(error, 'Unable to load activity logs from the database.'));
    return;
  }
  fillActivityFilter(filters[0], 'Date', ['Today', 'Yesterday']);
  fillActivityFilter(filters[1], 'User', [...new Set(activityRows.map(activityUser))].sort());
  fillActivityFilter(filters[2], 'Action', [...new Set(activityRows.map((row) => activityLabels[row.action]?.[0] || row.action))].sort());
  filters.forEach((select) => select?.addEventListener('change', () => renderActivity(filters)));
  renderActivity(filters);
});
