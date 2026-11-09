// Activity Logs: renders the MySQL-backed audit trail (/api/activity) into the existing table.
const activityDemoRows = null; // The static rows in activity-logs.html remain the demo fallback.
let activityRows = [];

const activityLabels = {
  LOGIN: ['Logged in', 'Authentication'], LOGIN_FAILED: ['Failed login attempt', 'Authentication'], LOGOUT: ['Logged out', 'Authentication'],
  USER_CREATED: ['Created user', 'User Management'], USER_UPDATED: ['Updated user', 'User Management'], USER_DELETED: ['Deleted user', 'User Management'],
  ADMIN_CREATED: ['Added administrator', 'Access Control'], ADMIN_UPDATED: ['Updated administrator', 'Access Control'], ADMIN_DELETED: ['Removed administrator', 'Access Control'],
  PERMISSIONS_UPDATED: ['Changed permissions', 'Access Control'], AGENT_REGISTERED: ['Registered monitoring agent', 'Monitoring'], AGENT_TOKEN_ROTATED: ['Issued new agent token', 'Monitoring'], THREAT_STATUS_UPDATED: ['Changed threat status', 'Threat Management'], SETTINGS_UPDATED: ['Changed settings', 'Settings'],
  LOGIN_LOCKED: ['Login blocked (too many attempts)', 'Authentication'], SESSION_EXPIRED: ['Session expired', 'Authentication'], ACCESS_DENIED: ['Access denied', 'Access Control'],
  PASSWORD_RESET: ['Password reset', 'User Management'], LOGIN_APPROVAL_REQUESTED: ['Phone sign-in requested', 'Authentication'], LOGIN_APPROVED_ON_PHONE: ['Sign-in approved on phone', 'Authentication'],
  PHONE_PAIRING_STARTED: ['Phone pairing started', 'Authentication'], PHONE_PAIRED: ['Phone paired', 'Authentication'], PHONE_REMOVED: ['Phone removed', 'Authentication'], PHONE_RESET: ['Phone sign-in reset', 'Authentication'],
  AGENT_ENROLLED: ['PC added with enrollment key', 'Monitoring'], AGENT_REENROLLED: ['PC enrolled again', 'Monitoring'], AGENT_REVOKED: ['Agent access revoked', 'Monitoring'], ENROLLMENT_FAILED: ['Enrollment refused', 'Monitoring'],
  ENROLLMENT_KEY_CREATED: ['Created enrollment key', 'Monitoring'], ENROLLMENT_KEY_REVOKED: ['Revoked enrollment key', 'Monitoring'], COMPUTER_RENAMED: ['Renamed computer', 'Monitoring'], COMPUTER_DELETED: ['Deleted computer', 'Monitoring'],
  FILE_UPDATED: ['Classified / reviewed file', 'File Activity'], SCAN_REQUESTED: ['Scan requested', 'File Scanner'], SCAN_INVESTIGATED: ['Scan result investigated', 'File Scanner'], FILE_UPLOAD_SCANNED: ['Scanned uploaded file', 'File Scanner'], UPLOAD_DELETED: ['Deleted uploaded file', 'File Scanner'],
  QUARANTINE_REQUESTED: ['Quarantine requested', 'Quarantine'], FILE_QUARANTINED: ['File quarantined', 'Quarantine'], QUARANTINE_FAILED: ['Quarantine failed', 'Quarantine'], QUARANTINE_RELEASE_REQUESTED: ['Release requested', 'Quarantine'], FILE_RELEASED: ['File released', 'Quarantine'],
  QUARANTINE_DELETE_REQUESTED: ['Delete from quarantine requested', 'Quarantine'], QUARANTINE_DELETED: ['Deleted from quarantine', 'Quarantine'], FILE_DELETE_REQUESTED: ['File delete requested', 'Quarantine'], REPORT_EXPORTED: ['Exported report', 'Reports']
};
// Any other code (e.g. a new one) is shown as words: "SOME_NEW_ACTION" -> "Some new action".
const activityLabel = (action) => activityLabels[action] || [String(action || 'Unknown').toLowerCase().replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()), 'System'];

// No account: a failed sign-in with an unknown name, or something MST/the server console did by itself.
const activityUser = (row) => row.username || (['LOGIN_FAILED', 'LOGIN_LOCKED'].includes(row.action) ? 'Unknown account' : 'System');

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
  const rows = activityRows.filter((row) => (!dateFilter || activityDay(row.createdAt) === dateFilter) && (!userFilter || activityUser(row) === userFilter) && (!actionFilter || activityLabel(row.action)[0] === actionFilter));
  const esc = mstEscape;
  body.innerHTML = rows.length ? rows.map((row) => {
    const [label, category] = activityLabel(row.action);
    const date = mstParseDate(row.createdAt);
    const time = date ? `${activityDay(row.createdAt) || date.toLocaleDateString('en-US', { month: 'short', day: '2-digit' })} ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}` : '—';
    return `<tr><td>${esc(time)}</td><td>${esc(activityUser(row))}</td><td>${esc(row.description || label)}</td><td>${esc(category)}</td></tr>`;
  }).join('') : '<tr><td colspan="4">No activity recorded for the selected filters.</td></tr>';
}

// Refills a filter's choices and keeps the one the user picked (when it is still there).
function fillActivityFilter(select, placeholder, values) {
  if (!select) return;
  const picked = select.selectedIndex > 0 ? select.value : '';
  select.innerHTML = `<option>${mstEscape(placeholder)}</option>${values.map((value) => `<option>${mstEscape(value)}</option>`).join('')}`;
  if (picked && values.includes(picked)) select.value = picked;
  select.classList.toggle('is-active', select.selectedIndex > 0);
}

async function loadActivity(filters, { live = false } = {}) {
  try {
    const { data, demo } = await window.MSTApi.apiGetOrDemo('/activity?limit=200', activityDemoRows);
    if (demo) { if (!live) showMSTToast('API unavailable — showing demo activity'); return false; }
    activityRows = data;
  } catch (error) {
    if (!live) showMSTToast(mstApiErrorMessage(error, 'Unable to load activity logs from the database.'));
    return false;
  }
  fillActivityFilter(filters[0], 'Date', ['Today', 'Yesterday']);
  fillActivityFilter(filters[1], 'User', [...new Set(activityRows.map(activityUser))].sort());
  fillActivityFilter(filters[2], 'Action', [...new Set(activityRows.map((row) => activityLabel(row.action)[0]))].sort());
  renderActivity(filters);
  return true;
}

document.addEventListener('DOMContentLoaded', async () => {
  const table = document.querySelector('.log-table');
  if (!table || !window.MSTApi) return;
  const filters = [...document.querySelectorAll('.table-filter')].slice(0, 3);
  filters.forEach((select) => select?.addEventListener('change', () => { select.classList.toggle('is-active', select.selectedIndex > 0); renderActivity(filters); }));
  // New log entries appear by themselves within about a second (assets/js/live.js).
  await loadActivity(filters);
  window.MSTLive?.start('activity', () => loadActivity(filters, { live: true }));
});
