// Demo records, only used when the MST API cannot be reached (see MSTApi.apiGetOrDemo).
const managementUsers = [
  { id: 'USR-001', name: 'Juan Dela Cruz', email: 'juan@example.com', mobile: '09XX XXX XXXX', username: 'juandc', role: 'Tenant', status: 'Active', registered: 'Sep 10, 2026', date: 'recent', lastActive: '2 minutes ago' },
  { id: 'USR-002', name: 'Maya Santos', email: 'maya@example.com', mobile: '09XX XXX XXXX', username: 'mayas', role: 'Tenant', status: 'Active', registered: 'Aug 28, 2026', date: 'recent', lastActive: '18 minutes ago' },
  { id: 'USR-003', name: 'Rafael Lim', email: 'rafael@example.com', mobile: '09XX XXX XXXX', username: 'rafaell', role: 'Tenant', status: 'Inactive', registered: 'Jul 04, 2026', date: 'old', lastActive: '4 days ago' },
  { id: 'USR-004', name: 'Nina Reyes', email: 'nina@example.com', mobile: '09XX XXX XXXX', username: 'ninareyes', role: 'Tenant', status: 'Suspended', registered: 'Jun 19, 2026', date: 'old', lastActive: '12 days ago' }
];

const managementAdmins = [
  { id: 'ADM-001', name: 'System Administrator', email: 'admin@mst.local', mobile: '09XX XXX XXXX', username: 'superadmin', role: 'Super Admin', status: 'Active', created: 'Aug 15, 2026', lastActive: '2 minutes ago', lastLogin: 'Today, 10:42 PM', primary: true },
  { id: 'ADM-002', name: 'Maria Santos', email: 'maria@mst.local', mobile: '09XX XXX XXXX', username: 'maria.santos', role: 'Admin', status: 'Active', created: 'Aug 20, 2026', lastActive: '15 minutes ago', lastLogin: 'Today, 10:27 PM' },
  { id: 'ADM-003', name: 'John Flores', email: 'john@mst.local', mobile: '09XX XXX XXXX', username: 'john.flores', role: 'Admin', status: 'Inactive', created: 'Aug 25, 2026', lastActive: '3 days ago', lastLogin: 'Sep 12, 2026' }
];

const managementState = { pending: null, demo: { users: false, admins: false }, rows: { users: [], admins: [] } };
const esc = mstEscape;
const statusClass = (status) => String(status).toLowerCase();
const managementCode = (prefix, id) => `${prefix}-${String(id).padStart(3, '0')}`;
const managementDate = (value) => { const date = mstParseDate(value); return date ? date.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }) : '—'; };

// Map MySQL-backed /api/users and /api/admins records onto the fields the existing tables and modals render.
function fromApiAccount(account, prefix) {
  const created = mstParseDate(account.createdAt);
  return {
    dbId: account.id, id: managementCode(prefix, account.id), name: [account.firstName, account.middleName, account.lastName].filter(Boolean).join(' '),
    firstName: account.firstName, middleName: account.middleName || '', lastName: account.lastName, email: account.email, mobile: '—', username: account.username,
    role: account.role, status: account.status, registered: managementDate(account.createdAt), created: managementDate(account.createdAt),
    date: created && Date.now() - created.getTime() < 30 * 86400000 ? 'recent' : 'old',
    lastActive: account.lastLogin ? mstTimeAgo(account.lastLogin) : 'Never', lastLogin: account.lastLogin ? mstFormatDate(account.lastLogin) : 'Never', primary: account.id === 1
  };
}

async function loadAccounts(type) {
  const { data, demo } = await window.MSTApi.apiGetOrDemo(`/${type}`, type === 'users' ? managementUsers : managementAdmins);
  managementState.demo[type] = demo;
  managementState.rows[type] = demo ? data : data.map((account) => fromApiAccount(account, type === 'users' ? 'USR' : 'ADM'));
  return managementState.rows[type];
}

async function fetchUsers() { return loadAccounts('users'); }
async function createUser(data) { return (await window.MSTApi.apiPost('/users', data)).data; }
async function updateUser(id, data) { return (await window.MSTApi.apiPut(`/users/${id}`, data)).data; }
async function fetchAdmins() { return loadAccounts('admins'); }
async function createAdmin(data) { return (await window.MSTApi.apiPost('/admins', data)).data; }
async function updateAdmin(id, data) { return (await window.MSTApi.apiPut(`/admins/${id}`, data)).data; }
async function fetchPermissions() { return (await window.MSTApi.apiGet('/permissions')).data; }
async function fetchSettings() { return (await window.MSTApi.apiGet('/settings')).data; }
async function updateSettings(data) { return (await window.MSTApi.apiPut('/settings', data)).data; }

function showManagementToast(message) { const toast = document.getElementById('managementToast'); if (!toast) { showMSTToast(message); return; } toast.querySelector('span').textContent = message; toast.classList.add('show'); window.setTimeout(() => toast.classList.remove('show'), 2800); }
function openManagementModal(id) { document.getElementById(id)?.classList.remove('hidden'); }
function closeManagementModals() { document.querySelectorAll('#users-page ~ .modal, #admins-page ~ .modal, .management-page + .modal, .modal').forEach((modal) => modal.classList.add('hidden')); }
function userDetails(user, demo) { const activity = demo ? '<p>Logged in <small>Today, 10:42 PM</small></p><p>Viewed Computer Monitoring <small>Today, 10:31 PM</small></p><p>Viewed Threat Report <small>Yesterday</small></p><p>Logged out <small>Yesterday</small></p>' : `<p>Last login <small>${esc(user.lastActive)}</small></p>`; return `<div class="management-detail-grid"><div><span>Full Name</span><strong>${esc(user.name)}</strong></div><div><span>User ID</span><strong>${esc(user.id)}</strong></div><div><span>Email</span><strong>${esc(user.email)}</strong></div><div><span>Mobile</span><strong>${esc(user.mobile)}</strong></div><div><span>Role</span><strong>${esc(user.role)}</strong></div><div><span>Status</span><strong class="management-status ${esc(statusClass(user.status))}">● ${esc(user.status)}</strong></div><div><span>Registered</span><strong>${esc(user.registered)}</strong></div><div><span>Last Active</span><strong>${esc(user.lastActive)}</strong></div></div><h4 class="detail-subheading">RECENT ACTIVITY</h4><div class="management-activity">${activity}</div>`; }
function adminDetails(admin, demo) { const activity = demo ? '<p>Viewed Computer Monitoring <small>Today, 10:31 PM</small></p><p>Reviewed Threat <small>Today, 10:20 PM</small></p><p>Viewed Scan History <small>Today, 9:45 PM</small></p><p>Updated System Settings <small>Yesterday</small></p>' : `<p>Last login <small>${esc(admin.lastLogin)}</small></p><p>Full audit trail <small><a class="text-link" href="../activity-logs.html">Activity Logs</a></small></p>`; return `<div class="management-detail-grid"><div><span>Admin Name</span><strong>${esc(admin.name)}</strong></div><div><span>Admin ID</span><strong>${esc(admin.id)}</strong></div><div><span>Email</span><strong>${esc(admin.email)}</strong></div><div><span>Role</span><strong>${esc(admin.role)}</strong></div><div><span>Status</span><strong class="management-status ${esc(statusClass(admin.status))}">● ${esc(admin.status)}</strong></div><div><span>Created Date</span><strong>${esc(admin.created)}</strong></div><div><span>Last Active</span><strong>${esc(admin.lastActive)}</strong></div><div><span>Last Login</span><strong>${esc(admin.lastLogin)}</strong></div></div><h4 class="detail-subheading">RECENT ADMIN ACTIVITY</h4><div class="management-activity">${activity}</div>`; }

function renderUsers() { const users = managementState.rows.users; const query = document.getElementById('userSearch')?.value.toLowerCase() || ''; const status = document.getElementById('userStatusFilter')?.value || 'all'; const role = document.getElementById('userRoleFilter')?.value || 'all'; const date = document.getElementById('userDateFilter')?.value || 'all'; const rows = users.filter((user) => `${user.name} ${user.username} ${user.email} ${user.id}`.toLowerCase().includes(query) && (status === 'all' || user.status === status) && (role === 'all' || user.role === role) && (date === 'all' || user.date === date)); const body = document.getElementById('usersTableBody'); if (!body) return; body.innerHTML = rows.map((user) => `<tr><td><strong>${esc(user.name)}</strong><small class="table-subtext">${esc(user.username)}</small></td><td>${esc(user.id)}</td><td>${esc(user.email)}</td><td>${esc(user.role)}</td><td><span class="management-status ${esc(statusClass(user.status))}">● ${esc(user.status.toUpperCase())}</span></td><td>${esc(user.registered)}</td><td>${esc(user.lastActive)}</td><td><button class="link-button view-user" data-id="${esc(user.id)}">View</button><button class="link-button edit-user" data-id="${esc(user.id)}">Edit</button><button class="link-button danger deactivate-user" data-id="${esc(user.id)}">Deactivate</button></td></tr>`).join(''); document.getElementById('usersEmpty')?.classList.toggle('hidden', rows.length > 0); document.getElementById('userCount').textContent = `Showing ${rows.length} of ${users.length} users${managementState.demo.users ? ' (demo data)' : ''}`; body.querySelectorAll('.view-user').forEach((button) => button.addEventListener('click', () => { const user = users.find((item) => item.id === button.dataset.id); document.getElementById('userDetailsTitle').textContent = user.name; document.getElementById('userDetailsContent').innerHTML = userDetails(user, managementState.demo.users); openManagementModal('userDetailsModal'); })); body.querySelectorAll('.edit-user').forEach((button) => button.addEventListener('click', () => fillAccountForm('user', users.find((item) => item.id === button.dataset.id)))); body.querySelectorAll('.deactivate-user').forEach((button) => button.addEventListener('click', () => confirmStatus('user', button.dataset.id))); }
function renderAdmins() { const admins = managementState.rows.admins; const query = document.getElementById('adminSearch')?.value.toLowerCase() || ''; const status = document.getElementById('adminStatusFilter')?.value || 'all'; const role = document.getElementById('adminRoleFilter')?.value || 'all'; const rows = admins.filter((admin) => `${admin.name} ${admin.username} ${admin.email} ${admin.id}`.toLowerCase().includes(query) && (status === 'all' || admin.status === status) && (role === 'all' || admin.role === role)); const body = document.getElementById('adminsTableBody'); if (!body) return; body.innerHTML = rows.map((admin) => `<tr><td><strong>${esc(admin.name)}</strong><small class="table-subtext">${esc(admin.username)}</small></td><td>${esc(admin.id)}</td><td>${esc(admin.email)}</td><td>${esc(admin.role)}</td><td><span class="management-status ${esc(statusClass(admin.status))}">● ${esc(admin.status.toUpperCase())}</span></td><td>${esc(admin.lastActive)}</td><td>${esc(admin.created)}</td><td><button class="link-button view-admin" data-id="${esc(admin.id)}">View</button><button class="link-button edit-admin" data-id="${esc(admin.id)}">Edit</button><button class="link-button danger deactivate-admin" data-id="${esc(admin.id)}">Deactivate</button></td></tr>`).join(''); document.getElementById('adminsEmpty')?.classList.toggle('hidden', rows.length > 0); document.getElementById('adminCount').textContent = `Showing ${rows.length} of ${admins.length} administrators${managementState.demo.admins ? ' (demo data)' : ''}`; body.querySelectorAll('.view-admin').forEach((button) => button.addEventListener('click', () => { const admin = admins.find((item) => item.id === button.dataset.id); document.getElementById('adminDetailsTitle').textContent = admin.name; document.getElementById('adminDetailsContent').innerHTML = adminDetails(admin, managementState.demo.admins); openManagementModal('adminDetailsModal'); })); body.querySelectorAll('.edit-admin').forEach((button) => button.addEventListener('click', () => fillAccountForm('admin', admins.find((item) => item.id === button.dataset.id)))); body.querySelectorAll('.deactivate-admin').forEach((button) => button.addEventListener('click', () => confirmStatus('admin', button.dataset.id))); }

function fillAccountForm(type, account = null) {
  const form = document.getElementById(`${type}Form`);
  if (!form) return;
  const demo = managementState.demo[`${type}s`];
  form.reset();
  document.getElementById(`${type}FormError`).textContent = '';
  form.id.value = account?.id || '';
  form.password.required = !account;
  form.confirmPassword.required = !account;
  // The users table has no mobile column yet, so the field is optional (and not saved) when using the database.
  if (form.mobile) form.mobile.required = demo;
  document.getElementById(`${type}ModalTitle`).textContent = account ? `Edit ${type === 'user' ? 'User' : 'Admin'}` : `Add ${type === 'user' ? 'User' : 'Admin'}`;
  if (account) {
    const values = demo ? { firstName: account.name.split(' ')[0], lastName: account.name.split(' ').slice(-1)[0], email: account.email, mobile: account.mobile, username: account.username, status: account.status } : { firstName: account.firstName, middleName: account.middleName, lastName: account.lastName, email: account.email, username: account.username, status: account.status };
    Object.entries(values).forEach(([key, value]) => { if (form[key]) form[key].value = value; });
  }
  openManagementModal(`${type}ManagementModal`);
}

function formData(form) { return Object.fromEntries(new FormData(form).entries()); }
function validateManagementForm(data, collection, editingId) { if (data.password && data.password !== data.confirmPassword) return 'Passwords do not match.'; if (data.password && data.password.length < 8) return 'Password must be at least 8 characters.'; if (collection.some((item) => item.username === data.username && item.id !== editingId)) return 'This username is already in use.'; if (collection.some((item) => item.email === data.email && item.id !== editingId)) return 'This email is already in use.'; return ''; }
function confirmStatus(type, id) { const collection = managementState.rows[`${type}s`]; const item = collection.find((entry) => entry.id === id); if (!item) return; if (item.primary) { showManagementToast('Primary Super Admin cannot be removed.'); return; } managementState.pending = { type, id }; document.getElementById('confirmMessage').textContent = `Are you sure you want to deactivate ${item.name}?`; openManagementModal('confirmModal'); }

function apiFormMessage(error) {
  const fieldErrors = error.payload?.errors ? Object.values(error.payload.errors).join(' ') : '';
  return error.status === 422 && fieldErrors ? fieldErrors : mstApiErrorMessage(error, 'Unable to save changes.');
}

async function saveAccount(type, form) {
  const collectionName = `${type}s`;
  const collection = managementState.rows[collectionName];
  const data = formData(form);
  const errorNode = document.getElementById(`${type}FormError`);
  const error = validateManagementForm(data, collection, data.id);
  errorNode.textContent = error;
  if (error) return;
  const existing = collection.find((item) => item.id === data.id);
  if (managementState.demo[collectionName]) {
    // Demo mode (API offline): keep the previous in-browser behaviour.
    const name = `${data.firstName} ${data.middleName ? `${data.middleName} ` : ''}${data.lastName}`;
    if (existing) Object.assign(existing, { name, email: data.email, mobile: data.mobile, username: data.username, status: data.status });
    else if (type === 'user') collection.push({ id: managementCode('USR', collection.length + 1), name, email: data.email, mobile: data.mobile, username: data.username, role: 'Tenant', status: data.status, registered: 'Today', date: 'recent', lastActive: 'Never' });
    else collection.push({ id: managementCode('ADM', collection.length + 1), name, email: data.email, mobile: data.mobile, username: data.username, role: 'Admin', status: data.status, created: 'Today', lastActive: 'Never', lastLogin: 'Never' });
  } else {
    const payload = { firstName: data.firstName, middleName: data.middleName, lastName: data.lastName, email: data.email, username: data.username, status: data.status };
    if (data.password) payload.password = data.password;
    const submit = form.querySelector('[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      if (existing) await (type === 'user' ? updateUser : updateAdmin)(existing.dbId, payload);
      else await (type === 'user' ? createUser : createAdmin)(payload);
      await loadAccounts(collectionName);
    } catch (requestError) {
      errorNode.textContent = apiFormMessage(requestError);
      return;
    } finally {
      if (submit) submit.disabled = false;
    }
  }
  closeManagementModals();
  type === 'user' ? renderUsers() : renderAdmins();
  showManagementToast(type === 'user' ? 'User saved successfully' : 'Administrator saved successfully');
}

async function deactivatePending() {
  const pending = managementState.pending;
  if (!pending) return;
  const collectionName = `${pending.type}s`;
  const item = managementState.rows[collectionName].find((entry) => entry.id === pending.id);
  if (item && managementState.demo[collectionName]) item.status = 'Inactive';
  else if (item) {
    try {
      await (pending.type === 'user' ? updateUser : updateAdmin)(item.dbId, { status: 'Inactive' });
      await loadAccounts(collectionName);
    } catch (error) {
      closeManagementModals();
      showManagementToast(mstApiErrorMessage(error, 'Unable to update the account status.'));
      return;
    }
  }
  closeManagementModals();
  pending.type === 'user' ? renderUsers() : renderAdmins();
  showManagementToast('Status updated successfully');
}

const permissionModules = [['dashboard', 'Dashboard'], ['computer_monitoring', 'Computer Monitoring'], ['network', 'Network'], ['threats', 'Threats'], ['file_scanner', 'File Scanner'], ['scan_history', 'Scan History'], ['reports', 'Reports'], ['activity_logs', 'Activity Logs'], ['user_management', 'User Management'], ['admin_management', 'Admin Management'], ['permissions', 'Permissions'], ['settings', 'Settings']];

async function renderPermissions() {
  const body = document.querySelector('#permissions-page .permission-table tbody');
  if (!body) return;
  let matrix;
  try {
    const { data, demo } = await window.MSTApi.apiGetOrDemo('/permissions', null);
    if (demo) return; // Keep the static matrix in the page when the API is offline.
    matrix = data;
  } catch (error) {
    showManagementToast(mstApiErrorMessage(error, 'Unable to load permissions from the database.'));
    return;
  }
  const badge = (allowed) => (allowed ? '<span class="permission allowed">✓ ALLOWED</span>' : '<span class="permission restricted">✕ RESTRICTED</span>');
  body.innerHTML = permissionModules.map(([module, label]) => `<tr><td>${label}</td><td>${badge(matrix['Super Admin']?.[module] === true)}</td><td>${badge(matrix.Admin?.[module] === true)}</td></tr>`).join('');
}

async function initializeManagement() {
  const usersPage = document.getElementById('users-page');
  const adminsPage = document.getElementById('admins-page');
  const permissionsPage = document.getElementById('permissions-page');
  if (!usersPage && !adminsPage && !permissionsPage) return;
  document.querySelectorAll('[data-management-close]').forEach((button) => button.addEventListener('click', closeManagementModals));
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeManagementModals(); });
  if (permissionsPage) renderPermissions();
  if (usersPage) {
    ['userSearch', 'userStatusFilter', 'userRoleFilter', 'userDateFilter'].forEach((id) => document.getElementById(id)?.addEventListener(id === 'userSearch' ? 'input' : 'change', renderUsers));
    document.querySelector('[data-management-action="add-user"]')?.addEventListener('click', () => fillAccountForm('user'));
    document.getElementById('userForm')?.addEventListener('submit', (event) => { event.preventDefault(); saveAccount('user', event.target); });
  }
  if (adminsPage) {
    ['adminSearch', 'adminStatusFilter', 'adminRoleFilter'].forEach((id) => document.getElementById(id)?.addEventListener(id === 'adminSearch' ? 'input' : 'change', renderAdmins));
    document.querySelector('[data-management-action="add-admin"]')?.addEventListener('click', () => fillAccountForm('admin'));
    document.getElementById('adminForm')?.addEventListener('submit', (event) => { event.preventDefault(); saveAccount('admin', event.target); });
  }
  document.getElementById('confirmAction')?.addEventListener('click', deactivatePending);
  for (const [page, type, render] of [[usersPage, 'users', renderUsers], [adminsPage, 'admins', renderAdmins]]) {
    if (!page) continue;
    try {
      await loadAccounts(type);
      if (managementState.demo[type]) showManagementToast(`API unavailable — showing demo ${type === 'users' ? 'user' : 'administrator'} data`);
    } catch (error) {
      managementState.rows[type] = [];
      showManagementToast(mstApiErrorMessage(error, 'Unable to load accounts from the database.'));
    }
    render();
  }
}

document.addEventListener('DOMContentLoaded', initializeManagement);
window.fetchUsers = fetchUsers; window.createUser = createUser; window.updateUser = updateUser; window.fetchAdmins = fetchAdmins; window.createAdmin = createAdmin; window.updateAdmin = updateAdmin; window.fetchPermissions = fetchPermissions; window.fetchSettings = fetchSettings; window.updateSettings = updateSettings;
