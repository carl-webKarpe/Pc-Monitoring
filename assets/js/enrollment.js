// Computers > Add Computers. "One PC": register a PC and get its device token + ready config.json (/api/computers).
// "Many PCs": enrollment keys (/api/enrollment), one key adds many lab PCs. Tokens and keys are shown once.
(() => {
  let created = null; // { key, serverUrl, label } of the key created in this window (never stored)
  let registered = null; // { deviceId, deviceToken, config } of the PC registered in this window (never stored)

  const modal = () => document.getElementById('enrollModal');
  const esc = (value) => mstEscape(value ?? '');

  function statusOf(key) {
    if (key.revokedAt) return '<span class="status-pill offline">● REVOKED</span>';
    if (key.active) return '<span class="status-pill online">● ACTIVE</span>';
    return `<span class="status-pill warning">● ${key.uses >= key.maxUses ? "USED UP" : "EXPIRED"}</span>`;
  }

  async function loadKeys() {
    const body = document.getElementById('enrollKeys');
    try {
      const { data } = await window.MSTApi.apiGet('/enrollment');
      body.innerHTML = data.keys.length ? data.keys.map((key) => `<tr>
          <td>${esc(key.label)}<small class="table-subtext">by ${esc(key.createdByUsername || '—')}</small></td>
          <td>${esc(key.uses)} / ${esc(key.maxUses)}</td>
          <td>${esc(mstFormatDate(key.expiresAt))}</td>
          <td>${statusOf(key)}</td>
          <td>${key.active ? `<button class="text-link link-button" data-revoke="${esc(key.id)}">Revoke</button>` : '—'}</td></tr>`).join('')
        : '<tr><td colspan="5">No enrollment keys yet.</td></tr>';
      body.querySelectorAll('[data-revoke]').forEach((button) => button.addEventListener('click', () => revoke(button.dataset.revoke)));
    } catch (error) {
      body.innerHTML = `<tr><td colspan="5">${esc(error.message || 'Could not load enrollment keys.')}</td></tr>`;
    }
  }

  async function revoke(id) {
    if (!window.confirm('Revoke this key? PCs already added keep working; no new PC can use the key.')) return;
    try {
      const result = await window.MSTApi.apiDelete(`/enrollment/${id}`);
      showMSTToast(result.message, 'computerToast');
    } catch (error) {
      showMSTToast(error.message || 'Could not revoke the key.', 'computerToast');
    }
    loadKeys();
  }

  async function createKey(event) {
    event.preventDefault();
    const error = document.getElementById('enrollError');
    const button = document.getElementById('enrollCreate');
    error.classList.add('hidden');
    button.disabled = true;
    try {
      const payload = { label: document.getElementById('enrollLabel').value.trim(), hours: Number(document.getElementById('enrollHours').value), maxUses: Number(document.getElementById('enrollMaxUses').value) };
      const { data } = await window.MSTApi.apiPost('/enrollment', payload);
      created = { key: data.key, serverUrl: data.serverUrl, label: data.record?.label || payload.label };
      document.getElementById('enrollKey').textContent = data.key;
      document.getElementById('enrollServer').textContent = data.serverUrl;
      document.getElementById('enrollResult').classList.remove('hidden');
      loadKeys();
    } catch (failure) {
      const details = failure.payload?.errors ? Object.values(failure.payload.errors).join(" ") : "";
      error.textContent = details || failure.message || 'Could not create the key.';
      error.classList.remove('hidden');
    } finally {
      button.disabled = false;
    }
  }

  function selectTab(name) {
    document.querySelectorAll('.enroll-tab').forEach((tab) => { const active = tab.dataset.enrollTab === name; tab.classList.toggle('active', active); tab.setAttribute('aria-selected', String(active)); });
    document.getElementById('enrollPanelOne').classList.toggle('hidden', name !== 'one');
    document.getElementById('enrollPanelMany').classList.toggle('hidden', name !== 'many');
    if (name === 'many') loadKeys();
  }

  // Shows a device token once (after Register Computer, or New Token on a computer's details).
  function showToken(data) {
    registered = data;
    document.getElementById('registerDevice').textContent = data.deviceId;
    document.getElementById('registerToken').textContent = data.deviceToken;
    document.getElementById('registerServer').textContent = data.serverUrl;
    document.getElementById('registerResult').classList.remove('hidden');
  }

  async function registerComputer(event) {
    event.preventDefault();
    const error = document.getElementById('registerError');
    const button = document.getElementById('registerCreate');
    error.classList.add('hidden');
    button.disabled = true;
    try {
      const { data } = await window.MSTApi.apiPost('/computers', { name: document.getElementById('registerName').value.trim() });
      showToken(data);
      document.getElementById('registerName').value = '';
      document.dispatchEvent(new CustomEvent('mst:computers-changed'));
    } catch (failure) {
      const details = failure.payload?.errors ? Object.values(failure.payload.errors).join(" ") : "";
      error.textContent = details || failure.message || 'Could not register the computer.';
      error.classList.remove('hidden');
    } finally {
      button.disabled = false;
    }
  }

  function saveText(name, text, type) {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([text], { type }));
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  function downloadFile() {
    if (!created) return;
    // Read by setup-agent.bat on each PC. KEY lets a PC enroll; SERVER is a hint (PCs also search the network).
    saveText('enrollment.txt', `MST enrollment (${created.label})\r\nKEY=${created.key}\r\nSERVER=${created.serverUrl}\r\n`, 'text/plain');
  }

  function clearSecrets() {
    created = null; registered = null; // keys and tokens are gone once the window closes
    ['enrollKey', 'registerToken', 'registerDevice'].forEach((id) => { document.getElementById(id).textContent = ''; });
    ['enrollResult', 'enrollError', 'registerResult', 'registerError'].forEach((id) => document.getElementById(id).classList.add('hidden'));
  }

  function open(tokenData) {
    clearSecrets();
    selectTab('one');
    if (tokenData) showToken(tokenData);
    modal().classList.remove('hidden');
    if (!tokenData) document.getElementById('registerName').focus();
  }

  function close() {
    clearSecrets();
    modal().classList.add('hidden');
  }

  window.MSTEnrollment = { open };

  document.addEventListener('DOMContentLoaded', () => {
    if (!modal()) return;
    document.getElementById('addComputers')?.addEventListener('click', () => open());
    document.querySelectorAll('.enroll-tab').forEach((tab) => tab.addEventListener('click', () => selectTab(tab.dataset.enrollTab)));
    document.getElementById('registerForm').addEventListener('submit', registerComputer);
    document.getElementById('registerDownload').addEventListener('click', () => registered && saveText('config.json', `${JSON.stringify(registered.config, null, 2)}\n`, 'application/json'));
    document.getElementById('registerCopy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(registered?.deviceToken || ''); showMSTToast('Token copied', 'computerToast'); }
      catch { showMSTToast('Select the token and press Ctrl+C', 'computerToast'); }
    });
    document.querySelectorAll('[data-close-enroll]').forEach((button) => button.addEventListener('click', close));
    document.getElementById('enrollForm').addEventListener('submit', createKey);
    document.getElementById('enrollDownload').addEventListener('click', downloadFile);
    document.getElementById('enrollCopy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(created?.key || ''); showMSTToast('Key copied', 'computerToast'); }
      catch { showMSTToast('Select the key and press Ctrl+C', 'computerToast'); }
    });
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && !modal().classList.contains('hidden')) close(); });
  });
})();
