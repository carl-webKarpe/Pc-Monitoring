// Computers > Add Computers: enrollment keys (/api/enrollment). One key adds many lab PCs; the key is shown once.
(() => {
  let created = null; // { key, serverUrl, label } of the key created in this window (never stored)

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

  function downloadFile() {
    if (!created) return;
    // Read by setup-agent.bat on each PC. KEY lets a PC enroll; SERVER is a hint (PCs also search the network).
    const text = `MST enrollment (${created.label})\r\nKEY=${created.key}\r\nSERVER=${created.serverUrl}\r\n`;
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    link.download = 'enrollment.txt';
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  function open() {
    created = null;
    document.getElementById('enrollResult').classList.add('hidden');
    document.getElementById('enrollError').classList.add('hidden');
    document.getElementById('enrollKey').textContent = '';
    modal().classList.remove('hidden');
    loadKeys();
    document.getElementById('enrollLabel').focus();
  }

  function close() {
    created = null; // the key is gone once the window closes
    document.getElementById('enrollKey').textContent = '';
    modal().classList.add('hidden');
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!modal()) return;
    document.getElementById('addComputers')?.addEventListener('click', open);
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
