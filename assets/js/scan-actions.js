// Scan and quarantine actions shared by Scan History and Detected Files. Every action is a real API call that the
// server checks (Admin only for changes) and records in the Activity Log. Risky actions need explicit confirmation.
window.MSTScanActions = (() => {
  const isAdmin = () => sessionStorage.getItem('mstRole') === 'admin';
  const errorText = (error, fallback) => {
    const fields = error?.payload?.errors ? Object.values(error.payload.errors).join(' ') : '';
    return fields || mstApiErrorMessage(error, fallback);
  };

  // Confirmation dialog: fields = [{ id, label, type: 'text' | 'textarea', placeholder }]
  function confirm({ title, message, fields = [], button = 'Confirm', run }) {
    const modal = document.getElementById('scanConfirmModal');
    if (!modal) return;
    document.getElementById('scanConfirmTitle').textContent = title;
    document.getElementById('scanConfirmMessage').textContent = message;
    document.getElementById('scanConfirmError').textContent = '';
    document.getElementById('scanConfirmFields').innerHTML = fields.map((field) => `<label class="file-note" for="${field.id}">${mstEscape(field.label)}</label>${field.type === 'textarea' ? `<textarea class="confirm-input" id="${field.id}" maxlength="255" placeholder="${mstEscape(field.placeholder || '')}"></textarea>` : `<input class="confirm-input" id="${field.id}" autocomplete="off" placeholder="${mstEscape(field.placeholder || '')}">`}`).join('');
    const confirmButton = document.getElementById('scanConfirmButton');
    confirmButton.textContent = button;
    confirmButton.disabled = false;
    confirmButton.onclick = async () => {
      const values = Object.fromEntries(fields.map((field) => [field.id, document.getElementById(field.id).value.trim()]));
      confirmButton.disabled = true;
      try {
        const message = await run(values);
        close();
        showMSTToast(message);
        document.dispatchEvent(new CustomEvent('mst:scans-changed'));
      } catch (error) {
        document.getElementById('scanConfirmError').textContent = errorText(error, 'The action could not be completed.');
        confirmButton.disabled = false;
      }
    };
    modal.classList.remove('hidden');
    modal.querySelector('input, textarea')?.focus();
  }
  function close() { document.getElementById('scanConfirmModal')?.classList.add('hidden'); }
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-confirm-close]').forEach((button) => button.addEventListener('click', close));
  });

  const quarantine = (fileName, path) => confirm({
    title: 'Quarantine file',
    message: `Move ${fileName} out of the user's folder into the agent's quarantine folder? The agent first checks that the file is unchanged (same SHA-256). The file can be released or deleted later.`,
    button: 'Quarantine', run: async () => (await window.MSTApi.apiPost(path, { confirm: true })).message,
  });
  const release = (item) => confirm({
    title: 'Release from quarantine',
    message: `Restore ${item.fileName} to ${item.originalPath}? Only do this when you are sure the file is safe. Your reason is saved in the Activity Log.`,
    fields: [{ id: 'releaseReason', label: 'Why is it safe to release? (at least 10 characters)', type: 'textarea' }, { id: 'releaseConfirm', label: 'Type RELEASE to confirm', placeholder: 'RELEASE' }],
    button: 'Release', run: async (values) => (await window.MSTApi.apiPost(`/quarantine/${item.id}/release`, { reason: values.releaseReason, confirm: values.releaseConfirm })).message,
  });
  const deleteQuarantined = (item) => confirm({
    title: 'Delete quarantined file',
    message: `Permanently delete ${item.fileName} from the quarantine folder on ${item.computerHostname}? This cannot be undone. The scan records are kept.`,
    fields: [{ id: 'deleteConfirm', label: 'Type DELETE to confirm', placeholder: 'DELETE' }],
    button: 'Delete permanently', run: async (values) => (await window.MSTApi.apiPost(`/quarantine/${item.id}/delete`, { confirm: values.deleteConfirm })).message,
  });
  const deleteStoredCopy = (scan) => confirm({
    title: 'Delete uploaded copy',
    message: `Delete the stored copy of ${scan.fileName} from the MST server now (it would otherwise be deleted when the retention period ends)? The scan record stays in Scan History.`,
    button: 'Delete copy', run: async () => (await window.MSTApi.apiDelete(`/scans/${scan.id}/stored-file`)).message,
  });
  async function rescan(scan) {
    try {
      const payload = await window.MSTApi.apiPost(`/scans/${scan.id}/rescan`, {});
      showMSTToast(payload.message);
      document.dispatchEvent(new CustomEvent('mst:scans-changed', { detail: { scanId: payload.data?.id } }));
      return payload.data;
    } catch (error) { showMSTToast(errorText(error, 'Unable to start a new scan.')); return null; }
  }
  return { isAdmin, confirm, close, quarantine, release, deleteQuarantined, deleteStoredCopy, rescan, errorText };
})();
