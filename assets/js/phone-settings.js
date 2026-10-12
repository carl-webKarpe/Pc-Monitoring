// Settings → Phone Verification (Super Admin): pair the phone that approves Super Admin sign-ins.
document.addEventListener('DOMContentLoaded', () => {
  const section = document.getElementById('phoneSettings');
  if (!section || !window.MSTApi) return;
  const esc = mstEscape;
  let pollTimer = null;

  function renderDevices(data) {
    const summary = document.getElementById('phoneSummary');
    const count = data.devices.length;
    if (!data.enabled) summary.textContent = 'Phone verification is turned off on the server (SUPERADMIN_PHONE_LOGIN=off in .env).';
    else if (count) summary.innerHTML = `<b>On.</b> After the password, Super Admin sign-in must be approved on ${count === 1 ? 'this phone' : `one of these ${count} phones`} by scanning a QR code.`;
    else summary.innerHTML = '<b>Not set up.</b> Super Admin currently signs in with the password only. Pair a phone to require approval on it.';
    document.getElementById('deviceList').innerHTML = data.devices.map((device) => `<li><span><b>${esc(device.name)}</b><small>Paired ${esc(mstFormatDate(device.createdAt))} · last used ${esc(device.lastUsedAt ? mstTimeAgo(device.lastUsedAt) : 'never')}</small></span><button class="btn-danger remove-device" type="button" data-id="${esc(device.id)}">Remove</button></li>`).join('');
    section.querySelectorAll('.remove-device').forEach((button) => button.addEventListener('click', () => removeDevice(button.dataset.id, count)));
    return data;
  }

  async function load() {
    try { return renderDevices((await window.MSTApi.apiGet('/auth/devices')).data); }
    catch (error) { document.getElementById('phoneSummary').textContent = mstApiErrorMessage(error, 'Unable to load paired phones.'); return null; }
  }

  async function removeDevice(id, count) {
    const warning = count === 1 ? ' It is your only paired phone: Super Admin will then sign in with the password only.' : '';
    if (!window.confirm(`Remove this phone? It will no longer be able to approve sign-ins.${warning}`)) return;
    try { renderDevices({ enabled: true, ...(await window.MSTApi.apiDelete(`/auth/devices/${id}`)).data }); showMSTToast('Phone removed', 'settingsToast'); load(); }
    catch (error) { showMSTToast(mstApiErrorMessage(error, 'Unable to remove the phone.'), 'settingsToast'); }
  }

  async function pair() {
    window.clearTimeout(pollTimer);
    let data;
    try { data = (await window.MSTApi.apiPost('/auth/devices', {})).data; }
    catch (error) { showMSTToast(mstApiErrorMessage(error, 'Unable to start pairing.'), 'settingsToast'); return; }
    const qr = window.qrcode(0, 'M');
    qr.addData(data.qrUrl);
    qr.make();
    document.getElementById('pairQr').innerHTML = qr.createSvgTag({ cellSize: 6, margin: 24, scalable: true });
    document.getElementById('pairQr').classList.remove('used');
    document.getElementById('pairUrl').textContent = data.qrUrl.replace(/\?t=.*/, '?t=…');
    document.getElementById('pairPanel').classList.remove('hidden');
    document.getElementById('pairStatus').textContent = 'Waiting for your phone…';
    const watch = async () => {
      const result = await load();
      const pairing = result?.pairing;
      if (pairing?.status === 'approved') {
        document.getElementById('pairStatus').innerHTML = `<b>Paired:</b> ${esc(pairing.deviceName || 'phone')}. From now on, Super Admin sign-in needs approval on it.`;
        document.getElementById('pairQr').classList.add('used');
        showMSTToast('Phone paired', 'settingsToast');
        return;
      }
      if (!pairing || pairing.status !== 'pending') {
        document.getElementById('pairStatus').textContent = 'The pairing QR code expired. Click "Pair a phone" to try again.';
        document.getElementById('pairQr').classList.add('used');
        return;
      }
      document.getElementById('pairStatus').textContent = `Waiting for your phone… ${pairing.secondsLeft} s left`;
      pollTimer = window.setTimeout(watch, 2000);
    };
    watch();
  }

  document.getElementById('pairPhone')?.addEventListener('click', pair);
  load().then((data) => {
    // Coming from the login page: a Super Admin without a paired phone is invited to pair one.
    if (data && !data.devices.length && data.enabled && new URLSearchParams(window.location.search).get('pair') === '1') {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' });
      showMSTToast('Protect the Super Admin account: pair your phone for sign-in approval', 'settingsToast');
    }
  });
});
