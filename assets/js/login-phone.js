// Super Admin sign-in, step 2: shows the QR code for the paired phone and waits until it is approved there.
window.MSTPhoneLogin = (() => {
  const POLL_MS = 2000;
  let timer = null;
  let countdown = null;

  function renderQr(target, text) {
    // qrcode-generator (assets/js/vendor/qrcode.js): type 0 = smallest size that fits, error correction M.
    const qr = window.qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    target.innerHTML = qr.createSvgTag({ cellSize: 6, margin: 24, scalable: true });
  }

  function show(form, panel) {
    form.classList.add('hidden');
    panel.classList.remove('hidden');
  }

  function stop() { window.clearTimeout(timer); window.clearInterval(countdown); }

  function finish(message, failed) {
    stop();
    const status = document.getElementById('phoneStatus');
    status.textContent = message;
    status.classList.toggle('failed', failed);
    document.getElementById('phoneQr').classList.add('used');
  }

  function start(data) {
    const form = document.getElementById('loginForm');
    const panel = document.getElementById('phoneApproval');
    if (!form || !panel || !window.qrcode) { alert('Phone verification is unavailable on this page.'); return; }
    stop();
    show(form, panel);
    renderQr(document.getElementById('phoneQr'), data.qrUrl);
    document.getElementById('phoneQr').classList.remove('used');
    document.getElementById('phoneMatch').textContent = String(data.matchNumber).padStart(2, '0');
    document.getElementById('phoneUrl').textContent = data.qrUrl.replace(/\?t=.*/, '?t=…');
    const status = document.getElementById('phoneStatus');
    status.classList.remove('failed');
    let left = data.expiresInSeconds;
    const tick = () => { status.textContent = `Waiting for approval… ${Math.max(0, left)} s left`; left -= 1; };
    tick();
    countdown = window.setInterval(tick, 1000);
    poll();
  }

  async function poll() {
    try {
      const { data } = await window.MSTApi.apiPost('/auth/approval', {});
      if (data.status === 'approved') {
        finish('Approved on your phone. Signing in…', false);
        sessionStorage.setItem('mstRole', data.user.role === 'Super Admin' ? 'superadmin' : 'admin');
        window.location.href = 'dashboard.html';
        return;
      }
    } catch (error) {
      if (!error.status) { timer = window.setTimeout(poll, POLL_MS * 2); return; } // API briefly unreachable: keep waiting
      finish(error.message || 'The sign-in could not be completed.', true);
      return;
    }
    timer = window.setTimeout(poll, POLL_MS);
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('phoneCancel')?.addEventListener('click', () => {
      stop();
      document.getElementById('phoneApproval')?.classList.add('hidden');
      document.getElementById('loginForm')?.classList.remove('hidden');
      const password = document.getElementById('password');
      if (password) { password.value = ''; password.focus(); }
    });
  });

  return { start };
})();
