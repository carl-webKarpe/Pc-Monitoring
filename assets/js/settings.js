document.addEventListener('DOMContentLoaded', () => {
  const page = document.getElementById('settings-page');
  if (!page) return;

  const saved = JSON.parse(localStorage.getItem('mstSettings') || '{}');
  page.querySelectorAll('[data-setting]').forEach((toggle) => {
    if (saved[toggle.dataset.setting] !== undefined) toggle.classList.toggle('on', saved[toggle.dataset.setting]);
  });

  document.getElementById('saveSettings')?.addEventListener('click', () => {
    const settings = {};
    page.querySelectorAll('[data-setting]').forEach((toggle) => { settings[toggle.dataset.setting] = toggle.classList.contains('on'); });
    page.querySelectorAll('input[name]').forEach((input) => { settings[input.name] = input.value; });
    localStorage.setItem('mstSettings', JSON.stringify(settings));
    const toast = document.getElementById('settingsToast');
    toast?.classList.add('show');
    window.setTimeout(() => toast?.classList.remove('show'), 2800);
  });
});
