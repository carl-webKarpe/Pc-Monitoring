document.addEventListener('DOMContentLoaded', () => {
  const page = document.getElementById('settings-page');
  if (!page) return;

  let settingsAreLocal = false;

  // Settings values come back from MySQL as strings; toggles are stored as "1" / "0".
  const applySettings = (saved) => {
    page.querySelectorAll('[data-setting]').forEach((toggle) => {
      const value = saved[toggle.dataset.setting];
      if (value !== undefined) toggle.classList.toggle('on', value === true || value === '1');
    });
    page.querySelectorAll('input[name]').forEach((input) => {
      if (saved[input.name] !== undefined) input.value = saved[input.name];
    });
  };

  const readLocalSettings = () => { try { return JSON.parse(localStorage.getItem('mstSettings') || '{}'); } catch { return {}; } };

  const collectSettings = () => {
    const settings = {};
    page.querySelectorAll('[data-setting]').forEach((toggle) => { settings[toggle.dataset.setting] = toggle.classList.contains('on'); });
    page.querySelectorAll('input[name]').forEach((input) => { settings[input.name] = input.value.trim(); });
    return settings;
  };

  window.MSTApi.apiGetOrDemo('/settings', readLocalSettings())
    .then(({ data, demo }) => {
      settingsAreLocal = demo;
      applySettings(data);
      if (demo) showMSTToast('API unavailable — settings are stored in this browser only', 'settingsToast');
    })
    .catch((error) => showMSTToast(mstApiErrorMessage(error, 'Unable to load settings from the database.'), 'settingsToast'));

  const saveButton = document.getElementById('saveSettings');
  saveButton?.addEventListener('click', async () => {
    const settings = collectSettings();
    if (settingsAreLocal) {
      localStorage.setItem('mstSettings', JSON.stringify(settings));
      showMSTToast('Settings saved in this browser (API unavailable)', 'settingsToast');
      return;
    }
    saveButton.disabled = true;
    try {
      const { data } = await window.MSTApi.apiPut('/settings', settings);
      applySettings(data);
      showMSTToast('Settings saved successfully', 'settingsToast');
    } catch (error) {
      const fieldErrors = error.payload?.errors ? Object.values(error.payload.errors).join(' ') : '';
      showMSTToast(error.status === 422 && fieldErrors ? fieldErrors : mstApiErrorMessage(error, 'Unable to save settings.'), 'settingsToast');
    } finally {
      saveButton.disabled = false;
    }
  });
});
