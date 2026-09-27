document.addEventListener('DOMContentLoaded', () => {
  const scannerPage = document.getElementById('scanner-page');
  if (!scannerPage || scannerPage.dataset.restricted === 'true') return;

  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const scanProgress = document.getElementById('scanProgress');
  const scanResult = document.getElementById('scanResult');

  const showProgress = () => {
    if (dropZone) dropZone.classList.add('hidden');
    if (scanProgress) scanProgress.classList.remove('hidden');
    if (scanResult) scanResult.classList.add('hidden');

    setTimeout(() => {
      if (scanProgress) scanProgress.classList.add('hidden');
      if (scanResult) scanResult.classList.remove('hidden');
      const fileName = fileInput?.files?.[0]?.name || 'example.exe';
      const hash = '4f2a8d9c91bf1a6a3e5f8d2a9c7b4e1a';
      const resultName = scannerPage.querySelector('#resultFileName');
      const resultHash = scannerPage.querySelector('#resultHash');
      if (resultName) resultName.textContent = fileName;
      if (resultHash) resultHash.textContent = hash;
    }, 2400);
  };

  if (fileInput) {
    fileInput.addEventListener('change', showProgress);
  }

  if (dropZone) {
    ['dragenter', 'dragover'].forEach(type => {
      dropZone.addEventListener(type, (event) => {
        event.preventDefault();
        dropZone.style.borderColor = 'rgba(0,217,255,0.7)';
      });
    });

    ['dragleave', 'drop'].forEach(type => {
      dropZone.addEventListener(type, (event) => {
        event.preventDefault();
        dropZone.style.borderColor = 'rgba(0,217,255,0.3)';
      });
    });

    dropZone.addEventListener('drop', (event) => {
      event.preventDefault();
      const files = event.dataTransfer?.files;
      if (files && files.length) {
        fileInput.files = files;
        showProgress();
      }
    });
  }
});
