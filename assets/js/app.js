// Shared helpers for pages that render API data.
function mstEscape(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[character]));
}

// MySQL DATETIME/TIMESTAMP values ("2026-09-15 22:42:00") are shown in the browser's local time.
function mstParseDate(value) {
  if (!value) return null;
  const date = new Date(String(value).replace(' ', 'T'));
  return Number.isNaN(date.getTime()) ? null : date;
}

function mstFormatDate(value) {
  const date = mstParseDate(value);
  if (!date) return '—';
  return `${date.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })} - ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
}

function mstTimeAgo(value) {
  const date = mstParseDate(value);
  if (!date) return '—';
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return 'Just now';
  const units = [['day', 86400], ['hour', 3600], ['min', 60]];
  const [unit, size] = units.find(([, length]) => seconds >= length);
  const amount = Math.floor(seconds / size);
  return `${amount} ${unit}${amount === 1 || unit === 'min' ? '' : 's'} ago`;
}

// Reuses a page's existing .toast element when it has one, otherwise creates one with the same styling.
function showMSTToast(message, toastId) {
  let toast = toastId ? document.getElementById(toastId) : null;
  if (!toast) {
    toast = document.getElementById('mstToast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'mstToast';
      toast.className = 'toast';
      toast.setAttribute('role', 'status');
      toast.innerHTML = '<i class="fa-solid fa-circle-info"></i><span></span>';
      document.body.appendChild(toast);
    }
  }
  const text = toast.querySelector('span');
  if (text) text.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(toast.mstTimer);
  toast.mstTimer = window.setTimeout(() => toast.classList.remove('show'), 3200);
}

function mstApiErrorMessage(error, fallback = 'Unable to load data from the server.') {
  if (!error || !error.status) return 'The MST API is not reachable. Start the PHP backend and try again.';
  if (error.status === 403) return error.payload?.error?.code === 'FORBIDDEN' ? 'You do not have permission to access this data.' : (error.message || 'This action is not allowed.');
  if (error.status >= 500) return fallback;
  return error.message || fallback;
}

// Notifications bell: newest files reported by the lab-PC agents. Keeps the page's demo items if the API is unreachable.
async function mstLoadNotifications() {
  const panel = document.getElementById('notificationsPanel');
  if (!panel || !window.MSTApi) return;
  let events;
  try {
    events = (await window.MSTApi.apiGet('/file-events?type=created&limit=5')).data;
  } catch (error) {
    return;
  }
  const container = panel.querySelector('.notification-list') || panel;
  panel.querySelectorAll('.notification-item').forEach((item) => item.remove());
  const items = events.length ? events.map((event) => `<div class="notification-item warning"><i class="fa-solid fa-file-circle-exclamation"></i><div><strong>New file detected: ${mstEscape(event.fileName)}</strong><small>${mstEscape(event.computerHostname)} · ${mstEscape(mstTimeAgo(event.detectedAt))}</small></div></div>`).join('') : '<div class="notification-item success"><i class="fa-solid fa-circle-check"></i><div><strong>No new file activity</strong><small>Files reported by the monitoring agents appear here.</small></div></div>';
  container.insertAdjacentHTML('beforeend', items);
  const badge = document.querySelector('#notificationsToggle .badge-dot');
  if (badge) {
    const recent = events.filter((event) => { const date = mstParseDate(event.detectedAt); return date && Date.now() - date.getTime() < 86400000; }).length;
    badge.textContent = recent;
    badge.style.display = recent ? '' : 'none';
  }
}

// ---- Scan results (Phase 13): shared by File Scanner, Scan History, Detected Files and the dashboard ----
const MST_RISK = {
  High: ['high', 'HIGH RISK', 'fa-triangle-exclamation'], Medium: ['medium', 'MEDIUM RISK', 'fa-circle-exclamation'], Safe: ['safe', 'SAFE', 'fa-circle-check'],
  Unknown: ['unknown', 'UNKNOWN', 'fa-circle-question'], Failed: ['failed', 'SCAN FAILED', 'fa-circle-xmark']
};
const MST_STRENGTH_HELP = {
  Strong: 'Confirmed by an antivirus signature, the blocklist, 10+ VirusTotal vendors, or two clean engines',
  Moderate: 'One engine result, 3-9 VirusTotal vendors, or a disguised program',
  Limited: 'Only suspicious indicators or 1-2 VirusTotal vendors',
  'N/A': 'Not enough evidence to rate'
};
function mstScanCode(id) { return `SCN-${String(id).padStart(3, '0')}`; }
// Results recorded before Phase 13 used Critical/Low: shown as High/Unknown on the five-level scale.
function mstRiskOf(scan) { return scan?.riskClass || ({ Critical: 'High', Low: 'Unknown' }[scan?.riskLevel] ?? scan?.riskLevel ?? null); }
function mstRiskBadge(risk, state) {
  if (state === 'Pending' || state === 'Scanning') return `<span class="risk-badge pending"><i class="fa-solid fa-spinner"></i> ${state === 'Pending' ? 'WAITING' : 'SCANNING'}</span>`;
  if (!risk) return '<span class="risk-badge unknown">NOT SCANNED</span>';
  const [tone, label, icon] = MST_RISK[risk] || ['unknown', String(risk).toUpperCase(), 'fa-circle-question'];
  return `<span class="risk-badge ${tone}"><i class="fa-solid ${icon}"></i> ${mstEscape(label)}</span>`;
}
function mstStateBadge(state) {
  const icon = { Pending: 'fa-clock', Scanning: 'fa-spinner', Completed: 'fa-check', Failed: 'fa-circle-xmark' }[state] || 'fa-circle';
  return `<span class="state-badge ${mstEscape(String(state || '').toLowerCase())}"><i class="fa-solid ${icon}"></i> ${mstEscape(state || '—')}</span>`;
}
function mstStrength(scan) {
  const strength = scan.evidenceStrength;
  if (!strength) return '<span class="strength">—</span>';
  return `<span class="strength" title="${mstEscape(MST_STRENGTH_HELP[strength] || '')}">${mstEscape(strength === 'N/A' ? 'N/A' : `${strength} evidence`)}${scan.analysisCoverage === 'Partial' ? '<small>Partial analysis</small>' : ''}</span>`;
}
function mstScanDetails(scan) { try { return scan?.scanDetails ? JSON.parse(scan.scanDetails) : {}; } catch { return {}; } }
function mstVirusTotalText(vt) {
  if (!vt) return 'Not checked';
  if (vt.status === 'found') return `${mstEscape(vt.malicious)} of ${mstEscape(vt.total)} security vendors flagged it${vt.suspicious ? ` (${mstEscape(vt.suspicious)} suspicious)` : ''} · <a class="text-link" href="${mstEscape(vt.link)}" target="_blank" rel="noopener noreferrer">View report</a>`;
  if (vt.status === 'not_found') return 'Unknown to VirusTotal (never submitted)';
  if (vt.status === 'pending') return '<i class="fa-solid fa-spinner"></i> Uploaded, analysis in progress…';
  if (vt.status === 'not_configured') return 'Not configured (no API key)';
  return `Unavailable${vt.reason ? ` — ${mstEscape(vt.reason)}` : ''}`;
}
function mstFileSize(bytes) {
  if (bytes === null || bytes === undefined || bytes === '') return '—';
  const value = Number(bytes);
  if (value < 1024) return `${value} B`;
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1048576).toFixed(1)} MB`;
}
// Full scan report: metadata, result, antivirus engines, VirusTotal, evidence and recommended next steps.
function mstScanReportHtml(scan) {
  const esc = mstEscape;
  const details = mstScanDetails(scan);
  const risk = mstRiskOf(scan);
  const location = scan.filePath || (scan.source === 'Upload' ? 'Uploaded on the File Scanner page' : '—');
  const download = details.download && details.download.zone >= 3 ? `Downloaded from the internet (Windows Mark of the Web, zone ${esc(details.download.zone)})${details.download.hostUrl ? ` · source: ${esc(details.download.hostUrl)}` : ''}` : '';
  const engines = (details.engines || []).map((engine) => `<tr><td>${esc(engine.name)} ${esc(engine.version || '')}${engine.signatureVersion ? `<small class="table-subtext">signatures ${esc(engine.signatureVersion)}</small>` : ''}</td><td>${engine.result === 'detected' ? `<span class="risk-badge high">DETECTED</span> ${esc(engine.signature || '')}` : engine.result === 'clean' ? '<span class="risk-badge safe">NO THREAT</span>' : `<span class="risk-badge unknown">${esc(String(engine.result).toUpperCase())}</span>`}<small class="table-subtext">${esc(engine.detail || '')}</small></td></tr>`).join('');
  const factors = (details.factors || (details.error ? [details.error] : [])).map((factor) => `<li>${esc(factor)}</li>`).join('') || '<li>No evidence recorded for this scan.</li>';
  const steps = (details.recommendations || []).map((step) => `<li>${esc(step)}</li>`).join('');
  const pending = scan.scanState === 'Pending' || scan.scanState === 'Scanning';
  return `<div class="phase5-detail-grid">
      <div><span>Scan ID</span><strong>${esc(mstScanCode(scan.id))}</strong></div>
      <div><span>Status</span><strong>${mstStateBadge(scan.scanState)}</strong></div>
      <div><span>Risk Level</span><strong>${mstRiskBadge(risk, scan.scanState)}</strong></div>
      <div><span>Evidence Strength</span><strong>${mstStrength(scan)}</strong></div>
      <div class="file-wide"><span>Detection</span><strong>${esc(scan.detection || (pending ? 'Waiting for the scan to finish' : '—'))}</strong></div>
      <div><span>File Name</span><strong>${esc(scan.fileName || '—')}</strong></div>
      <div><span>File Type (from content)</span><strong>${esc(scan.fileType || details.fileType?.label || '—')}</strong></div>
      <div class="file-wide"><span>Location</span><strong>${esc(location)}</strong></div>
      <div><span>Computer</span><strong>${esc(scan.computerHostname ? `${scan.computerHostname} (${scan.computerDeviceId})` : 'MST server (upload)')}</strong></div>
      <div><span>File Size</span><strong>${esc(mstFileSize(scan.fileSize))}</strong></div>
      <div class="file-wide"><span>SHA-256</span><strong class="hash-cell">${esc(scan.fileHash || 'Not available')}</strong></div>
      <div><span>Requested</span><strong>${esc(mstFormatDate(scan.createdAt))}<small class="table-subtext">${esc(scan.source === 'Auto' ? 'Automatic scan of a new file' : `by ${scan.createdByUsername || 'System'}`)}</small></strong></div>
      <div><span>Completed</span><strong>${esc(scan.completedAt ? mstFormatDate(scan.completedAt) : '—')}<small class="table-subtext">${esc(scan.duration || '')}</small></strong></div>
      <div class="file-wide"><span>Scanner</span><strong>${esc(scan.scanner || '—')}</strong></div>
      ${download ? `<div class="file-wide"><span>Download Information</span><strong>${download}</strong></div>` : ''}
    </div>
    ${risk === 'Safe' && !pending ? '<p class="safe-note"><i class="fa-solid fa-circle-info"></i> Safe means the configured scanners found no threat. It does not guarantee that the file is completely safe.</p>' : ''}
    ${scan.analysisCoverage === 'Partial' ? '<p class="scan-note"><i class="fa-solid fa-circle-half-stroke"></i> Partial analysis: at least one scanner could not check this file (see Evidence).</p>' : ''}
    <h4 class="phase5-subheading">ANTIVIRUS ENGINES</h4>
    ${engines ? `<table class="engine-table"><tbody>${engines}</tbody></table>` : '<p class="file-note">No antivirus engine result for this scan.</p>'}
    <h4 class="phase5-subheading">VIRUSTOTAL</h4><p class="file-note">${mstVirusTotalText(details.virusTotal)}</p>
    <h4 class="phase5-subheading">EVIDENCE</h4><ul class="evidence-list">${factors}</ul>
    ${steps ? `<h4 class="phase5-subheading">RECOMMENDED NEXT STEPS</h4><ul class="evidence-list">${steps}</ul>` : ''}`;
}

document.addEventListener('DOMContentLoaded', () => {
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  const pathPrefix = window.location.pathname.includes('/management/') ? '../' : '';
  const isAppPage = Boolean(document.getElementById('sidebar'));
  const toFrontendRole = (serverRole) => ({ 'Super Admin': 'superadmin', Admin: 'admin' }[serverRole] || null);
  const redirectToLogin = (expired = false) => { sessionStorage.removeItem('mstRole'); window.location.replace(`${pathPrefix}login.html${expired ? '?expired=1' : ''}`); };
  const role = sessionStorage.getItem('mstRole');

  // Pages behind the sidebar require a signed-in Super Admin or Admin; the server session is the source of truth.
  if (isAppPage && !['superadmin', 'admin'].includes(role)) {
    redirectToLogin();
    return;
  }
  if (isAppPage && window.MSTApi) {
    window.MSTApi.authMe().then(({ data }) => {
      const serverRole = toFrontendRole(data.user.role);
      if (!serverRole) { redirectToLogin(); return; }
      if (serverRole !== role) { sessionStorage.setItem('mstRole', serverRole); window.location.reload(); return; }
      mstLoadNotifications();
    }).catch((error) => {
      if (error.status === 401) window.MSTApi.sessionEnded(error.payload?.error?.code);
      // Other failures (API offline) keep the current view; every API request is still authorized server-side.
    });
  }

  const getNavigation = (selectedRole) => [
    { label: 'MAIN', items: [{ href: 'dashboard.html', icon: 'table-columns', text: 'Dashboard' }] },
    { label: 'MONITORING', items: [
      { href: 'monitoring.html', icon: 'chart-line', text: 'Overview' },
      { href: 'computers.html', icon: 'desktop', text: 'Computers' },
      { href: 'monitoring.html#network-visual', icon: 'network-wired', text: 'Network Activity' }
    ] },
    { label: 'THREAT MANAGEMENT', items: [
      { href: 'threats.html', icon: 'shield-halved', text: 'Threats' },
      { href: 'files.html', icon: 'file-circle-exclamation', text: 'Detected Files' },
      ...(selectedRole === 'admin' ? [{ href: 'file-scanner.html', icon: 'magnifying-glass', text: 'File Scanner' }] : []),
      { href: 'scan-history.html', icon: 'clock-rotate-left', text: 'Scan History' }
    ] },
    ...(selectedRole === 'superadmin' ? [{ label: 'USER MANAGEMENT', items: [
      { href: 'management/admins.html', icon: 'user-gear', text: 'Admins' },
      { href: 'management/users.html', icon: 'users', text: 'Users' },
      { href: 'management/permissions.html', icon: 'key', text: 'Permissions' }
    ] }] : []),
    { label: 'REPORTS', items: [
      { href: 'reports.html', icon: 'chart-column', text: 'Reports' },
      { href: 'activity-logs.html', icon: 'clipboard-list', text: 'Activity Logs' }
    ] },
    { label: 'SYSTEM', items: [{ href: 'settings.html', icon: 'gear', text: 'Settings' }] }
  ];

  const renderSidebar = (selectedRole = role) => {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    const navigation = getNavigation(selectedRole);
    const sidebarNav = sidebar.querySelector('.nav-section');
    const linkPrefix = window.location.pathname.includes('/management/') ? '../' : '';
    if (sidebarNav) {
      sidebarNav.innerHTML = navigation.map((section) => `
        <div class="nav-label">${section.label}</div>
        ${section.items.map((item) => `<a href="${linkPrefix}${item.href}" class="nav-item ${currentPage === item.href.split('#')[0] ? 'active' : ''}"><i class="fa-solid fa-${item.icon}"></i><span>${item.text}</span></a>`).join('')}
      `).join('');
    }
    const roleName = selectedRole === 'admin' ? 'Administrator' : 'Super Administrator';
    const roleBadge = selectedRole === 'admin' ? 'ADMIN' : 'SUPER ADMIN';
    const initials = selectedRole === 'admin' ? 'AD' : 'SA';
    document.querySelectorAll('.user-name').forEach((node) => { node.textContent = roleName; });
    document.querySelectorAll('.role-badge').forEach((node) => { node.textContent = roleBadge; });
    document.querySelectorAll('.avatar').forEach((node) => { node.textContent = initials; });
  };

  window.renderSidebar = renderSidebar;
  renderSidebar();

  document.querySelectorAll('a[href="index.html"], a[href="../index.html"]').forEach((link) => {
    link.addEventListener('click', (event) => {
      sessionStorage.removeItem('mstRole');
      if (!window.MSTApi) return;
      event.preventDefault();
      window.MSTApi.logout().catch(() => {}).finally(() => { window.location.href = link.href; });
    });
  });

  const restrictedPage = (role === 'admin' && ['admins.html', 'users.html', 'permissions.html'].includes(currentPage)) || (role === 'superadmin' && currentPage === 'file-scanner.html');
  if (restrictedPage) {
    const pageContent = document.querySelector('main .page-content');
    if (currentPage === 'file-scanner.html') document.getElementById('scanner-page')?.setAttribute('data-restricted', 'true');
    if (pageContent) {
      pageContent.innerHTML = `<section class="access-restricted"><div class="restricted-icon"><i class="fa-solid fa-lock"></i></div><p class="eyebrow">ACCESS RESTRICTED</p><h2>${role === 'admin' ? 'Administrator management is restricted.' : 'File Scanner is restricted.'}</h2><p>${role === 'admin' ? 'You do not have permission to access Administrator or User Management.' : 'The File Scanner is available only to authorized Admin accounts.'}</p><a href="dashboard.html" class="btn-primary">Return to Dashboard</a></section>`;
    }
  }

  const loader = document.querySelector('.loader');
  const header = document.querySelector('.landing-header');
  const mobileMenu = document.querySelector('.mobile-menu');
  const mobileToggle = document.querySelector('.mobile-menu-toggle');
  const revealItems = document.querySelectorAll('.reveal');
  const countNodes = document.querySelectorAll('.count');

  if (loader) {
    window.setTimeout(() => {
      loader.classList.add('hidden');
    }, 1600);
  }

  if (header) {
    const onScroll = () => {
      header.classList.toggle('scrolled', window.scrollY > 18);
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  if (mobileToggle && mobileMenu) {
    mobileToggle.addEventListener('click', () => {
      const isOpen = mobileMenu.classList.toggle('show');
      mobileToggle.setAttribute('aria-expanded', String(isOpen));
    });

    mobileMenu.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        mobileMenu.classList.remove('show');
        mobileToggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  if ('IntersectionObserver' in window && revealItems.length) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });

    revealItems.forEach((item) => observer.observe(item));
  } else {
    revealItems.forEach((item) => item.classList.add('visible'));
  }

  if (countNodes.length && 'IntersectionObserver' in window) {
    const countObserver = new IntersectionObserver((entries, observerInstance) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;

        const element = entry.target;
        const target = Number(element.dataset.target || 0);
        const duration = 1200;
        const start = performance.now();

        const tick = (now) => {
          const progress = Math.min((now - start) / duration, 1);
          const value = Math.floor(progress * target);
          element.textContent = value.toLocaleString();

          if (progress < 1) {
            requestAnimationFrame(tick);
          } else {
            element.textContent = target.toLocaleString();
          }
        };

        requestAnimationFrame(tick);
        observerInstance.unobserve(element);
      });
    }, { threshold: 0.4 });

    countNodes.forEach((node) => countObserver.observe(node));
  } else {
    countNodes.forEach((node) => {
      const target = Number(node.dataset.target || 0);
      node.textContent = target.toLocaleString();
    });
  }

  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('overlay');
  const sidebarToggle = document.getElementById('sidebarToggle');
  const sidebarClose = document.getElementById('sidebarClose');
  const notificationsToggle = document.getElementById('notificationsToggle');
  const notificationsPanel = document.getElementById('notificationsPanel');
  const profileToggle = document.getElementById('profileToggle');
  const profilePanel = document.getElementById('profilePanel');
  const openModalButtons = document.querySelectorAll('.open-modal');
  const closeModalButtons = document.querySelectorAll('[data-close-modal]');
  const globalSearch = document.getElementById('globalSearch');

  const setSidebarState = (open) => {
    if (!sidebar) return;
    sidebar.classList.toggle('open', open);
    if (overlay) {
      overlay.classList.toggle('visible', open);
    }
  };

  if (sidebarToggle) {
    sidebarToggle.addEventListener('click', () => setSidebarState(!sidebar.classList.contains('open')));
  }
  if (sidebarClose) {
    sidebarClose.addEventListener('click', () => setSidebarState(false));
  }
  if (overlay) {
    overlay.addEventListener('click', () => setSidebarState(false));
  }

  const closePanels = () => {
    if (notificationsPanel) notificationsPanel.classList.add('hidden');
    if (profilePanel) profilePanel.classList.add('hidden');
  };

  if (notificationsToggle && notificationsPanel) {
    notificationsToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      notificationsPanel.classList.toggle('hidden');
      if (!profilePanel?.classList.contains('hidden')) profilePanel.classList.add('hidden');
    });
  }

  if (profileToggle && profilePanel) {
    profileToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      profilePanel.classList.toggle('hidden');
      if (!notificationsPanel?.classList.contains('hidden')) notificationsPanel.classList.add('hidden');
    });
  }

  document.addEventListener('click', (event) => {
    if (!event.target.closest('#notificationsToggle') && !event.target.closest('#notificationsPanel')) {
      if (notificationsPanel) notificationsPanel.classList.add('hidden');
    }
    if (!event.target.closest('#profileToggle') && !event.target.closest('#profilePanel')) {
      if (profilePanel) profilePanel.classList.add('hidden');
    }
  });

  if (openModalButtons.length) {
    openModalButtons.forEach((button) => {
      button.addEventListener('click', () => {
        const modalId = button.getAttribute('data-modal');
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.remove('hidden');
      });
    });
  }

  if (closeModalButtons.length) {
    closeModalButtons.forEach((button) => {
      button.addEventListener('click', () => {
        const modal = button.closest('.modal');
        if (modal) modal.classList.add('hidden');
      });
    });
  }

  const loginForm = document.getElementById('loginForm');
  if (loginForm && new URLSearchParams(window.location.search).get('expired') === '1') {
    const notice = document.createElement('p');
    notice.className = 'form-error';
    notice.setAttribute('role', 'status');
    notice.textContent = 'Your session expired after a period of inactivity. Please sign in again.';
    loginForm.prepend(notice);
  }
  if (loginForm) {
    loginForm.addEventListener('submit', (event) => {
      event.preventDefault();
      if (!loginForm.checkValidity()) {
        loginForm.reportValidity();
        return;
      }
      const username = document.getElementById('username')?.value.trim();
      const password = document.getElementById('password')?.value;
      if (!window.MSTApi) {
        alert('Authentication service is unavailable.');
        return;
      }
      window.MSTApi.apiPost('/auth/login', { username, password })
        .then(({ data }) => {
          const signedInRole = toFrontendRole(data.user.role);
          if (!signedInRole) {
            alert('Invalid username or password');
            return;
          }
          sessionStorage.setItem('mstRole', signedInRole);
          window.location.href = 'dashboard.html';
        })
        .catch((error) => {
          alert(error.status ? error.message : 'Authentication service is unavailable.');
        });
    });
  }

  const togglePasswordButtons = document.querySelectorAll('.toggle-password');
  togglePasswordButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const input = button.parentElement.querySelector('input');
      const icon = button.querySelector('i');
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      icon.classList.toggle('fa-eye', !isPassword);
      icon.classList.toggle('fa-eye-slash', isPassword);
      button.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
  });

  const toggleSwitches = document.querySelectorAll('.toggle-switch');
  toggleSwitches.forEach((toggle) => {
    toggle.addEventListener('click', () => toggle.classList.toggle('on'));
  });

  if (globalSearch) {
    globalSearch.addEventListener('input', (event) => {
      const query = event.target.value.toLowerCase().trim();
      const searchableNodes = document.querySelectorAll('tbody tr, .computer-card, .activity-item, .metric-card');
      searchableNodes.forEach((node) => {
        const text = node.textContent.toLowerCase();
        node.style.display = text.includes(query) || !query ? '' : 'none';
      });
    });
  }

  if (window.innerWidth <= 840 && sidebar) {
    setSidebarState(false);
  }

  if (window.location.pathname.endsWith('dashboard.html')) {
    const metricCards = document.querySelectorAll('.metric-card');
    metricCards.forEach((card, index) => {
      card.style.animationDelay = `${index * 100}ms`;
    });
  }
});

window.fetchDashboardData = function () {
  return {
    totalComputers: 24,
    onlineComputers: 18,
    offlineComputers: 6,
    threatsDetected: 7,
    filesScanned: 1284,
    safeFiles: 1261,
    suspiciousFiles: 16,
    criticalThreats: 7,
    status: 'Low Risk'
  };
};

window.fetchComputers = function () {
  return [
    { name: 'LAB-PC-01', ip: '192.168.1.20', status: 'online' },
    { name: 'LAB-PC-02', ip: '192.168.1.21', status: 'online' },
    { name: 'LAB-PC-03', ip: '192.168.1.22', status: 'offline' },
    { name: 'LAB-PC-04', ip: '192.168.1.23', status: 'threat' }
  ];
};

window.fetchThreats = function () { return [{ id: 'THR-001', computer: 'LAB-PC-04', file: 'unknown.exe', severity: 'critical' }]; };
window.fetchUsers = function () { return [{ name: 'Alex Martin', username: 'alexm', role: 'Analyst' }]; };
window.fetchAdmins = function () { return [{ name: 'Maria Santos', role: 'Super Admin' }]; };
window.fetchActivityLogs = function () { return [{ time: '10:42 PM', user: 'admin01', action: 'Logged in' }]; };
window.scanFile = function () { return { status: 'SAFE', threats: 0, hash: 'xxxxxxxxxxxxxxxx' }; };

window.addEventListener('load', () => {
  const adminOnlyLinks = document.querySelectorAll('.admin-only');
  const isSuperAdmin = true;
  if (!isSuperAdmin) {
    adminOnlyLinks.forEach((node) => node.style.display = 'none');
  }
});
