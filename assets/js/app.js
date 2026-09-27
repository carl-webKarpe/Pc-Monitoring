document.addEventListener('DOMContentLoaded', () => {
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  const pathPrefix = window.location.pathname.includes('/management/') ? '../' : '';
  const isAppPage = Boolean(document.getElementById('sidebar'));
  const toFrontendRole = (serverRole) => ({ 'Super Admin': 'superadmin', Admin: 'admin' }[serverRole] || null);
  const redirectToLogin = () => { sessionStorage.removeItem('mstRole'); window.location.replace(`${pathPrefix}login.html`); };
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
      if (serverRole !== role) { sessionStorage.setItem('mstRole', serverRole); window.location.reload(); }
    }).catch((error) => {
      if (error.status === 401) redirectToLogin();
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
