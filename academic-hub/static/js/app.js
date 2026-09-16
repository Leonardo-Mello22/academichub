// AcademicHub — scripts do cliente

// Fechar alertas ao clicar
document.querySelectorAll('.alert').forEach(function (el) {
  el.style.cursor = 'pointer';
  el.title = 'Clique para fechar';

  el.addEventListener('click', function () {
    el.remove();
  });
});


// Sidebar: recolher (desktop) + abrir (mobile)
(function () {
  var STORAGE_KEY = 'academichub.sidebarCollapsed';
  var collapseBtn = document.getElementById('sidebar-collapse');
  var mobileToggle = document.getElementById('sidebar-toggle');
  var backdrop = document.getElementById('sidebar-backdrop');

  function setCollapsed(collapsed) {
    document.body.classList.toggle('sidebar-collapsed', collapsed);

    if (collapseBtn) {
      collapseBtn.setAttribute(
        'aria-label',
        collapsed ? 'Expandir menu' : 'Recolher menu'
      );
      collapseBtn.title = collapsed ? 'Expandir menu' : 'Recolher menu';
    }

    try {
      localStorage.setItem(STORAGE_KEY, collapsed ? '1' : '0');
    } catch (e) {
      // ignore
    }
  }

  function closeMobileSidebar() {
    document.body.classList.remove('sidebar-open');
    if (backdrop) {
      backdrop.hidden = true;
    }
  }

  function openMobileSidebar() {
    document.body.classList.add('sidebar-open');
    if (backdrop) {
      backdrop.hidden = false;
    }
  }

  // Restaura preferência no desktop
  try {
    if (localStorage.getItem(STORAGE_KEY) === '1') {
      setCollapsed(true);
    }
  } catch (e) {
    // ignore
  }

  if (collapseBtn) {
    collapseBtn.addEventListener('click', function () {
      setCollapsed(!document.body.classList.contains('sidebar-collapsed'));
    });
  }

  if (mobileToggle) {
    mobileToggle.addEventListener('click', function () {
      if (document.body.classList.contains('sidebar-open')) {
        closeMobileSidebar();
      } else {
        openMobileSidebar();
      }
    });
  }

  if (backdrop) {
    backdrop.addEventListener('click', closeMobileSidebar);
  }

  document.querySelectorAll('.sidebar .nav-links a').forEach(function (link) {
    link.addEventListener('click', closeMobileSidebar);
  });
})();

(function () {
  var params = new URLSearchParams(
    window.location.search
  );

  var notif = params.get('notificacao');

  if (notif) {
    try {
      eval(notif);
    } catch (e) {
    }
  }
})();
