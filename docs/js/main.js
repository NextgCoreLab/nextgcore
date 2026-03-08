// NextGCore Documentation — Main JS

(function () {
  'use strict';

  // Mobile menu toggle
  const menuBtn = document.querySelector('.mobile-menu-btn');
  const navLinks = document.querySelector('.nav-links');
  if (menuBtn && navLinks) {
    menuBtn.addEventListener('click', () => {
      navLinks.classList.toggle('open');
      menuBtn.textContent = navLinks.classList.contains('open') ? '\u2715' : '\u2630';
    });
    // Close on link click
    navLinks.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('open');
        menuBtn.textContent = '\u2630';
      });
    });
  }

  // Active nav link on scroll
  const sections = document.querySelectorAll('section[id]');
  const navAnchors = document.querySelectorAll('.nav-links a[href^="#"]');

  function updateActiveNav() {
    const scrollY = window.scrollY + 100;
    sections.forEach(section => {
      const top = section.offsetTop;
      const height = section.offsetHeight;
      const id = section.getAttribute('id');
      if (scrollY >= top && scrollY < top + height) {
        navAnchors.forEach(a => {
          a.classList.toggle('active', a.getAttribute('href') === '#' + id);
        });
      }
    });
  }

  window.addEventListener('scroll', updateActiveNav, { passive: true });
  updateActiveNav();

  // Copy button for code blocks
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const code = btn.closest('.code-block').querySelector('code');
      const text = code.textContent;
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
      });
    });
  });

  // API spec loader (api.html only)
  const specSelect = document.getElementById('spec-select');
  const redocContainer = document.getElementById('redoc-container');

  if (specSelect && redocContainer) {
    // Options are inlined in the HTML — no fetch needed.
    // Auto-load the first spec on page load.
    var firstSpec = specSelect.querySelector('option[value]:not([value=""])');
    if (firstSpec) {
      specSelect.value = firstSpec.value;
      loadSpec(firstSpec.value);
    }

    specSelect.addEventListener('change', () => {
      if (specSelect.value) {
        loadSpec(specSelect.value);
      }
    });
  }

  function loadSpec(specFile) {
    if (!redocContainer) return;
    redocContainer.innerHTML = '<p style="padding:2rem;color:#94a3b8;">Loading specification...</p>';
    // eslint-disable-next-line no-undef
    if (typeof Redoc !== 'undefined') {
      Redoc.init(specFile, {
        theme: {
          colors: {
            primary: { main: '#6366f1' },
            text: { primary: '#e2e8f0', secondary: '#94a3b8' },
            http: {
              get: '#22c55e',
              post: '#6366f1',
              put: '#f59e0b',
              delete: '#ef4444',
              patch: '#06b6d4'
            }
          },
          typography: {
            fontSize: '14px',
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            code: { fontSize: '13px', fontFamily: '"SF Mono", "Fira Code", monospace' }
          },
          sidebar: {
            backgroundColor: '#0a0a0f',
            textColor: '#94a3b8',
            activeTextColor: '#6366f1'
          },
          rightPanel: { backgroundColor: '#12121a' },
          schema: { nestedBackground: '#1e1e2e' }
        },
        scrollYOffset: 64,
        hideDownloadButton: false,
        expandResponses: '200',
        pathInMiddlePanel: true,
        nativeScrollbars: true,
        disableSearch: false
      }, redocContainer);
    } else {
      redocContainer.innerHTML = '<p style="padding:2rem;color:#94a3b8;">ReDoc library not loaded.</p>';
    }
  }

})();
