/**
 * Vaultaire — theme (cookie + localStorage), section dropdown, right-click context menu, drawer panel
 */
(function () {
  'use strict';

  var COOKIE_NAME = 'vaultaire-theme';
  var COOKIE_MAX_AGE_DAYS = 365;

  function getThemeFromCookie() {
    var match = document.cookie.match(new RegExp('(?:^|;\\s*)' + COOKIE_NAME + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
  }

  function setThemeCookie(theme) {
    var maxAge = COOKIE_MAX_AGE_DAYS * 24 * 60 * 60;
    document.cookie = COOKIE_NAME + '=' + encodeURIComponent(theme) + '; path=/; max-age=' + maxAge + '; SameSite=Lax';
  }

  function getSavedTheme() {
    var fromCookie = getThemeFromCookie();
    if (fromCookie === 'dark' || fromCookie === 'light') return fromCookie;
    var fromStorage = localStorage.getItem(COOKIE_NAME);
    if (fromStorage === 'dark' || fromStorage === 'light') return fromStorage;
    return 'light';
  }

  function applyTheme(theme) {
    if (theme === 'dark') document.body.classList.add('dark');
    else document.body.classList.remove('dark');
  }

  function saveTheme(theme) {
    setThemeCookie(theme);
    try { localStorage.setItem(COOKIE_NAME, theme); } catch (e) {}
  }

  function initTheme() {
    var saved = getSavedTheme();
    applyTheme(saved);
  }
  initTheme();
  document.addEventListener('DOMContentLoaded', initTheme);

  var themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      var isDark = document.body.classList.toggle('dark');
      var theme = isDark ? 'dark' : 'light';
      saveTheme(theme);
    });
  }

  var container = document.querySelector('.app-container, .profil-container, .login-card');
  if (container && !container.classList.contains('animate-in')) {
    container.classList.add('animate-in');
  }

  document.addEventListener('mouseover', function (e) {
    var btn = e.target.closest('.btn');
    if (btn && !btn.disabled) btn.style.transform = 'translateY(-1px)';
  });
  document.addEventListener('mouseout', function (e) {
    var btn = e.target.closest('.btn');
    if (btn) btn.style.transform = '';
  });

  // ——— Section dropdown (same on all pages): navigate on change
  var sectionDropdown = document.getElementById('section-dropdown');
  if (sectionDropdown) {
    sectionDropdown.addEventListener('change', function () {
      var url = this.value;
      if (url) window.location.href = url;
    });
  }

  // ——— Right-click context menu (vCenter-style)
  var contextMenu = document.getElementById('context-menu');
  var drawerBackdrop = document.getElementById('drawer-backdrop');
  var drawerPanel = document.getElementById('drawer-panel');
  var drawerTitle = document.getElementById('drawer-title');
  var drawerFrame = document.getElementById('drawer-frame');
  var drawerClose = document.getElementById('drawer-close');

  function openContextMenu(x, y, href, label) {
    if (!contextMenu) return;
    contextMenu.classList.add('is-open');
    contextMenu.style.left = x + 'px';
    contextMenu.style.top = y + 'px';
    contextMenu.dataset.href = href || '';
    contextMenu.dataset.label = label || 'Détail';

    var btnOpen = contextMenu.querySelector('[data-action="open-panel"]');
    var linkOpen = contextMenu.querySelector('[data-action="open-page"]');
    if (btnOpen) btnOpen.onclick = function () { openDrawer(href, label); closeContextMenu(); };
    if (linkOpen) linkOpen.href = href || '#';
  }

  function closeContextMenu() {
    if (contextMenu) contextMenu.classList.remove('is-open');
  }

  function openDrawer(url, title) {
    if (!drawerBackdrop || !drawerFrame) return;
    if (title && drawerTitle) drawerTitle.textContent = title;
    drawerFrame.src = url;
    drawerBackdrop.classList.add('is-open');
  }

  function closeDrawer() {
    if (drawerBackdrop) drawerBackdrop.classList.remove('is-open');
    if (drawerFrame) drawerFrame.src = 'about:blank';
  }

  document.addEventListener('contextmenu', function (e) {
    var row = e.target.closest('tr.row-context') || e.target.closest('li.row-context');
    if (row) {
      e.preventDefault();
      var href = row.getAttribute('data-href');
      var label = row.getAttribute('data-label') || 'Détail';
      if (href) openContextMenu(e.pageX, e.pageY, href, label);
    }
  });

  document.addEventListener('click', function () {
    closeContextMenu();
  });

  if (drawerBackdrop) {
    drawerBackdrop.addEventListener('click', function (e) {
      if (e.target === drawerBackdrop) closeDrawer();
    });
  }
  if (drawerClose) drawerClose.addEventListener('click', closeDrawer);
})();
