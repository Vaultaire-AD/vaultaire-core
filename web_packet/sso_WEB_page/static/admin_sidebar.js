/**
 * Global search bar (admin): debounced fetch, dropdown results, navigate on click
 */
(function () {
  'use strict';

  var searchInput = document.getElementById('global-search');
  var searchResults = document.getElementById('search-results');
  if (!searchInput || !searchResults) return;

  var debounceTimer;
  var DEBOUNCE_MS = 250;

  function renderResults(data) {
    var html = '';
    if (data.users && data.users.length) {
      html += '<div class="search-result-section"><div class="search-result-section-title">Utilisateurs</div>';
      data.users.forEach(function (r) {
        html += '<a class="search-result-item" href="' + r.url + '">' + escapeHtml(r.name) + '</a>';
      });
      html += '</div>';
    }
    if (data.groups && data.groups.length) {
      html += '<div class="search-result-section"><div class="search-result-section-title">Groupes</div>';
      data.groups.forEach(function (r) {
        html += '<a class="search-result-item" href="' + r.url + '">' + escapeHtml(r.name) + '</a>';
      });
      html += '</div>';
    }
    if (data.clients && data.clients.length) {
      html += '<div class="search-result-section"><div class="search-result-section-title">Clients</div>';
      data.clients.forEach(function (r) {
        html += '<a class="search-result-item" href="' + r.url + '">' + escapeHtml(r.name) + '</a>';
      });
      html += '</div>';
    }
    if (data.permissions && data.permissions.length) {
      html += '<div class="search-result-section"><div class="search-result-section-title">Permissions</div>';
      data.permissions.forEach(function (r) {
        html += '<a class="search-result-item" href="' + r.url + '">' + escapeHtml(r.name) + '</a>';
      });
      html += '</div>';
    }
    if (!html) html = '<div class="search-result-section"><div class="search-result-section-title">Aucun résultat</div></div>';
    searchResults.innerHTML = html;
    searchResults.classList.add('is-open');
    searchResults.setAttribute('aria-hidden', 'false');
  }

  function escapeHtml(s) {
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function doSearch() {
    var q = searchInput.value.trim();
    if (q.length < 2) {
      searchResults.classList.remove('is-open');
      searchResults.innerHTML = '';
      return;
    }
    fetch('/admin/api/search?q=' + encodeURIComponent(q), { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(renderResults)
      .catch(function () {
        searchResults.innerHTML = '<div class="search-result-section"><div class="search-result-section-title">Erreur</div></div>';
        searchResults.classList.add('is-open');
      });
  }

  searchInput.addEventListener('input', function () {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(doSearch, DEBOUNCE_MS);
  });

  searchInput.addEventListener('focus', function () {
    if (searchResults.innerHTML) searchResults.classList.add('is-open');
  });

  document.addEventListener('click', function (e) {
    if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
      searchResults.classList.remove('is-open');
      searchResults.setAttribute('aria-hidden', 'true');
    }
  });
})();
