/**
 * LDAP tree: domain blocks + group cards with expandable details (fetch group-info on open)
 */
(function () {
  var MOUNT = document.getElementById('ldap-tree-mount');
  var ROOT = document.getElementById('tree-root');
  var LOADING = document.getElementById('tree-loading');

  function renderDomainBlock(node) {
    var domainBlock = document.createElement('div');
    domainBlock.className = 'tree-domain-block';
    var domainHead = document.createElement('div');
    domainHead.className = 'domain-head';
    domainHead.textContent = node.full_domain || node.name;
    domainBlock.appendChild(domainHead);

    var domainGroups = document.createElement('div');
    domainGroups.className = 'domain-groups';

    if (node.groups && node.groups.length) {
      node.groups.forEach(function (grp) {
        var card = document.createElement('div');
        card.className = 'tree-group-card';
        card.setAttribute('data-group', grp.name);

        var head = document.createElement('div');
        head.className = 'group-head';
        var nameSpan = document.createElement('span');
        nameSpan.className = 'group-name';
        nameSpan.textContent = grp.name;
        var badge = document.createElement('span');
        badge.className = 'tree-badge';
        badge.textContent = (grp.users && grp.users.length) ? grp.users.length + ' user(s)' : '0 user';
        var toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'group-toggle';
        toggle.setAttribute('aria-label', 'Ouvrir');
        toggle.innerHTML = '▼';

        head.appendChild(nameSpan);
        head.appendChild(badge);
        head.appendChild(toggle);
        card.appendChild(head);

        var details = document.createElement('div');
        details.className = 'group-details';
        details.innerHTML = '<div class="loading">Chargement…</div>';
        card.appendChild(details);

        head.addEventListener('click', function () {
          var isOpen = card.classList.toggle('is-open');
          if (isOpen && details.querySelector('.loading')) {
            fetch('/admin/api/group-info?group=' + encodeURIComponent(grp.name), { credentials: 'same-origin' })
              .then(function (r) { return r.json(); })
              .then(function (info) {
                var html = '';
                if (info.users && info.users.length) {
                  html += '<h4>Utilisateurs</h4><ul>';
                  info.users.forEach(function (u) {
                    html += '<li><a href="/admin/users?user=' + encodeURIComponent(u) + '">' + escapeHtml(u) + '</a></li>';
                  });
                  html += '</ul>';
                } else {
                  html += '<h4>Utilisateurs</h4><ul><li class="muted">Aucun</li></ul>';
                }
                if (info.permissions && info.permissions.length) {
                  html += '<h4>Permissions</h4><ul>';
                  info.permissions.forEach(function (p) {
                    html += '<li><a href="/admin/permissions?perm=' + encodeURIComponent(p) + '">' + escapeHtml(p) + '</a></li>';
                  });
                  html += '</ul>';
                } else {
                  html += '<h4>Permissions</h4><ul><li class="muted">Aucune</li></ul>';
                }
                if (info.clients && info.clients.length) {
                  html += '<h4>Clients</h4><ul>';
                  info.clients.forEach(function (c) {
                    html += '<li><a href="/admin/clients?client=' + encodeURIComponent(c) + '">' + escapeHtml(c) + '</a></li>';
                  });
                  html += '</ul>';
                } else {
                  html += '<h4>Clients</h4><ul><li class="muted">Aucun</li></ul>';
                }
                details.innerHTML = html;
              })
              .catch(function () {
                details.innerHTML = '<p class="muted">Erreur chargement.</p>';
              });
          }
        });

        domainGroups.appendChild(card);
      });
    }

    domainBlock.appendChild(domainGroups);

    if (node.children && node.children.length) {
      node.children.forEach(function (child) {
        domainBlock.appendChild(renderDomainBlock(child));
      });
    }
    return domainBlock;
  }

  function escapeHtml(s) {
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function renderTree(data) {
    ROOT.innerHTML = '';
    ROOT.className = 'tree-blocks';
    if (!data.tree || data.tree.length === 0) {
      ROOT.innerHTML = '<p class="muted">Aucun domaine ou groupe.</p>';
      ROOT.style.display = 'block';
      if (LOADING) LOADING.style.display = 'none';
      return;
    }
    data.tree.forEach(function (node) {
      ROOT.appendChild(renderDomainBlock(node));
    });
    ROOT.style.display = 'block';
    if (LOADING) LOADING.style.display = 'none';
  }

  function loadTree() {
    if (LOADING) LOADING.style.display = 'block';
    ROOT.style.display = 'none';
    fetch('/admin/api/ldap-tree', { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error(r.statusText);
        return r.json();
      })
      .then(renderTree)
      .catch(function (err) {
        ROOT.innerHTML = '<p class="muted">Erreur : ' + (err.message || 'inconnue') + '</p>';
        ROOT.style.display = 'block';
        if (LOADING) LOADING.style.display = 'none';
      });
  }

  var refreshBtn = document.getElementById('tree-refresh');
  if (refreshBtn) refreshBtn.addEventListener('click', loadTree);

  loadTree();
})();
