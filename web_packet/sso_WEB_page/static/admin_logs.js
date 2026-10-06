/* Page Journal du portail. Sorti d'un script en ligne de admin_logs.html : la
   Content-Security-Policy du portail interdit tout script en ligne (TO-DO 103). */
(function () {
'use strict';
  // La page ne filtre rien elle-même : elle transmet les champs à
  // /admin/api/logs, qui appelle l'action log.list — la même que « vlt logs ».
  // Deux filtres, l'un en JavaScript et l'autre en Go, finiraient par ne plus
  // rendre les mêmes lignes.
  let page = 1;
  let autoRefreshInterval = null;

  function formatTimestamp(ts) {
    const d = new Date(ts);
    return d.toLocaleString('fr-FR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text == null ? '' : String(text);
    return div.innerHTML;
  }

  function params() {
    const p = new URLSearchParams();
    const champs = { level: 'level-filter', core: 'core-filter', code: 'code-filter',
                     per_page: 'per-page-filter' };
    for (const [nom, id] of Object.entries(champs)) {
      const v = document.getElementById(id).value.trim();
      if (v) p.append(nom, v);
    }
    // Un champ datetime-local est à l'heure du NAVIGATEUR, sans fuseau. Le
    // core, lui, lirait « 14:30 » à SON heure — souvent UTC dans un
    // conteneur — et la période serait décalée sans que rien ne le montre.
    // On envoie donc un instant complet, en RFC 3339.
    for (const [nom, id] of [['since', 'since-filter'], ['until', 'until-filter']]) {
      const v = document.getElementById(id).value;
      if (v) p.append(nom, new Date(v).toISOString());
    }
    p.append('page', page);
    return p;
  }

  // Garnit la liste des cores sans perdre la sélection en cours : un core
  // choisi qui disparaîtrait de la liste à l'actualisation changerait le
  // filtre sans qu'on l'ait touché.
  function garnirCores(cores) {
    const select = document.getElementById('core-filter');
    const choisi = select.value;
    const connus = new Set(Array.from(select.options).map(o => o.value));
    (cores || []).forEach(c => {
      if (!connus.has(c)) {
        const o = document.createElement('option');
        o.value = c; o.textContent = c;
        select.appendChild(o);
      }
    });
    select.value = choisi;
  }

  function afficher(data) {
    const warning = document.getElementById('log-warning');
    if (data.source === 'memoire') {
      warning.textContent = data.avertissement;
      warning.hidden = false;
    } else {
      warning.hidden = true;
    }
    garnirCores(data.cores);

    const container = document.getElementById('log-container');
    const lignes = data.lignes || [];
    if (lignes.length === 0) {
      container.innerHTML = '<div class="loading">Aucune ligne pour ce filtre.</div>';
    } else {
      container.innerHTML = '<table class="log-table"><thead><tr>' +
        '<th>Quand</th><th>Core</th><th>Niveau</th><th>Code</th><th>Message</th>' +
        '</tr></thead><tbody>' +
        lignes.map(l => `<tr class="level-${escapeHtml(l.level)}">
          <td class="log-when">${escapeHtml(formatTimestamp(l.timestamp))}</td>
          <td class="log-core">${escapeHtml(l.hostname)}</td>
          <td class="log-level">${escapeHtml(l.level)}</td>
          <td class="log-code">${escapeHtml(l.code || '')}</td>
          <td class="log-message">${escapeHtml(l.message)}</td>
        </tr>`).join('') +
        '</tbody></table>';
    }

    document.getElementById('page-label').textContent = 'Page ' + data.page;
    document.getElementById('page-prev').disabled = data.page <= 1;
    document.getElementById('page-next').disabled = !data.suivante;
  }

  function loadLogs() {
    const erreur = document.getElementById('log-error');
    fetch('/admin/api/logs?' + params().toString(), { cache: 'no-store' })
      .then(r => r.json().then(data => ({ ok: r.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) {
          erreur.textContent = data.erreur || 'Lecture du journal refusée.';
          erreur.hidden = false;
          return;
        }
        erreur.hidden = true;
        afficher(data);
      })
      .catch(err => {
        erreur.textContent = 'Erreur : ' + err.message;
        erreur.hidden = false;
      });
  }

  document.getElementById('apply-filters').addEventListener('click', function() {
    page = 1;
    loadLogs();
  });
  document.getElementById('page-prev').addEventListener('click', function() {
    if (page > 1) { page--; loadLogs(); }
  });
  document.getElementById('page-next').addEventListener('click', function() {
    page++;
    loadLogs();
  });

  // L'auto-actualisation ramène à la PAGE 1 : actualiser une page ancienne
  // la ferait glisser à mesure que de nouvelles lignes arrivent, et on
  // lirait deux fois les mêmes lignes.
  document.getElementById('auto-refresh').addEventListener('click', function() {
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
      this.textContent = 'Auto-actualisation';
      this.classList.remove('btn-primary');
      this.classList.add('btn-ghost');
    } else {
      page = 1;
      loadLogs();
      autoRefreshInterval = setInterval(function() { page = 1; loadLogs(); }, 5000);
      this.textContent = 'Arrêter l\'auto-actualisation';
      this.classList.remove('btn-ghost');
      this.classList.add('btn-primary');
    }
  });

  loadLogs();
})();
