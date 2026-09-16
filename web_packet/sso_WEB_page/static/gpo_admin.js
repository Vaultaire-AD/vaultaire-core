/**
 * gpo_admin.js — ergonomie des pages GPO
 *
 * Trois comportements, tous en amélioration progressive : la page reste
 * complète et utilisable sans ce script, simplement longue. C'est le script qui
 * ajoute la classe .gpo-js et déclenche le découpage en onglets (voir app.css).
 *
 *   1. Onglets            — une section visible à la fois
 *   2. Filtre de liste    — recherche sur les modules et sur le catalogue
 *   3. Sélecteur d'ajout  — un seul formulaire rendu, celui du type choisi
 *
 * Motivation : le catalogue passe d'environ 8 à près de 40 types de modules.
 * Rendre 40 formulaires dans la page, même repliés, la rend impraticable.
 */
(function () {
  'use strict';

  var root = document.querySelector('[data-gpo-page]');
  if (!root) { return; }

  // Signale au CSS que le script est actif : sans cette classe, les onglets
  // restent masqués et tous les panneaux visibles.
  root.classList.add('gpo-js');

  // -----------------------------------------------------------------------
  // 1. Onglets
  // -----------------------------------------------------------------------

  var tabs = Array.prototype.slice.call(root.querySelectorAll('[data-gpo-tab]'));
  var panels = Array.prototype.slice.call(root.querySelectorAll('[data-gpo-panel]'));

  // Les formulaires transportent l'onglet courant pour que le serveur le
  // rouvre après une action. Sans ça, chaque ajout de module ramènerait sur le
  // premier onglet.
  var tabInputs = Array.prototype.slice.call(root.querySelectorAll('input[name="active_tab"]'));

  function selectTab(name, remember) {
    // Un nom inconnu n'est pas appliqué : il peut venir d'un fragment d'URL
    // laissé par une autre page, et masquer alors tous les panneaux à la fois.
    var known = tabs.some(function (tab) { return tab.getAttribute('data-gpo-tab') === name; });
    if (!known) { return false; }

    tabs.forEach(function (tab) {
      tab.setAttribute('aria-selected', tab.getAttribute('data-gpo-tab') === name ? 'true' : 'false');
    });

    panels.forEach(function (panel) {
      panel.hidden = panel.getAttribute('data-gpo-panel') !== name;
    });
    tabInputs.forEach(function (input) { input.value = name; });

    if (remember) {
      // L'onglet vit dans le fragment d'URL : un rechargement, un signet ou un
      // retour arrière retrouvent la même vue, sans stockage persistant.
      try { history.replaceState(null, '', '#' + name); } catch (e) { /* sans effet */ }
    }
    return true;
  }

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      selectTab(tab.getAttribute('data-gpo-tab'), true);
    });
  });

  if (tabs.length) {
    // Priorité : fragment d'URL, puis onglet demandé par le serveur après une
    // action, puis le premier. Chaque candidat est essayé à son tour ; le
    // dernier existe toujours, donc un onglet finit forcément par s'ouvrir.
    var candidates = [
      (window.location.hash || '').replace('#', ''),
      root.getAttribute('data-gpo-active'),
      tabs[0].getAttribute('data-gpo-tab')
    ];
    for (var i = 0; i < candidates.length; i++) {
      if (candidates[i] && selectTab(candidates[i], false)) { break; }
    }
  }

  // -----------------------------------------------------------------------
  // 2. Filtres de liste
  // -----------------------------------------------------------------------

  /**
   * Branche un champ de recherche sur une liste d'éléments filtrables.
   *
   * Le texte de comparaison vient de l'attribut data-gpo-search. Il est mis en
   * minuscules une seule fois, au branchement : le refaire à chaque frappe
   * recalculerait la même chaîne des dizaines de fois pour rien.
   */
  function bindFilter(input) {
    var scope = document.getElementById(input.getAttribute('data-gpo-filter'));
    if (!scope) { return; }

    var items = Array.prototype.slice.call(scope.querySelectorAll('[data-gpo-search]'))
      .map(function (el) {
        return { el: el, text: (el.getAttribute('data-gpo-search') || '').toLowerCase() };
      });
    // Le message « aucun résultat » est cherché dans le panneau, pas dans la
    // liste : dans un tableau il est forcément en dehors du <tbody>, un <p> ne
    // pouvant pas y vivre.
    var panel = input.closest('[data-gpo-panel]') || root;
    var empty = panel.querySelector('[data-gpo-empty]');

    function apply() {
      var needle = input.value.trim().toLowerCase();
      var visible = 0;
      items.forEach(function (item) {
        var match = !needle || item.text.indexOf(needle) !== -1;
        item.el.hidden = !match;
        if (match) { visible++; }
      });
      if (empty) { empty.hidden = visible !== 0; }
    }

    input.addEventListener('input', apply);
    // Échap vide le champ : plus rapide que de sélectionner et effacer.
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { input.value = ''; apply(); }
    });
    apply();
  }

  Array.prototype.slice.call(root.querySelectorAll('[data-gpo-filter]')).forEach(bindFilter);

  // -----------------------------------------------------------------------
  // 3. Sélecteur du catalogue
  // -----------------------------------------------------------------------

  var catalogButtons = Array.prototype.slice.call(root.querySelectorAll('[data-gpo-pick]'));
  var catalogForms = Array.prototype.slice.call(root.querySelectorAll('[data-gpo-form]'));

  function pickModule(type) {
    catalogButtons.forEach(function (btn) {
      btn.setAttribute('aria-pressed', btn.getAttribute('data-gpo-pick') === type ? 'true' : 'false');
    });
    catalogForms.forEach(function (form) {
      form.hidden = form.getAttribute('data-gpo-form') !== type;
    });

    var active = root.querySelector('[data-gpo-form="' + type + '"]');
    if (!active) { return; }
    // Le focus part sur le premier champ saisissable : après avoir choisi un
    // type, on veut taper, pas chercher où cliquer.
    var first = active.querySelector('input:not([type=hidden]), select, textarea');
    if (first) { first.focus({ preventScroll: true }); }
  }

  catalogButtons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      pickModule(btn.getAttribute('data-gpo-pick'));
    });
  });

  // -----------------------------------------------------------------------
  // 4. Édition d'un module dans le tableau
  // -----------------------------------------------------------------------

  Array.prototype.slice.call(root.querySelectorAll('[data-gpo-edit]')).forEach(function (btn) {
    btn.addEventListener('click', function () {
      var row = document.getElementById(btn.getAttribute('data-gpo-edit'));
      if (!row) { return; }
      var opening = row.hidden;
      row.hidden = !opening;
      btn.setAttribute('aria-expanded', opening ? 'true' : 'false');
      btn.textContent = opening ? 'Fermer' : 'Modifier';
      if (opening) {
        var first = row.querySelector('input:not([type=hidden]), select, textarea');
        if (first) { first.focus({ preventScroll: true }); }
      }
    });
  });
})();
