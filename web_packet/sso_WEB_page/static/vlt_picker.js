/* ====================================================================
 * vlt_picker — sélecteur d'entités avec recherche, filtres et
 *              sélection multiple
 * ====================================================================
 *
 * Remplace les listes déroulantes natives qui portent des DONNÉES —
 * utilisateurs, clients, permissions, GPO, groupes — par un panneau
 * ouvrant sur un champ de recherche, des filtres et une liste cochable.
 *
 * Les listes d'ÉNUMÉRATION (Oui/Non, type d'enregistrement DNS, niveau de
 * journal) gardent volontairement le <select> natif : trois entrées fixes se
 * parcourent plus vite au clavier avec le contrôle du système qu'avec un
 * widget, et le natif est accessible sans qu'on ait rien à écrire.
 *
 * --------------------------------------------------------------------
 * Principe : on ENRICHIT le <select>, on ne le remplace pas
 * --------------------------------------------------------------------
 * Le <select> reste dans le formulaire et reste la source de vérité. Le
 * module le masque visuellement et construit le widget à côté ; toute
 * sélection est réécrite dans le <select>, qui est ce que le navigateur
 * soumet.
 *
 * Trois propriétés en découlent, qu'un widget « à base de <div> et d'inputs
 * cachés » n'aurait pas :
 *
 *   - sans JavaScript — erreur de chargement, script bloqué, navigateur
 *     ancien — la page reste utilisable : le CSS ne masque le <select> que
 *     lorsque le module a posé sa classe, donc jamais si le script n'a pas
 *     tourné ;
 *   - la validation du navigateur (`required`) continue de fonctionner ;
 *   - un <select multiple> soumet nativement plusieurs valeurs, sans qu'aucun
 *     champ caché n'ait à être fabriqué en JavaScript.
 *
 * --------------------------------------------------------------------
 * Sélection multiple
 * --------------------------------------------------------------------
 * `multiple` sur le <select> fait basculer le widget : cases à cocher, jetons
 * dans le bouton, compteur, et « Tout cocher » qui porte sur les options
 * FILTRÉES — chercher « paris », puis tout cocher, puis soumettre.
 *
 * Côté serveur, le formulaire doit DÉCLARER quel champ porte les cibles :
 *
 *     <input type="hidden" name="bulk_field" value="username">
 *     <select name="username" multiple data-vlt-picker>…</select>
 *
 * Sans cette déclaration, le pont ne retiendrait que la première valeur —
 * `parametresDepuisRequete` fait `p[nom] = valeurs[0]` — et les autres cibles
 * seraient perdues sans message ni journal. La déclaration est donc
 * OBLIGATOIRE partout où `multiple` est posé.
 *
 * Voir core/web_serveur/web_action_groupe.go : une exécution par cible, donc
 * un contrôle de droits par cible, et un compte rendu qui nomme les échecs.
 *
 * --------------------------------------------------------------------
 * Utilisation dans un gabarit
 * --------------------------------------------------------------------
 *
 *     <select name="username"
 *             data-vlt-picker
 *             data-placeholder="Choisir un utilisateur"
 *             data-search-placeholder="Rechercher un utilisateur…">
 *       {{ range .AllUsers }}
 *         <option value="{{ .Username }}">{{ .Username }}</option>
 *       {{ end }}
 *     </select>
 *
 * Attributs reconnus sur le <select> :
 *
 *   data-vlt-picker           active le module (valeur ignorée)
 *   data-placeholder          texte du bouton quand rien n'est choisi
 *   data-search-placeholder   texte du champ de recherche
 *   data-empty                texte affiché quand la recherche ne donne rien
 *   data-filters="off"        désactive la rangée de filtres
 *   data-search="always"      force le champ de recherche même sur liste courte
 *   data-search="off"         supprime le champ de recherche
 *   multiple                  sélection multiple — exige un champ caché
 *                             `bulk_field` dans le même formulaire
 *
 * Attributs reconnus sur les <option> :
 *
 *   data-tags="admin,paris"   étiquettes, qui deviennent des filtres cliquables
 *   data-hint="texte"         précision affichée en gris à droite du libellé
 *
 * Un <optgroup> vaut étiquette pour toutes les options qu'il contient : il
 * suffit de grouper dans le gabarit pour obtenir les filtres.
 *
 * --------------------------------------------------------------------
 * API
 * --------------------------------------------------------------------
 *
 *   VltPicker.init(racine)     enrichit les <select> non encore traités
 *   VltPicker.refresh(select)  relit les options (liste modifiée en JS)
 *   VltPicker.destroy(select)  rend la main au <select> natif
 *
 * L'initialisation est automatique au chargement du document. `init` est
 * idempotente : la rappeler sur une zone fraîchement injectée n'enrichit que
 * ce qui ne l'est pas déjà.
 * ==================================================================== */

(function (window, document) {
  'use strict';

  /* Sous ce nombre d'options, pas de champ de recherche : le chercher coûte
     plus de temps que parcourir la liste. Contournable par data-search. */
  var SEUIL_RECHERCHE = 8;

  /* Plafond de lignes construites en une passe. Un groupe de 5 000 comptes
     produirait 5 000 nœuds à chaque frappe et rendrait la saisie saccadée ;
     au-delà, on affiche un pied de liste qui invite à affiner. Les options
     non rendues restent sélectionnables : elles apparaissent dès que la
     recherche les ramène sous le plafond. */
  var MAX_AFFICHES = 200;

  var compteur = 0;
  var instances = [];

  /* ---------------------------------------------------------------- */
  /* Utilitaires                                                       */
  /* ---------------------------------------------------------------- */

  /* Repli de normalisation : « Élève » et « eleve » doivent se trouver
     mutuellement. NFD sépare la lettre de son accent, la plage U+0300-U+036F
     supprime les accents ainsi isolés.

     `normalize` manque sur les navigateurs très anciens ; le try/catch évite
     que toute la recherche tombe pour cette seule raison. */
  function aplatir(s) {
    s = String(s == null ? '' : s).toLowerCase();
    try {
      return s.normalize('NFD').replace(/[\u0300-\u036F]/g, '');
    } catch (e) {
      return s;
    }
  }

  function echapper(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* Surligne l'occurrence trouvée. Le calcul se fait sur la forme aplatie
     mais le découpage sur le texte D'ORIGINE : les deux ont la même longueur
     après NFD→suppression des diacritiques uniquement si l'on ne recompose
     pas, ce qui n'est pas garanti. On repasse donc par indexOf sur une copie
     aplatie caractère à caractère — d'où `aplatirParCaractere`. */
  function aplatirParCaractere(texte) {
    var sortie = '';
    var i;
    for (i = 0; i < texte.length; i++) {
      var c = aplatir(texte.charAt(i));
      /* Un caractère peut s'aplatir en rien (accent isolé) ou en plusieurs
         (ligature). On force la longueur à 1 pour que les index restent
         alignés sur le texte d'origine. */
      sortie += c.length === 1 ? c : (c.charAt(0) || ' ');
    }
    return sortie;
  }

  function surligner(texte, requete) {
    if (!requete) return echapper(texte);
    var plat = aplatirParCaractere(texte);
    var pos = plat.indexOf(requete);
    if (pos < 0) return echapper(texte);
    return echapper(texte.slice(0, pos)) +
      '<mark>' + echapper(texte.slice(pos, pos + requete.length)) + '</mark>' +
      echapper(texte.slice(pos + requete.length));
  }

  function creer(tag, classe, texte) {
    var el = document.createElement(tag);
    if (classe) el.className = classe;
    if (texte != null) el.textContent = texte;
    return el;
  }

  /* ---------------------------------------------------------------- */
  /* Construction d'une instance                                       */
  /* ---------------------------------------------------------------- */

  function Picker(select) {
    this.select = select;
    this.id = 'vltp' + (++compteur);
    this.multiple = select.multiple;
    this.ouvert = false;
    this.requete = '';
    this.filtresActifs = [];
    this.actif = -1;      // index (dans this.visibles) de la ligne survolée au clavier
    this.visibles = [];

    this.construire();
    this.lireOptions();
    this.rendreFiltres();
    this.majControle();

    select.setAttribute('data-vlt-picker-ready', '1');
    instances.push(this);
  }

  Picker.prototype.construire = function () {
    var select = this.select;
    var d = select.dataset || {};

    this.placeholder = d.placeholder || (this.multiple ? 'Aucune sélection' : 'Choisir…');
    this.texteVide = d.empty || 'Aucun résultat';

    var enveloppe = creer('div', 'vlt-picker');
    if (this.multiple) enveloppe.classList.add('vlt-picker--multiple');
    if (select.disabled) enveloppe.classList.add('vlt-picker--disabled');

    /* Le <select> est déplacé DANS l'enveloppe, et non retiré : il doit
       rester un descendant du <form> pour être soumis. Il est ensuite
       positionné en absolu sous le bouton, transparent, hauteur 1px.

       Pourquoi pas `display:none` : Chrome refuse de focaliser un contrôle
       invalide qui n'est pas affiché et abandonne la soumission en
       n'écrivant qu'un message dans la console — un `required` deviendrait
       un blocage silencieux. Transparent mais présent, la bulle de
       validation s'affiche au bon endroit. */
    select.parentNode.insertBefore(enveloppe, select);
    enveloppe.appendChild(select);
    select.classList.add('vlt-picker-native');
    select.setAttribute('tabindex', '-1');
    select.setAttribute('aria-hidden', 'true');

    var controle = creer('button', 'vlt-picker-control');
    /* type=button explicite : dans un <form>, un <button> sans type soumet. */
    controle.type = 'button';
    controle.id = this.id + '-ctl';
    controle.setAttribute('aria-haspopup', 'listbox');
    controle.setAttribute('aria-expanded', 'false');
    controle.setAttribute('aria-controls', this.id + '-panel');
    /* Nom accessible : le texte du bouton est la VALEUR choisie, pas
       l'intitulé du champ. Sans cet aria-label, un lecteur d'écran
       annoncerait « alice, bouton » sans jamais dire de quoi il s'agit.
       Les <label> des gabarits ne portent pas d'attribut `for`, ils ne
       peuvent donc pas jouer ce rôle. */
    controle.setAttribute('aria-label', this.placeholder);
    if (select.disabled) controle.disabled = true;

    var valeur = creer('span', 'vlt-picker-value');
    var fleche = creer('span', 'vlt-picker-caret');
    fleche.setAttribute('aria-hidden', 'true');
    fleche.textContent = '▾';
    controle.appendChild(valeur);
    controle.appendChild(fleche);

    var panneau = creer('div', 'vlt-picker-panel');
    panneau.id = this.id + '-panel';
    panneau.hidden = true;

    var zoneRecherche = creer('div', 'vlt-picker-search');
    var champ = creer('input', 'vlt-picker-input');
    champ.type = 'text';
    champ.autocomplete = 'off';
    champ.spellcheck = false;
    champ.placeholder = d.searchPlaceholder || 'Rechercher…';
    champ.setAttribute('role', 'combobox');
    champ.setAttribute('aria-expanded', 'true');
    champ.setAttribute('aria-autocomplete', 'list');
    champ.setAttribute('aria-controls', this.id + '-list');
    zoneRecherche.appendChild(champ);

    var filtres = creer('div', 'vlt-picker-filters');
    filtres.hidden = true;

    var barre = creer('div', 'vlt-picker-bulk');
    barre.hidden = !this.multiple;
    var compte = creer('span', 'vlt-picker-count', '');
    var btnTout = creer('button', 'vlt-picker-bulk-btn', 'Tout cocher');
    btnTout.type = 'button';
    btnTout.setAttribute('data-act', 'all');
    var btnAucun = creer('button', 'vlt-picker-bulk-btn', 'Effacer');
    btnAucun.type = 'button';
    btnAucun.setAttribute('data-act', 'none');
    barre.appendChild(compte);
    barre.appendChild(btnTout);
    barre.appendChild(btnAucun);

    var liste = creer('ul', 'vlt-picker-list');
    liste.id = this.id + '-list';
    liste.setAttribute('role', 'listbox');
    if (this.multiple) liste.setAttribute('aria-multiselectable', 'true');

    var pied = creer('div', 'vlt-picker-foot');
    pied.hidden = true;

    panneau.appendChild(zoneRecherche);
    panneau.appendChild(filtres);
    panneau.appendChild(barre);
    panneau.appendChild(liste);
    panneau.appendChild(pied);

    enveloppe.appendChild(controle);
    enveloppe.appendChild(panneau);

    this.el = {
      enveloppe: enveloppe, controle: controle, valeur: valeur,
      panneau: panneau, zoneRecherche: zoneRecherche, champ: champ,
      filtres: filtres, barre: barre, compte: compte,
      liste: liste, pied: pied
    };

    this.brancher();
  };

  /* ---------------------------------------------------------------- */
  /* Lecture des <option>                                              */
  /* ---------------------------------------------------------------- */

  Picker.prototype.lireOptions = function () {
    var select = this.select;
    var d = select.dataset || {};
    var options = [];
    var etiquettes = [];
    var vues = {};
    var i;

    for (i = 0; i < select.options.length; i++) {
      var o = select.options[i];
      var tags = [];

      if (o.dataset && o.dataset.tags) {
        o.dataset.tags.split(',').forEach(function (t) {
          t = t.trim();
          if (t) tags.push(t);
        });
      }
      /* Un <optgroup> vaut étiquette : grouper dans le gabarit suffit à
         obtenir un filtre, sans attribut supplémentaire. */
      if (o.parentNode && o.parentNode.tagName === 'OPTGROUP') {
        var lab = o.parentNode.label;
        if (lab && tags.indexOf(lab) < 0) tags.push(lab);
      }

      tags.forEach(function (t) {
        if (!vues[t]) { vues[t] = true; etiquettes.push(t); }
      });

      options.push({
        index: i,
        valeur: o.value,
        libelle: o.text,
        plat: aplatirParCaractere(o.text) + ' ' + aplatirParCaractere(o.value),
        hint: (o.dataset && o.dataset.hint) || '',
        tags: tags,
        desactivee: o.disabled,
        choisie: o.selected
      });
    }

    this.options = options;
    this.etiquettes = etiquettes.sort();

    /* Décision d'afficher le champ de recherche. `always`/`off` priment sur
       le seuil, pour les cas où l'auteur du gabarit sait ce qu'il fait. */
    var mode = d.search || '';
    this.avecRecherche = mode === 'always' ? true
      : mode === 'off' ? false
        : options.length >= SEUIL_RECHERCHE;
    this.el.zoneRecherche.hidden = !this.avecRecherche;

    this.avecFiltres = d.filters !== 'off' && this.etiquettes.length > 1;
  };

  /* ---------------------------------------------------------------- */
  /* Rendu                                                             */
  /* ---------------------------------------------------------------- */

  Picker.prototype.rendreFiltres = function () {
    var self = this;
    var zone = this.el.filtres;
    zone.innerHTML = '';
    zone.hidden = !this.avecFiltres;
    if (!this.avecFiltres) return;

    this.etiquettes.forEach(function (tag) {
      var chip = creer('button', 'vlt-picker-chip', tag);
      chip.type = 'button';
      chip.setAttribute('data-tag', tag);
      chip.setAttribute('aria-pressed', 'false');
      zone.appendChild(chip);
    });
  };

  Picker.prototype.filtrer = function () {
    var self = this;
    var q = this.requete;
    var actifs = this.filtresActifs;

    var retenues = this.options.filter(function (o) {
      if (q && o.plat.indexOf(q) < 0) return false;
      if (actifs.length) {
        /* OU entre les étiquettes cochées : cocher « admin » et « paris »
           montre les deux ensembles. Un ET les rendrait presque toujours
           vides, les étiquettes de ce produit étant exclusives. */
        var touche = actifs.some(function (t) { return o.tags.indexOf(t) >= 0; });
        if (!touche) return false;
      }
      return true;
    });

    /* Les correspondances en début de libellé remontent : chercher « adm »
       doit proposer « admin » avant « web_admin ». Tri stable sur le reste,
       pour que l'ordre voulu par le gabarit soit préservé. */
    if (q) {
      retenues.sort(function (a, b) {
        var pa = a.plat.indexOf(q) === 0 ? 0 : 1;
        var pb = b.plat.indexOf(q) === 0 ? 0 : 1;
        if (pa !== pb) return pa - pb;
        return a.index - b.index;
      });
    }
    return retenues;
  };

  Picker.prototype.rendreListe = function () {
    var self = this;
    var liste = this.el.liste;
    var retenues = this.filtrer();
    this.visibles = retenues.slice(0, MAX_AFFICHES);

    liste.innerHTML = '';

    if (!retenues.length) {
      var vide = creer('li', 'vlt-picker-empty', this.texteVide);
      vide.setAttribute('role', 'presentation');
      liste.appendChild(vide);
    } else {
      var frag = document.createDocumentFragment();
      this.visibles.forEach(function (o, rang) {
        var li = creer('li', 'vlt-picker-option');
        li.setAttribute('role', 'option');
        li.id = self.id + '-o' + o.index;
        li.setAttribute('data-index', String(o.index));
        li.setAttribute('aria-selected', o.choisie ? 'true' : 'false');
        if (o.choisie) li.classList.add('is-selected');
        if (o.desactivee) {
          li.classList.add('is-disabled');
          li.setAttribute('aria-disabled', 'true');
        }
        if (rang === self.actif) li.classList.add('is-active');

        var coche = creer('span', 'vlt-picker-check');
        coche.setAttribute('aria-hidden', 'true');
        li.appendChild(coche);

        var lab = creer('span', 'vlt-picker-label');
        lab.innerHTML = surligner(o.libelle, self.requete);
        li.appendChild(lab);

        if (o.hint) li.appendChild(creer('span', 'vlt-picker-hint', o.hint));

        if (o.tags.length) {
          var boite = creer('span', 'vlt-picker-tags');
          o.tags.forEach(function (t) { boite.appendChild(creer('span', 'vlt-picker-tag', t)); });
          li.appendChild(boite);
        }
        frag.appendChild(li);
      });
      liste.appendChild(frag);
    }

    var reste = retenues.length - this.visibles.length;
    this.el.pied.hidden = reste <= 0;
    if (reste > 0) {
      this.el.pied.textContent = reste + ' autre' + (reste > 1 ? 's' : '') +
        ' résultat' + (reste > 1 ? 's' : '') + ' — affinez la recherche.';
    }

    this.majActiveDescendant();
    this.majBarre();
  };

  Picker.prototype.majBarre = function () {
    if (!this.multiple) return;
    var n = this.options.filter(function (o) { return o.choisie; }).length;
    this.el.compte.textContent = n === 0 ? 'Aucune sélection'
      : n + ' sélectionné' + (n > 1 ? 's' : '');
  };

  Picker.prototype.majControle = function () {
    var choisies = this.options.filter(function (o) { return o.choisie; });
    var valeur = this.el.valeur;
    valeur.innerHTML = '';

    if (!choisies.length) {
      valeur.appendChild(creer('span', 'vlt-picker-placeholder', this.placeholder));
      return;
    }

    if (!this.multiple) {
      valeur.appendChild(creer('span', 'vlt-picker-single', choisies[0].libelle));
      return;
    }

    /* Au-delà de trois jetons le bouton s'allonge sans rien apprendre :
       on montre les trois premiers et le reste en compteur. */
    var MAX_JETONS = 3;
    var self = this;
    choisies.slice(0, MAX_JETONS).forEach(function (o) {
      var jeton = creer('span', 'vlt-picker-pill');
      jeton.appendChild(creer('span', 'vlt-picker-pill-text', o.libelle));
      var croix = creer('span', 'vlt-picker-pill-x', '×');
      croix.setAttribute('data-index', String(o.index));
      croix.setAttribute('role', 'button');
      croix.setAttribute('aria-label', 'Retirer ' + o.libelle);
      jeton.appendChild(croix);
      valeur.appendChild(jeton);
    });
    if (choisies.length > MAX_JETONS) {
      valeur.appendChild(creer('span', 'vlt-picker-more',
        '+' + (choisies.length - MAX_JETONS)));
    }
  };

  Picker.prototype.majActiveDescendant = function () {
    var o = this.visibles[this.actif];
    if (o) this.el.champ.setAttribute('aria-activedescendant', this.id + '-o' + o.index);
    else this.el.champ.removeAttribute('aria-activedescendant');
  };

  /* ---------------------------------------------------------------- */
  /* Sélection                                                         */
  /* ---------------------------------------------------------------- */

  Picker.prototype.choisir = function (index, force) {
    var o = null;
    var i;
    for (i = 0; i < this.options.length; i++) {
      if (this.options[i].index === index) { o = this.options[i]; break; }
    }
    if (!o || o.desactivee) return;

    if (this.multiple) {
      o.choisie = force == null ? !o.choisie : !!force;
    } else {
      this.options.forEach(function (x) { x.choisie = false; });
      o.choisie = true;
    }
    this.appliquer();

    if (!this.multiple) this.fermer(true);
    else this.rendreListe();
  };

  /* Réécrit la sélection dans le <select> — le seul état que le formulaire
     soumettra — puis émet `change`. L'événement bulle : du code tiers déjà
     branché sur le <select> continue de fonctionner sans le savoir. */
  Picker.prototype.appliquer = function () {
    var select = this.select;
    this.options.forEach(function (o) {
      if (select.options[o.index]) select.options[o.index].selected = o.choisie;
    });
    this.majControle();
    this.majBarre();
    try {
      var evt = new Event('change', { bubbles: true });
      evt.__vltPicker = true;
      select.dispatchEvent(evt);
    } catch (e) {
      /* Repli pour les navigateurs sans constructeur Event. */
      var ev = document.createEvent('HTMLEvents');
      ev.initEvent('change', true, false);
      ev.__vltPicker = true;
      select.dispatchEvent(ev);
    }
  };

  Picker.prototype.toutCocher = function (etat) {
    if (!this.multiple) return;
    /* Porte sur les options FILTRÉES, pas sur toutes : c'est le geste utile —
       chercher « paris », puis tout cocher. Cocher les 4 000 comptes du parc
       n'est jamais ce qu'on veut. */
    var cibles = this.filtrer();
    if (!etat) {
      /* « Effacer » décoche tout, filtre compris : sinon une sélection faite
         sous un autre filtre resterait, invisible, et partirait au serveur. */
      this.options.forEach(function (o) { o.choisie = false; });
    } else {
      cibles.forEach(function (o) { if (!o.desactivee) o.choisie = true; });
    }
    this.appliquer();
    this.rendreListe();
  };

  /* ---------------------------------------------------------------- */
  /* Ouverture / fermeture                                             */
  /* ---------------------------------------------------------------- */

  Picker.prototype.ouvrir = function () {
    if (this.ouvert || this.select.disabled) return;
    fermerLesAutres(this);
    this.ouvert = true;
    this.el.enveloppe.classList.add('is-open');
    this.el.panneau.hidden = false;
    this.el.controle.setAttribute('aria-expanded', 'true');

    /* Position : sous le bouton par défaut, au-dessus s'il n'y a pas la
       place. Sans ça, une liste ouverte en bas de page s'affiche hors écran
       et donne l'impression que le clic n'a rien fait. */
    this.el.enveloppe.classList.remove('is-above');
    var r = this.el.controle.getBoundingClientRect();
    var h = this.el.panneau.offsetHeight || 320;
    if (r.bottom + h > window.innerHeight && r.top > h) {
      this.el.enveloppe.classList.add('is-above');
    }

    /* Position de départ du curseur clavier : la ligne déjà choisie, pour
       que ↓ parte de là et non du haut de la liste. */
    this.requete = '';
    this.el.champ.value = '';
    this.rendreListe();
    var self = this;
    this.actif = -1;
    this.visibles.some(function (o, i) {
      if (o.choisie) { self.actif = i; return true; }
      return false;
    });
    if (this.actif < 0 && this.visibles.length) this.actif = 0;
    this.rendreListe();
    this.defilerVersActif();

    if (this.avecRecherche) this.el.champ.focus();
  };

  Picker.prototype.fermer = function (rendreFocus) {
    if (!this.ouvert) return;
    this.ouvert = false;
    this.el.enveloppe.classList.remove('is-open', 'is-above');
    this.el.panneau.hidden = true;
    this.el.controle.setAttribute('aria-expanded', 'false');
    if (rendreFocus) this.el.controle.focus();
  };

  function fermerLesAutres(sauf) {
    instances.forEach(function (p) { if (p !== sauf) p.fermer(false); });
  }

  Picker.prototype.defilerVersActif = function () {
    var o = this.visibles[this.actif];
    if (!o) return;
    var li = this.el.liste.querySelector('#' + this.id + '-o' + o.index);
    if (!li) return;
    var liste = this.el.liste;
    if (li.offsetTop < liste.scrollTop) {
      liste.scrollTop = li.offsetTop;
    } else if (li.offsetTop + li.offsetHeight > liste.scrollTop + liste.clientHeight) {
      liste.scrollTop = li.offsetTop + li.offsetHeight - liste.clientHeight;
    }
  };

  Picker.prototype.deplacer = function (pas) {
    if (!this.visibles.length) return;
    var n = this.visibles.length;
    var i = this.actif;
    var tours = 0;
    do {
      i = (i + pas + n) % n;
      tours++;
    } while (this.visibles[i].desactivee && tours <= n);
    this.actif = i;
    this.rendreListe();
    this.defilerVersActif();
  };

  /* ---------------------------------------------------------------- */
  /* Événements                                                        */
  /* ---------------------------------------------------------------- */

  Picker.prototype.brancher = function () {
    var self = this;
    var el = this.el;

    el.controle.addEventListener('click', function (e) {
      /* Clic sur la croix d'un jeton : retirer, sans ouvrir le panneau. */
      var x = e.target.closest ? e.target.closest('.vlt-picker-pill-x') : null;
      if (x) {
        e.stopPropagation();
        self.choisir(parseInt(x.getAttribute('data-index'), 10), false);
        return;
      }
      if (self.ouvert) self.fermer(true); else self.ouvrir();
    });

    el.controle.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        self.ouvrir();
      }
    });

    el.champ.addEventListener('input', function () {
      self.requete = aplatirParCaractere(el.champ.value.trim().toLowerCase());
      self.actif = 0;
      self.rendreListe();
      self.el.liste.scrollTop = 0;
    });

    el.champ.addEventListener('keydown', function (e) {
      switch (e.key) {
        case 'ArrowDown': e.preventDefault(); self.deplacer(1); break;
        case 'ArrowUp': e.preventDefault(); self.deplacer(-1); break;
        case 'Home': e.preventDefault(); self.actif = 0; self.rendreListe(); self.defilerVersActif(); break;
        case 'End': e.preventDefault(); self.actif = self.visibles.length - 1; self.rendreListe(); self.defilerVersActif(); break;
        case 'Enter':
          e.preventDefault();
          /* Toujours préventé, même sans ligne active : sans ça, Entrée dans
             le champ de recherche soumettrait le formulaire qui entoure le
             widget — donc « Ajouter » avec l'ancienne valeur. */
          var o = self.visibles[self.actif];
          if (o) self.choisir(o.index);
          break;
        case 'Escape': e.preventDefault(); self.fermer(true); break;
        case 'Tab': self.fermer(false); break;
      }
    });

    /* mousedown préventé : sans ça le champ de recherche perd le focus avant
       que le click ne parte, et le panneau se referme sur un blur. */
    el.liste.addEventListener('mousedown', function (e) { e.preventDefault(); });

    el.liste.addEventListener('click', function (e) {
      var li = e.target.closest ? e.target.closest('.vlt-picker-option') : null;
      if (!li || li.classList.contains('is-disabled')) return;
      self.choisir(parseInt(li.getAttribute('data-index'), 10));
    });

    el.filtres.addEventListener('mousedown', function (e) { e.preventDefault(); });
    el.filtres.addEventListener('click', function (e) {
      var chip = e.target.closest ? e.target.closest('.vlt-picker-chip') : null;
      if (!chip) return;
      var tag = chip.getAttribute('data-tag');
      var i = self.filtresActifs.indexOf(tag);
      if (i >= 0) self.filtresActifs.splice(i, 1); else self.filtresActifs.push(tag);
      chip.setAttribute('aria-pressed', i >= 0 ? 'false' : 'true');
      chip.classList.toggle('is-on', i < 0);
      self.actif = 0;
      self.rendreListe();
    });

    el.barre.addEventListener('mousedown', function (e) { e.preventDefault(); });
    el.barre.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('.vlt-picker-bulk-btn') : null;
      if (!b) return;
      self.toutCocher(b.getAttribute('data-act') === 'all');
    });

    /* Le <select> natif est invisible mais reste focalisable par du code
       tiers — gpo_admin.js fait `querySelector('input, select, textarea')
       .focus()` après avoir déplié un formulaire — et par un <label for>.
       Sans ce renvoi, le focus disparaîtrait à l'écran. */
    this.select.addEventListener('focus', function () {
      if (!self.ouvert) el.controle.focus();
    });

    /* Une modification du <select> par du code extérieur doit se voir. */
    this.select.addEventListener('change', function (e) {
      if (e.__vltPicker) return;
      self.synchroniserDepuisSelect();
    });
  };

  Picker.prototype.synchroniserDepuisSelect = function () {
    var select = this.select;
    this.options.forEach(function (o) {
      if (select.options[o.index]) o.choisie = select.options[o.index].selected;
    });
    this.majControle();
    if (this.ouvert) this.rendreListe();
  };

  /* ---------------------------------------------------------------- */
  /* Cycle de vie                                                      */
  /* ---------------------------------------------------------------- */

  Picker.prototype.refresh = function () {
    this.lireOptions();
    this.rendreFiltres();
    this.majControle();
    if (this.ouvert) this.rendreListe();
  };

  Picker.prototype.destroy = function () {
    var env = this.el.enveloppe;
    var select = this.select;
    select.classList.remove('vlt-picker-native');
    select.removeAttribute('tabindex');
    select.removeAttribute('aria-hidden');
    select.removeAttribute('data-vlt-picker-ready');
    env.parentNode.insertBefore(select, env);
    env.parentNode.removeChild(env);
    var i = instances.indexOf(this);
    if (i >= 0) instances.splice(i, 1);
  };

  /* ---------------------------------------------------------------- */
  /* API publique                                                      */
  /* ---------------------------------------------------------------- */

  function init(racine) {
    var portee = racine || document;
    var cibles = portee.querySelectorAll('select[data-vlt-picker]:not([data-vlt-picker-ready])');
    var i;
    for (i = 0; i < cibles.length; i++) {
      try {
        new Picker(cibles[i]);
      } catch (e) {
        /* Un widget qui échoue ne doit pas emporter les autres, ni la page.
           Le <select> reste alors natif : dégradé, mais utilisable. */
        if (window.console && console.error) {
          console.error('vlt_picker : initialisation impossible', cibles[i], e);
        }
      }
    }
  }

  function trouver(select) {
    var i;
    for (i = 0; i < instances.length; i++) {
      if (instances[i].select === select) return instances[i];
    }
    return null;
  }

  document.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('.vlt-picker')) return;
    fermerLesAutres(null);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') fermerLesAutres(null);
  });

  window.VltPicker = {
    init: init,
    refresh: function (select) { var p = trouver(select); if (p) p.refresh(); },
    destroy: function (select) { var p = trouver(select); if (p) p.destroy(); }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { init(document); });
  } else {
    init(document);
  }

})(window, document);
