# Sélecteur d'entités du portail web (`vlt_picker`)

Module JavaScript qui remplace les listes déroulantes natives portant des
**données** — utilisateurs, clients, permissions, GPO, groupes — par un panneau
avec recherche, filtres et sélection multiple.

| | |
| --- | --- |
| Script | [`web_packet/sso_WEB_page/static/vlt_picker.js`](../../web_packet/sso_WEB_page/static/vlt_picker.js) |
| Styles | [`web_packet/sso_WEB_page/static/vlt_picker.css`](../../web_packet/sso_WEB_page/static/vlt_picker.css) |
| Tests navigateur | [`web_packet/sso_WEB_page/tests/vlt_picker.test.js`](../../web_packet/sso_WEB_page/tests/vlt_picker.test.js) |
| Exécution groupée | [`core/web_serveur/web_action_groupe.go`](../../src/vaultaire_serveur/core/web_serveur/web_action_groupe.go) |
| Tests serveur | [`core/web_serveur/web_action_groupe_test.go`](../../src/vaultaire_serveur/core/web_serveur/web_action_groupe_test.go) |
| Dépendances | aucune |

---

## Ce qu'il fait

- **Recherche** insensible à la casse et aux accents (« celine » trouve
  « Céline »), portant sur le libellé et sur la valeur, avec surlignage de
  l'occurrence. Les correspondances en début de mot remontent en tête.
- **Filtres** cliquables, déduits des étiquettes portées par les options.
- **Sélection multiple** avec jetons, compteur et « Tout cocher » portant sur
  les options filtrées : chercher « paris », tout cocher, soumettre une fois.
- **Clavier complet** : `↓` `↑` `Début` `Fin` `Entrée` `Échap` `Tab`.
- **Thème sombre** sans une ligne de CSS supplémentaire : tout passe par les
  variables de `app.css`.

---

## Où il est appliqué

Seules les listes de **données** sont concernées. Les **énumérations** gardent
le `<select>` natif : trois entrées fixes se parcourent plus vite au clavier
avec le contrôle du système, et le natif est accessible sans qu'on écrive quoi
que ce soit.

| Gabarit | Listes enrichies | Groupées |
| --- | --- | --- |
| `admin_group_detail.html` | 10 — utilisateurs, clients, permissions, permissions client, GPO (ajout et retrait) | 10 |
| `admin_user_detail.html` | 2 — ajout et retrait de groupe | 2 |
| `admin_gpo_detail.html` | 1 — lier à des groupes | 1 |
| `admin_enroll.html` | 1 — type de service | — |

Soit **14 listes enrichies**, dont **13 en sélection groupée**.

Restent en natif, volontairement : `is_serveur`, `record_type`,
`level-filter`, `kill_reason` (×2), `scope` (×2), `mode`, `rule_type`,
`propagation`, et les champs `p_*` d'énumération des GPO — soit onze listes.

Le script et la feuille de style sont chargés sur **toutes** les pages
d'application (`admin_*`, `profil*`), pas seulement sur les quatre concernées :
une nouvelle liste n'a ainsi qu'un attribut à porter. Les pages
d'authentification (`sso_login`, `login_mfa`) en sont exclues, faute d'y avoir
la moindre liste.

---

## Utilisation dans un gabarit

```html
<select name="username"
        data-vlt-picker
        data-placeholder="Choisir un utilisateur"
        data-search-placeholder="Rechercher un utilisateur…"
        data-empty="Aucun utilisateur ne correspond">
  {{ range .AllUsers }}
    <option value="{{ .Username }}">{{ .Username }}</option>
  {{ end }}
</select>
```

### Attributs du `<select>`

| Attribut | Effet |
| --- | --- |
| `data-vlt-picker` | active le module |
| `data-placeholder` | texte du bouton quand rien n'est choisi ; sert aussi de nom accessible |
| `data-search-placeholder` | texte du champ de recherche |
| `data-empty` | texte affiché quand la recherche ne donne rien |
| `data-filters="off"` | supprime la rangée de filtres |
| `data-search="always"` \| `"off"` | force ou supprime le champ de recherche |
| `multiple` | sélection multiple — **exige un `bulk_field`, voir ci-dessous** |

Le champ de recherche apparaît automatiquement à partir de **8 options**.

### Attributs des `<option>`

| Attribut | Effet |
| --- | --- |
| `data-tags="admin,paris"` | étiquettes, qui deviennent des filtres cliquables |
| `data-hint="texte"` | précision affichée en gris à droite du libellé |

Un `<optgroup>` vaut étiquette pour toutes les options qu'il contient : grouper
dans le gabarit suffit à obtenir les filtres.

Exemple réel, dans `admin_group_detail.html` — deux étiquettes isolent d'un
clic les permissions qui donnent l'administration de la machine :

```html
<option value="{{ .Name }}" data-tags="{{ if .IsAdmin }}admin{{ else }}standard{{ end }}">
```

### Chargement

```html
<link rel="stylesheet" href="/static/vlt_picker.css">   <!-- après app.css -->
<script src="/static/vlt_picker.js"></script>            <!-- après app.js -->
```

> ⚠️ **Les gabarits et les fichiers statiques vivent en double.** `web_packet/`
> est la source ; `cmd/web_packet/` en est une copie que `auto-compil.sh`
> régénère à chaque compilation, et c'est elle que sert le binaire déployé.
> Une modification de gabarit reste donc invisible tant que `auto-compil.sh`
> (ou `deployments/pre-prod/deploy.sh`) n'a pas tourné. Le test
> `TestToutesLesActionsDesGabaritsSontRoutees` lit lui aussi la copie de
> `cmd/`, et jugerait donc une version périmée.

---

## Sélection multiple et exécution groupée

Deux moitiés indissociables : `multiple` côté gabarit, `bulk_field` côté
formulaire. Poser la première sans la seconde produit une perte silencieuse.

```html
<form method="post" action="/admin/groups?group={{ .Group }}">
  <input type="hidden" name="action" value="add_user">
  <input type="hidden" name="bulk_field" value="username">
  <input type="hidden" name="target_group" value="{{ .Group }}">
  <label>Ajouter des utilisateurs</label>
  <select name="username" multiple data-vlt-picker>…</select>
  <button type="submit">Ajouter</button>
</form>
```

### Pourquoi le formulaire doit déclarer son champ

`parametresDepuisRequete` ne retient que la première valeur d'un champ répété.
Poser `multiple` seul enverrait douze comptes et n'en ajouterait qu'un, sans
erreur, sans message et sans journal : l'administrateur repartirait convaincu
que son geste est fait.

`bulk_field` nomme explicitement le champ porteur de cibles. En son absence, le
chemin d'exécution est **exactement** celui d'avant, à l'instruction près —
c'est ce qui garantit qu'aucun des formulaires existants n'a changé de
comportement.

La détection automatique — chercher quel champ arrive en plusieurs exemplaires
— a été écartée, et pas pour des raisons de style : `r.Form` **fusionne** le
corps de la requête et la chaîne de requête de l'URL. Les pages de détail
postent vers `/admin/groups?group=X` ; le jour où un formulaire porterait un
champ nommé `group`, la valeur de l'URL s'ajouterait à celle du corps et la
détection croirait à deux cibles. Une heuristique qui se trompe ici agit sur la
mauvaise entité.

### Les trois garanties

1. **Les cibles viennent de `r.PostForm`, jamais de `r.Form`.** Ajouter
   `?username=victime` à l'URL n'ajoute aucune cible.
2. **Une exécution par cible, donc un contrôle de droits par cible.**
   `action.Executer` résout les domaines de la cible et exige le droit dessus.
   Grouper les cibles en un seul appel aurait fait porter le contrôle sur la
   première, et les suivantes seraient passées avec le droit d'une autre — une
   élévation de privilèges offerte par une optimisation.
3. **Le compte rendu nomme tous les échecs**, avec leur motif. Les réussites
   sont abrégées au-delà de huit ; les échecs, jamais.

### Ce qui n'est pas garanti : l'atomicité

Il n'y a pas de transaction. Si la huitième cible échoue, les sept premières
sont écrites. C'est assumé — chaque cible est une opération indépendante, et
annuler sept rattachements réussis parce qu'un huitième compte a disparu
entre-temps serait plus surprenant qu'utile. Le message dit exactement ce qui a
eu lieu :

> 7 réussites : alice, bob, carol, dave, erin, frank, grace. 1 échec :
> heidi — Permission refusée : aucun droit sur le domaine lyon.

### Garde-fous

| | |
| --- | --- |
| `MaxCiblesGroupees` | 200 par soumission. Au-delà, **rien** n'est exécuté : refuser après avoir écrit deux cents lignes laisserait un état partiel qu'aucun message ne décrirait. |
| Cibles vides ou en double | écartées avant exécution. Deux fois la même cible produirait une réussite puis un échec « déjà membre » — un échec annoncé là où l'administrateur n'a rien fait de mal. |
| Aucune cible cochée | refus explicite. Un `<select multiple>` vide n'envoie aucun champ ; sans ce refus l'action partirait avec une cible vide et rendrait un message qui n'explique pas le vrai problème. |
| Champs de transport | `action`, `bulk_field` et `active_tab` ne peuvent pas porter de cibles. |
| Une seule cible | le résultat et l'erreur de l'action sont rendus tels quels, pour que `errors.As` continue de reconnaître `*ErrRefusee` et que le mot « refusée » survive. |

### Où c'est actif

13 formulaires : les 10 de `admin_group_detail.html`, les 2 de
`admin_user_detail.html`, et « Lier à des groupes » de `admin_gpo_detail.html`.

Le type de service de `admin_enroll.html` reste en sélection simple : on crée
une clé d'enrôlement d'un type, pas de plusieurs.

## Pourquoi on enrichit le `<select>` au lieu de le remplacer

Le `<select>` reste dans le formulaire et reste la source de vérité. Le module
le masque visuellement et construit le widget à côté ; toute sélection est
réécrite dedans, et c'est lui que le navigateur soumet.

Trois propriétés en découlent, qu'un widget « à base de `<div>` et d'inputs
cachés » n'aurait pas :

- **sans JavaScript**, la page reste utilisable. Le CSS ne masque le `<select>`
  que par la classe `.vlt-picker-native`, **posée par le script** — jamais si
  le script n'a pas tourné. Ne jamais masquer un `<select>` sur la seule foi de
  `[data-vlt-picker]` ;
- **`required` continue de fonctionner**. Le `<select>` est transparent et haut
  d'un pixel, mais toujours affiché : ni `display:none`, ni
  `visibility:hidden`. Chrome refuse de focaliser un contrôle invalide non
  affiché et abandonne la soumission en n'écrivant qu'une ligne dans la
  console — un `required` masqué deviendrait un blocage silencieux ;
- **le serveur ne voit aucune différence**, ce qui permet de livrer sans
  toucher au Go.

---

## API

```js
VltPicker.init(racine);      // enrichit les <select> non encore traités
VltPicker.refresh(select);   // relit les options (liste modifiée en JS)
VltPicker.destroy(select);   // rend la main au <select> natif
```

L'initialisation est automatique au chargement. `init` est idempotente : la
rappeler sur une zone fraîchement injectée n'enrichit que ce qui ne l'est pas
déjà. Une instance qui échoue est journalisée en console et laisse son
`<select>` natif : un widget cassé n'emporte ni les autres, ni la page.

---

## Tests

**Navigateur** — 32 assertions dans un DOM jsdom, pilotées par de vrais
événements, aucune fonction interne appelée directement :

```bash
cd web_packet/sso_WEB_page/tests
./run_tests.sh
```

Le script installe `jsdom` dans son propre répertoire à la première exécution,
et se termine sans échouer si Node est absent : ces tests ne doivent pas
bloquer quelqu'un qui ne touche qu'au Go.

**Serveur** — l'exécution groupée :

```bash
cd src/vaultaire_serveur
go test ./core/web_serveur/ -run Groupe -v
go test ./core/web_serveur/
```

Les points qui justifient à eux seuls les deux suites, côté navigateur :

- le `<select>` reste **dans le formulaire** après enrichissement — sinon plus
  rien n'est soumis et l'écran paraît fonctionner ;
- **Entrée** dans le champ de recherche ne soumet pas le formulaire — sinon
  chercher un utilisateur déclencherait « Ajouter » avec l'ancienne valeur ;
- « Tout cocher » porte sur les options **filtrées**, jamais sur les 4 000
  comptes du parc ;
- `destroy()` rend un `<select>` intact, toujours dans son `<form>`.

Et côté serveur, les cinq manières dont la boucle pourrait mentir :

- traiter douze fois la même cible en annonçant douze réussites — le piège des
  alias, où écraser le champ *après* leur résolution laisse le nom canonique
  figé sur la première valeur du lot ;
- accepter une cible venue de l'URL et non du formulaire ;
- taire un échec au milieu d'un lot ;
- écrire une partie du lot avant de refuser le reste ;
- faire basculer sur le chemin groupé un formulaire qui n'a rien demandé.

---

## Détails d'implémentation à connaître

**Plafond d'affichage.** 200 lignes construites au maximum par passe. Un groupe
de 5 000 comptes produirait 5 000 nœuds à chaque frappe et rendrait la saisie
saccadée. Les options non rendues restent sélectionnables : elles apparaissent
dès que la recherche les ramène sous le plafond, et un pied de liste annonce le
reste.

**Filtres en OU.** Cocher « admin » et « standard » montre les deux ensembles.
Un ET les rendrait presque toujours vides, les étiquettes de ce produit étant
exclusives.

**Curseur clavier et souris séparés.** `is-active` suit le clavier, `:hover` la
souris. Un mouvement involontaire de la souris ne doit pas changer la cible
d'un `Entrée`.

**Renvoi du focus.** `gpo_admin.js` fait
`querySelector('input:not([type=hidden]), select, textarea').focus()` après
avoir déplié un formulaire, et un `<label for>` focalise aussi le `<select>`.
Le module écoute `focus` sur le `<select>` invisible et renvoie sur le bouton,
sans quoi le focus disparaîtrait de l'écran.

**Position du panneau.** Sous le bouton par défaut, retourné au-dessus s'il n'y
a pas la place — mesuré à l'ouverture. Sans cela, une liste ouverte en bas de
page s'affiche hors écran et donne l'impression que le clic n'a rien fait.
