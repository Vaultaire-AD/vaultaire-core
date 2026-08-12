# Le registre d'actions — `core/action`

Comment le paquet fonctionne, et comment y ajouter une action sans se tromper.

> **Public : développeurs.** Pour savoir *quel droit* il faut pour telle
> opération, voir [`Utilisation/Actions_et_Permissions.md`](../../Utilisation/Actions_et_Permissions.md).
> Pour le modèle RBAC lui-même, voir [`Permissions_RBAC.md`](./Permissions_RBAC.md).

---

## Table des matières

1. [Le problème qu'il résout](#1-le-problème-quil-résout)
2. [La forme d'une action](#2-la-forme-dune-action)
3. [Le chemin d'une requête](#3-le-chemin-dune-requête)
4. [Les portées](#4-les-portées)
5. [Le filtrage des listes](#5-le-filtrage-des-listes)
6. [Ajouter une action — la recette](#6-ajouter-une-action--la-recette)
7. [Ce que le registre refuse au démarrage](#7-ce-que-le-registre-refuse-au-démarrage)
8. [Tester une action](#8-tester-une-action)
9. [Les pièges déjà tombés](#9-les-pièges-déjà-tombés)

---

## 1. Le problème qu'il résout

Créer un utilisateur s'écrivait à **deux endroits** : `command_create` pour la
ligne de commande, `web_admin_pages.go` pour le portail.

Ce n'étaient pas deux copies mais **deux comportements**. Le web validait la date
de naissance, la commande non. La commande déduisait prénom et nom d'un point
dans l'identifiant, le web non. Le web exigeait un mot de passe non vide, la
commande l'acceptait vide. La même demande n'aboutissait pas au même compte selon
la porte empruntée.

Le second problème était plus grave : le contrôle des droits côté web était
**fail-open**. Le motif employé partout était

```go
if actionKey != "" {
    ok, msg := permission.CheckPermissionsMultipleDomains(...)
    ...
}
```

— une clé restée vide sautait donc le contrôle, en silence.

Le registre répond aux deux : **une action est définie une fois**, avec sa clé,
sa portée et son effet ; et **le contrôle est dans l'exécuteur**, pas dans
l'action. Une action ne *peut pas* oublier son contrôle, puisqu'elle ne l'écrit
pas.

---

## 2. La forme d'une action

```go
r.MustEnregistrer(Definition{
    Nom:      "user.create",
    CleRBAC:  "write:create:user",
    Portee:   PorteeGlobale,
    Resume:   "crée un compte utilisateur",
    Executer: creerUtilisateur,
})
```

| Champ | Rôle |
|---|---|
| `Nom` | `objet.verbe`. Se lit dans les journaux, se retrouve dans les formulaires web. |
| `CleRBAC` | la permission exigée. |
| `ExigeSuperadmin` | appartenance au groupe protégé **au lieu** ou **en plus** de la clé. |
| `ExigeSuperadminSi` | la même exigence, mais **conditionnée aux paramètres**. N'en tient jamais lieu — voir §7. |
| `Portee` | **obligatoire** : sur quels domaines `CleRBAC` est exigée. |
| `UnDomaineSuffit` | un seul des domaines de la cible suffit. Lectures d'entité. |
| `PorteeOuverte` | la clé détenue n'importe où suffit ; le `Filtre` réduit. Listes. |
| `Filtre` | réduit les données rendues au périmètre de l'appelant. |
| `FiltreInutile` | justification **écrite** de l'absence de filtre sur une `.list`. |
| `Executer` | l'effet. Reçoit `Appelant` et `Params`, rend `Resultat`. |

`Params` est une `map[string]string` avec trois accesseurs : `Get` (trimé),
`Brut` (non trimé — pour une clé SSH ou un mot de passe, dont les espaces
comptent) et `Presente` (distingue « absent » de « vide »).

`Resultat` porte `Message` (une phrase pour un humain), `Donnees` (le résultat
structuré, que les deux façades mettent en forme chacune à sa manière) et
`Cible` (le nom de l'objet visé pour le journal d'audit, quand le paramètre n'est
qu'un identifiant).

---

## 3. Le chemin d'une requête

```
  vlt / portail web
        │
        ▼
  action.Executer(nom, appelant, params)
        │
        ├─ Controler ─── action inconnue ?          → ErrInconnue
        │                groupe protégé exigé ?     → EstSuperadmin
        │                Portee(params) → domaines
        │                CleRBAC exigée sur ces domaines → ErrRefusee + Journal.Refus
        │
        ├─ d.Executer(appelant, params)             ← l'effet, enfin
        │
        ├─ appliquerFiltre(...)                     ← seulement en cas de succès
        │
        └─ Journal.Execution / Journal.Echec        ← seulement pour les écritures
```

**L'ordre est la garantie.** Il n'existe aucun chemin qui atteigne `d.Executer`
sans être passé par la vérification, parce que la vérification est dans
`Executer` et non dans chaque action.

`Controler` est exporté et s'emploie seul quand il faut **décider sans agir** :
`vlt certificate fingerprint` calcule une empreinte en mémoire — ce n'est pas une
action — mais doit exiger le même droit que `certificate.list`. Elle appelle donc
`Controler` plutôt que de recopier une vérification.

---

## 4. Les portées

La portée répond à « sur quels domaines la clé est-elle exigée ? ». Elle dépend
de la **cible**, connue seulement à l'exécution :

```go
func PorteeUtilisateur(p Params) ([]string, error)  // les domaines du compte visé
func PorteeGroupe(p Params) ([]string, error)       // ceux du groupe visé
func PorteeClient(p Params) ([]string, error)       // ceux de la machine visée
func PorteeGlobale(Params) ([]string, error)        // « * »
```

Et trois manières de l'exiger :

| Déclaration | Exigé | Employée par |
|---|---|---|
| *(défaut)* | la clé sur **tous** les domaines | écritures |
| `UnDomaineSuffit` | la clé sur **un** des domaines | lecture d'une entité |
| `PorteeOuverte` | la clé **quelque part** | listes filtrées |

**Voir et agir ne s'exigent pas pareil.** Un compte présent dans `paris` et
`lyon` m'est légitimement visible si j'administre `paris` — me le cacher
m'empêcherait de constater qu'il y est. En revanche je ne dois pas pouvoir le
*modifier*, parce que mon geste porterait aussi sur `lyon`.

Le défaut est l'exigence stricte : un oubli rend une action **plus sévère** que
voulu — visible et corrigeable — plutôt que plus permissive, ce qui ne se verrait
pas.

> ⚠️ `UnDomaineSuffit` est **sans effet** sur `PorteeGlobale` : la liste de
> domaines vaut `["*"]`, et « au moins un de cette liste » n'a qu'un candidat.
> C'est le piège du §9.

---

## 5. Le filtrage des listes

Le contrôle décide **si l'action a lieu** ; le filtre décide **ce que la réponse
contient**. Une lecture autorisée peut légitimement ne rien rendre.

```go
func filtrerUtilisateurs(donnees any, perim Perimetre) (any, int) {
    users, ok := donnees.([]storage.User)
    if !ok {
        return donnees, 0
    }
    garde := make([]storage.User, 0, len(users))
    masquees := 0
    for _, u := range users {
        if perim.AutoriseUnDes(perim.DomainesDe(EntiteUtilisateur, u.Username)) {
            garde = append(garde, u)
        } else {
            masquees++
        }
    }
    return garde, masquees
}
```

Le second retour — le **nombre d'entrées masquées** — sert à le dire dans le
message. Une liste tronquée en silence se lit comme une liste complète, et c'est
ainsi qu'on croit un annuaire vide alors qu'on n'en voit qu'une part.

`Perimetre.DomainesDe` prend un **genre typé** (`EntiteUtilisateur`,
`EntiteClient`, `EntitePermission`, `EntiteGroupe`) et non une chaîne libre : une
faute de frappe rendrait sinon une liste vide, donc un masquage total, sans la
moindre erreur.

---

## 6. Ajouter une action — la recette

### Étape 1 — Écrire l'effet

Dans le fichier `actions_<domaine>.go` qui correspond. La fonction ne vérifie
**aucun droit** : c'est tout l'intérêt.

```go
func archiverUtilisateur(a Appelant, p Params) (Resultat, error) {
    cible := p.Get("username")
    if cible == "" {
        return Resultat{}, fmt.Errorf("utilisateur cible requis")
    }
    // … l'effet …
    return Resultat{Message: fmt.Sprintf("Compte %s archivé.", cible)}, nil
}
```

**Validez les paramètres ici**, et rendez des messages qui disent quoi corriger.
C'est le seul endroit où la validation vivra pour les deux façades.

### Étape 2 — La déclarer

```go
r.MustEnregistrer(Definition{
    Nom:      "user.archive",
    CleRBAC:  "write:update:user",
    Portee:   PorteeUtilisateur,
    Resume:   "archive un compte sans le supprimer",
    Executer: archiverUtilisateur,
})
```

Le lot d'enregistrement doit être appelé par `EnregistrerTout` dans
`adaptateurs.go`. Un appel explicite plutôt qu'un `init()` : l'ordre entre
paquets dépendrait sinon de l'ordre des imports, et un import retiré ferait
disparaître des actions sans la moindre erreur de compilation.

### Étape 3 — La brancher aux façades

**Ligne de commande** : ajouter la syntaxe dans `command_<verbe>/`, et le nom de
l'action dans le `ActionsUtilisees` du paquet — cette liste est vérifiée au
démarrage contre le registre.

```go
p := commandaction.ParamsDepuisPositionnels(args, "username")
return commandaction.ExecuterAction("user.archive", p, groupIDs, sender)
```

**Portail web** : ajouter l'entrée dans la table `actionsFormulaire` de
`web_serveur/web_action.go`, qui associe le `name` du formulaire au nom de
l'action. Le gabarit poste `action=archive_user`.

> ⚠️ **Ne lisez jamais la base directement depuis un gestionnaire de page.** Le
> contrôle ne vaut que ce que vaut le chemin le plus court, et un chemin qui
> contourne le registre n'a aucun contrôle. Voir §9.

### Étape 4 — Documenter et tester

- une ligne dans [`Utilisation/Actions_et_Permissions.md`](../../Utilisation/Actions_et_Permissions.md) ;
- l'entrée dans `portees_declarees_test.go` (portée et clé attendues) ;
- un test de l'effet si la logique n'est pas triviale.

---

## 7. Ce que le registre refuse au démarrage

`Enregistrer` refuse — et `MustEnregistrer` fait paniquer, donc le serveur ne
démarre pas — dans ces cas :

| Refus | Pourquoi |
|---|---|
| ni `CleRBAC` ni `ExigeSuperadmin` | l'action s'exécuterait sans vérification. `ExigeSuperadminSi` ne suffit pas : sa condition peut être fausse, et on ne peut pas inspecter une fonction pour savoir si elle rend parfois faux. |
| `Portee` nulle | sans domaines à vérifier, le contrôle ne porterait sur rien. |
| `.list` sans `Filtre` ni `FiltreInutile` | la liste rendrait tout à qui détient le droit sur un seul domaine. |
| `PorteeOuverte` sans `Filtre` ni `FiltreInutile` | même divulgation, par l'autre bout. |
| `PorteeGlobale` + `Filtre` sans `PorteeOuverte` | contradiction : qui détient `*` n'a rien à se voir filtrer. Le filtre ne servirait jamais et tout délégué serait refusé. |
| nom déjà enregistré | l'une écraserait l'autre selon l'ordre des fichiers. |

Le refus est **à l'enregistrement** plutôt que dans un test : il arrête le
serveur au démarrage, avec le nom de l'action et la correction à faire, avant
qu'une seule requête n'ait été servie.

`FiltreInutile` demande une **justification écrite** plutôt qu'une exception dans
un test. La tentation, en découvrant un cas légitime, est d'affiner la détection
jusqu'à ce que le test passe — c'est ajuster le test au code. Un champ
obligatoire oblige au contraire à écrire *pourquoi*, une fois, à l'endroit où la
décision est prise.

---

## 8. Tester une action

Le registre est testable **sans base de données**, et c'est délibéré : sans cela,
les tests du contrôle d'accès demanderaient un annuaire complet, donc ne seraient
pas écrits, donc le contrôle ne serait pas testé. C'est exactement ce qui s'était
passé pour le module web — cinq mille lignes, aucun test.

```go
r := NouveauRegistre()
r.MustEnregistrer(Definition{ /* … */ })

e := &Executeur{
    Registre:   r,
    Droits:     &droitsFixes{autorise: false},
    Superadmin: &superadminFixe{},
    Journal:    &journalMemoire{},
}

_, err := e.Executer("user.archive", Appelant{Username: "alice"}, Params{})
```

Les doublures **tracent ce qui a été demandé** : c'est ce qui permet de
distinguer « autorisé » de « jamais vérifié ». Les deux produisent une exécution ;
seul l'enregistrement les sépare.

`VerificateurDroits` porte **trois** méthodes nommées plutôt qu'une avec un
booléen. `Autorise(ids, cle, doms, false)` ne se lit pas ; et surtout, trois
méthodes obligent chaque doublure à répondre explicitement aux trois questions —
une implémentation qui n'aurait pensé qu'à deux **ne compile pas**.

> ⚠️ Certains tests appellent une action directement pour vérifier son message,
> et l'action écrit en base. Sans base, `database.GetDatabase()` rend nil et
> l'appel **panique** — or un panic ne fait pas échouer ce seul test, il fait
> tomber le binaire de test du paquet entier. Isolez l'accès derrière une
> variable substituable, comme `lireCertificat` dans `actions_certificats.go`.

---

## 9. Les pièges déjà tombés

Chacun a coûté un cycle. Ils sont ici pour ne pas y retomber.

### `UnDomaineSuffit` sur une portée globale ne fait rien

Onze listes déclaraient `PorteeGlobale` + `UnDomaineSuffit` + un filtre, ce qui
se lit « le droit sur un domaine ouvre la liste ». `PorteeGlobale` rend `["*"]`,
et « au moins un de cette liste » n'a qu'un candidat : `*`. Ces lectures
exigeaient donc le droit global, et leur filtre n'était jamais atteint.

**Fermé** par le refus à l'enregistrement (§7) et par `PorteeOuverte`.

### Une page qui lit la base n'a aucun contrôle

`AdminCertificatesHandler` appelait `dbcertificates.GetAllCertificates()`
directement. Tout compte disposant de `web_admin` voyait les certificats du
serveur, y compris celui à qui `read:certificate` avait été explicitement refusé
— pendant que la ligne de commande refusait correctement.

Même défaut sur la page d'enrôlement, qui exigeait `read:get:client` là où le CLI
exigeait `read:enrollment`.

**Fermé** par `web_cles_des_pages_test.go`, qui vérifie que chaque page nomme la
clé attendue et passe par l'action.

### La cible de l'audit se déduit des PARAMÈTRES

`cibleDe` avait été écrite d'après le vocabulaire du modèle — `certificate`,
`record` — au lieu des paramètres que les actions lisent : `certificate_id`,
`record_name`, `permission_name`. Toutes les écritures sur les permissions et les
certificats étaient journalisées « sur le serveur ».

**Fermé** par `cible_test.go`, qui confronte la liste aux sources du paquet.

### Un type de `Donnees` qui change ne casse pas à la compilation

`res.Donnees.(MonType)` avec `, ok` **compile toujours**. Changer ce que rend une
action dégrade silencieusement chaque consommateur qui n'a pas été mis à jour :
il retombe sur `res.Message`, et l'affichage perd la moitié de son contenu sans
la moindre erreur.

Cherchez tous les consommateurs — `grep` sur le type — avant de changer un
`Donnees`.

---

## Voir aussi

| | |
|---|---|
| Modèle RBAC, matrice d'administration | [`Permissions_RBAC.md`](./Permissions_RBAC.md) |
| Ce que le serveur journalise, et pourquoi | [`Journalisation.md`](./Journalisation.md) |
| Quel droit pour quelle opération | [`Utilisation/Actions_et_Permissions.md`](../../Utilisation/Actions_et_Permissions.md) |
| Déléguer au quotidien | [`Utilisation/Group-Permission.md`](../../Utilisation/Group-Permission.md) |
