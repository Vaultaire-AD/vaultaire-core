[⌂ Documentation](../../README.md) › [how it work](./README.md) › Tests

# Les tests : ce qui existe, comment les lancer, comment en ajouter

---

## La commande

```bash
cd src/<module> && go test ./...
```

Il n'y a **rien d'autre à savoir** : pas de base à monter, pas de variable à
poser, aucun filtre à passer. Un test qui a besoin de plus se saute tout seul en
le disant (voir « Les tests qui exigent une base »).

Les modules :

| Module | Tests | Ce qu'ils gardent |
|---|---|---|
| `src/vaultaire_serveur` | ~466 | actions et RBAC, GPO, LDAP, cluster, portail, hachage, migrations |
| `src/vaultaire_client` | ~169 | agent : GPO, comptes locaux, sessions, configuration |
| `src/ducky-network-sdk-service` | ~72 | protocole Ducky : découverte, confiance, journaux, sessions |
| `src/vaultaire_nexus` | ~23 | dépôts, index, authentification du Nexus |
| `src/vaultaire_proxy` | ~10 | relais : configuration, transport, plafonds, refus franc |
| `src/vaultaire_client_windows` | ~10 | agent Windows : protocole du tube, nommage des comptes locaux |
| `src/vaultaire_cli`, `src/vaultaire_ctl` | — | façades minces ; la logique est testée dans le serveur |
| `src/api_client_package` | — | exemple de client d'API : aucun test, mais **compilé et analysé** par l'intégration continue — un exemple publié qui ne compile plus est un exemple qui ment |

Le tout tourne en quelques dizaines de secondes. Lancez au moins le module que
vous avez touché, **et** `ducky-network-sdk-service` si vous avez touché au
protocole : il est consommé par l'agent, le proxy et le Nexus.

Avec `-race` pour tout ce qui a des goroutines (relais, sessions, journaux) :

```bash
go test -race ./...
```

## Les deux familles de tests

**1. Les tests de règle.** La grande majorité. Ils éprouvent une décision pure :
un paramètre refusé, un ordre de tri, une forme de trame, une portée déclarée,
un message qui nomme ce qu'il a changé. Aucune base, aucun réseau, aucun
fichier — ils tournent partout et en quelques millisecondes.

**2. Les tests qui traversent jusqu'à la base.** Une poignée. Sans base,
`database.GetDatabase()` rend un pointeur nul et `database/sql` **panique**
dessus — et une panique n'échoue pas seulement son test, elle arrête tout le
paquet et emporte le verdict des autres.

Dans `core/action`, ces tests appellent donc `exigeBase(t)`
(`exige_base_test.go`), qui les **saute** avec sa raison quand il n'y a pas de
base. Reprenez ce geste si vous en écrivez un.

> C'est ce qui a manqué longtemps : cinq tests paniquaient, le paquet ne rendait
> plus aucun verdict, et l'habitude s'était prise de le lancer avec un filtre
> qui les écartait. Un paquet qu'on ne lance qu'en écartant des tests ne dit
> plus rien de ce qu'il couvre.

### Le module Windows se teste SOUS LINUX

`src/vaultaire_client_windows` se compile pour les deux systèmes : ce qui touche
à Windows vit dans des fichiers `_windows.go`, avec une souche pour le reste.
`go test ./...` y tourne donc sur la machine de développement et couvre ce qui
compte le plus — le protocole du tube et le nommage des comptes locaux.

Ce qui ne peut PAS se tester ainsi : le tube nommé lui-même, la création de
comptes et la DLL du Credential Provider. Le premier s'éprouve sous `wine`, les
deux autres sur une vraie machine (voir `exploitation/A_TESTER.md` § 14).

## Les tests qui lisent des FICHIERS du dépôt

Trois catégories les utilisent, et elles ont une contrainte commune : `go test`
exécute chaque paquet depuis **son propre répertoire**, pas depuis la racine du
dépôt.

| Ce qui est lu | Comment le chemin est trouvé |
|---|---|
| gabarits du portail (`web_packet/`) | `TestMain` de `core/web_serveur` cherche la racine du dépôt et pose `VAULTAIRE_WEB_PACKET` |
| fichiers source du paquet (`handler.go`…) | chemin relatif simple : le paquet est déjà le répertoire courant |
| gabarits depuis un autre paquet | chemin relatif explicite, commenté sur place |

Corollaire pour le code de production : **ne figez pas un chemin de ressource
dans une variable de paquet**. Une variable est évaluée au chargement, donc
avant qu'un test ait pu désigner la racine ; une fonction est évaluée à l'usage.
C'est ce qui rendait tous les tests du portail inertes.

## Les tests-sentinelles, et ce qu'on en fait

Certains tests ne vérifient pas un calcul mais une **promesse** que le code
pourrait perdre sans rien casser visiblement. Ils échouent alors de façon
délibérément bruyante :

| Test | Promesse tenue | À faire s'il échoue |
|---|---|---|
| `TestCatalogueCompletNaPasDeDoublon` | le catalogue d'actions contient exactement N actions | si l'ajout est voulu : mettre le nombre à jour **dans le même passage** |
| `RBAC.LectureVoitSonPerimetre` / `AucuneEcritureNeSeContenteDUnDomaine` | une lecture déclare `UnDomaineSuffit`, une écriture jamais | corriger la déclaration de l'action, pas le test |
| `TestLaColonneEstDefinieALIdentiqueDesDeuxCotes` | base neuve et base migrée portent la même colonne | aligner la migration sur le schéma |
| `TestLeRefusEstNonPunitifDansLeHandler` | un quota dépassé ne ferme pas la connexion d'un nœud | ne pas remonter d'erreur depuis ce chemin |
| `TestLEmpreinteSeRelitParVerifier` | ce qui est haché est relu par les quatre portes | ne jamais changer le hachage d'un seul côté |

**Un test-sentinelle rouge n'est jamais « normal ».** Soit le code a perdu la
promesse, soit le test décrit un contrat périmé — dans les deux cas cela se
traite, pas se contourne. Deux d'entre eux ont décrit pendant des mois l'ancien
hachage SHA-256 alors que le stockage était passé à argon2id : ils échouaient à
chaque exécution, et le bruit couvrait le reste.

## La suite intégrée au binaire (`--test`)

En plus de `go test`, le serveur embarque une suite :

```bash
vaultaire_serveur --test
```

Elle vit dans `core/testrunner/` et tient les invariants qu'on veut pouvoir
vérifier **sur une machine en service**, avec le binaire réellement installé :
assainissement des entrées, identité d'amorçage, catalogue et restrictions GPO,
dérive et conformité, conformité LDAP, attestation de la clé du core, TOTP
(vecteurs de la RFC 6238), politique d'expiration, hachage argon2id.

Elle ne remplace pas `go test` : elle répond à « ce binaire-ci, sur cette
machine-ci, tient-il ses invariants ». Ajoutez-y un test quand la réponse doit
pouvoir être donnée en exploitation.

## Ce que l'intégration continue fait

Deux fichiers, deux questions, deux moments.

| Fichier | Déclenchement | Ce qu'il répond |
|---|---|---|
| `.github/workflows/tests.yaml` | **push sur `dev`** — donc chaque merge | « ce code fait-il ce qu'il promet ? » |
| `.github/workflows/dev.yaml` | push et PR sur `dev`, plus une fois par semaine | « ce code est-il propre et sûr ? » (format, SAST, dépendances, images, IaC, SBOM, licences) |

`tests.yaml` fait, par module : `go build`, `go vet`, puis **`go test -race`**.
Un job séparé compile l'agent Windows et la face Windows du socle en
`GOOS=windows` — sans lui, on pourrait les casser sans qu'aucune exécution ne
rougisse, puisque Linux ne les compile même pas.

**Le déclenchement est `dev` seulement, et c'est délibéré.** Une branche de
travail a le droit d'être rouge : c'est à cela qu'elle sert. Le merge dans `dev`
est le moment où le code devient celui que tout le monde récupère, donc le seul
où un test rouge doit arrêter quelqu'un.

**La liste des modules n'est écrite nulle part.** Les deux fichiers la
demandent au dépôt (`find src -maxdepth 2 -name go.mod`). L'ancienne liste,
tenue à la main, citait un `vaultaire_api` inexistant — le pas était alors
sauté, avec un avertissement que personne ne lit — et en oubliait quatre. Un
module neuf est désormais couvert le jour où il naît, et une découverte qui ne
trouve rien **échoue** au lieu de rendre une matrice vide, c'est-à-dire un
succès qui n'a rien testé.

> Historique, pour comprendre les tests qu'on trouve encore : jusqu'au 23/09
> l'intégration continue ne lançait **aucun** `go test`, et le job de lint était
> toujours vert — ses pas portaient `continue-on-error` sans que personne ne
> relise leur issue. C'est ainsi que des tests périmés ont vécu des mois
> (**TO-DO 75**).

`golangci-lint` reste non bloquant, et c'est un choix : il tourne en
`version: latest`, donc son verdict peut changer sans que le dépôt bouge. Un
contrôle qui rougit tout seul un matin finit par être ignoré, et emporte les
autres avec lui.

La vérification avant commit reste utile — voir le
[pense-bête de développement](./Pense-bete_developpement.md) : l'intégration
continue dit non après le merge, le pense-bête l'évite avant.

## Écrire un test dans ce dépôt

- **En français, et il dit POURQUOI.** Le commentaire au-dessus explique ce que
  le test empêche, pas ce qu'il fait — le corps le dit déjà. Un message d'échec
  utile nomme la conséquence : « l'ordre sel‖mot de passe n'est pas respecté, le
  client ne retrouverait jamais cette valeur ».
- **Le test ne réutilise pas la fonction qu'il vérifie.** Il faut une seconde
  expression de la même règle, sinon la comparaison ne compare rien.
- **Pas de fenêtre de N caractères pour lire la source.** Un test qui inspecte
  du code (il y en a) délimite le bloc par ses accolades : une fenêtre finit par
  déborder sur du code voisin, et le test accuse ce qu'il ne regarde pas.
- **Rien d'ordonné au hasard.** Pas de dépendance à l'ordre d'exécution, pas
  d'état partagé entre tests : `go test` les réordonne, et `-race` les
  parallélise.
- **Un test qui a besoin d'un service le SAUTE** (`t.Skip`) en disant lequel. Il
  ne panique pas, et il n'est pas « connu pour échouer ».

## L'état, au 23/09/2026

Les huit modules passent : `go test ./...` **et** `go test -race ./...` sont
verts partout, sans filtre.
Ce qui a été réparé lors de la remise au propre :

| Ce qui n'allait pas | Ce qui a été fait |
|---|---|
| `db_gpo` ne compilait pas (deux aides de test nommées `ligne`) | l'une renommée — tout le paquet était muet |
| deux tests de hachage décrivaient SHA-256 | réécrits sur argon2id et sur `Verifier` |
| le compte d'actions du catalogue était figé à 80 (il y en a 89) | mis à jour, et le message dit quoi faire |
| cinq tests paniquaient faute de base | `exigeBase(t)` : ils se sautent |
| le test des droits du journal lisait le mode de `t.TempDir()` | il éprouve maintenant le répertoire **créé** par le paquet |
| `core/global/security` paniquait en fabriquant une empreinte à paramètres nuls | l'empreinte est composée sans appeler argon2 |
| le test du quota lisait 400 caractères de source | il lit le bloc du `if` |
| tout `core/web_serveur` paniquait au chargement | gabarits résolus à l'usage, `TestMain` pose la racine |
| une course détectée par `-race` dans le test du superviseur de l'agent | le test pilote la persistance par un drapeau atomique et attend la fin de la goroutine |
| 15 fichiers non formatés | `gofmt -w` |
