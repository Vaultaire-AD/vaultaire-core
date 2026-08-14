# Versions des composants Vaultaire

Quatre binaires, un socle partagé, et une question : **qu'est-ce qui tourne
réellement sur ce parc ?**

---

## 1. Deux sources, et pourquoi les deux

| | D'où elle vient | Ce qu'elle dit |
|---|---|---|
| **Version sémantique** | constante dans le code | ce que le composant **promet** — compatibilité, rupture |
| **Commit et date** | injectés à la compilation | ce qui a **réellement** été construit |

Ni l'un ni l'autre ne suffit seul.

Une constante seule **finit toujours par mentir** : elle se monte à la main,
donc un jour elle ne le sera pas. Ce n'est pas une hypothèse, c'est le cas
général.

Un commit seul ne dit rien à qui lit un journal d'incident. « g1939a3b »
n'annonce aucune compatibilité, et ne se compare à rien.

Ensemble : `2.1.0+g1939a3b (2026-08-14)`.

Le `+` suit la convention SemVer des métadonnées de build — ce qui le suit
n'entre dans aucune comparaison d'ordre. C'est exactement le statut qu'on veut
donner au commit : informatif, jamais décisionnel.

---

## 2. Où vivent les paquets

| Module | Paquet | Ce qu'il déclare |
|---|---|---|
| `vaultaire` (core) | `core/version` | version du core |
| `duckynetworkclient/V1` | `duckynetwork/version` | version du **SDK**, et le type `Info` partagé |
| `vaultaire_client` | `vaultaire_client/version` | version de l'agent |
| `vaultaire_proxy` | `vaultaire_proxy/version` | version du proxy |

**Pourquoi une version par composant.** L'agent et le SDK ne bougent pas
ensemble : une correction du provisionnement des groupes ne touche pas au socle
réseau, et un durcissement du protocole ne change rien à l'agent. Un seul numéro
pour les deux obligerait à monter l'un pour une raison qui ne le concerne pas —
et le rendrait faux comme promesse de compatibilité.

**Pourquoi le core redit ce que fait le SDK.** Le serveur n'importe pas le
SDK — c'est lui qui juge les clients, il ne partage pas leur socle. Le type et la
mise en forme sont donc écrits deux fois.

La duplication est **sans conséquence de protocole** : le core ne *parse* jamais
la version d'un agent, il la stocke et l'affiche. Les deux formats peuvent
diverger sans rien casser. C'est ce qui distingue ce cas de `PrefixeGroupes` ou
de la règle de calcul du GID, où une divergence d'un caractère casse en silence
et où des tests jumeaux figent la valeur. Ici, il n'y a rien à figer.

---

## 3. L'injection au build

```bash
go build -ldflags "-X vaultaire_client/version.Commit=g1939a3b \
                   -X vaultaire_client/version.Date=2026-08-14 \
                   -X duckynetworkclient/V1/duckynetwork/version.Commit=g1939a3b \
                   -X duckynetworkclient/V1/duckynetwork/version.Date=2026-08-14"
```

`auto-compil.sh` compose ces valeurs à partir de `git describe --always --dirty
--tags`, et les pose sur **chaque paquet `version` présent dans le build**. Le
client et le proxy en reçoivent donc deux jeux : le leur, et celui du SDK qu'ils
embarquent.

> ⚠️ **Un `-X` sur un chemin de paquet inexistant est IGNORÉ SANS ERREUR.**
>
> C'est le piège de ce mécanisme. On croit avoir injecté, le binaire annonce
> « dev », et rien ne le signale — jusqu'au jour où l'inventaire du parc affiche
> « dev » partout et où plus personne ne sait ce qui tourne.
>
> Renommer un paquet, déplacer un module, changer un chemin d'import : chacun de
> ces gestes casse l'injection en silence. `auto-compil.sh` vérifie donc, après
> chaque build, que la chaîne injectée se retrouve dans le binaire, et **arrête**
> sinon.

### Le repli « dev » est affiché, jamais masqué

Un `go build` lancé à la main ne pose rien. La version rendue est alors
`2.1.0 (build local)`.

C'est délibéré. Un binaire construit sur un poste de développement doit se
**reconnaître** dans l'inventaire du parc — c'est même la première chose qu'on
veut savoir devant une machine qui se comporte mal.

---

## 4. Comment la version remonte au core

### L'agent : inventaire `02_12`

```
[0] hostname
[1] os
[2] ram
[3] processeur
[4] sessions actives
[5] version du programme      ← ajouté
[6] version du socle réseau   ← ajouté
```

En **queue**, et facultatives. Un agent d'une version antérieure envoie cinq
lignes : il est enregistré sans version, et apparaît « inconnue ». Les insérer
au milieu aurait fait lire les sessions comme une version par tout core resté à
l'ancienne version.

Une ligne **vide** plutôt qu'absente quand le binaire n'a pas déclaré sa
version : l'omettre décalerait le champ suivant, et le core lirait la version du
socle comme celle du programme — une valeur fausse qui a l'air juste, ce qui est
pire qu'une valeur manquante.

### Le proxy : enregistrement `04_01`

Deux lignes de plus, en queue également, après le port et l'empreinte.

`version_code` portait jusqu'ici la chaîne `"vaultaire_proxy"` **écrite en dur
côté core** : la colonne annonçait une version et contenait un type, que `role`
porte déjà. Elle reçoit maintenant ce que le nœud déclare de lui-même.

### Le socle ne peut pas lire la version du binaire

L'agent importe le SDK ; l'inverse serait un cycle. Et un socle qui connaîtrait
le nom de ses consommateurs ne serait plus un socle.

Le binaire la **pose** donc dans `storage.VersionComposant`, au démarrage, avant
toute ouverture de session — même motif que `Computeur_ID` et
`DemarrerSessionMachine`. Ce que le programme sait de lui-même descend, il ne
remonte pas.

Posée après l'ouverture de session, le premier inventaire l'annoncerait vide.

---

## 5. Où c'est stocké

| Table | Colonnes |
|---|---|
| `id_logiciels` | `agent_version`, `sdk_version` |
| `cluster_nodes` | `version_code` (le programme), `sdk_version` |

`VARCHAR(64)`. Le core **tronque lui-même** à la réception : la troncature de
MySQL est silencieuse en mode non strict, et on lirait une version coupée sans
jamais savoir qu'elle l'a été.

Les caractères de contrôle sont écartés à la même occasion. La valeur vient du
réseau et finit dans les tableaux de `vlt` et dans une page web ; un retour
chariot y ferait sauter une ligne au milieu d'un tableau aligné.

### Les versions ne sont pas éditables

`update_client` les repasse telles quelles. Elles décrivent ce qui **tourne** —
c'est la machine qui les déclare. Laisser un administrateur les corriger
produirait une vue qui dit ce qu'on aimerait plutôt que ce qui est, et c'est
justement dans cette vue qu'on ira chercher qui n'est pas à jour.

Les repasser est indispensable : `UpdateHostname` écrit systématiquement toutes
les colonnes, donc les omettre les effacerait à chaque correction de nom d'hôte.

---

## 6. Ce que le core NE fait PAS de ces valeurs

**Aucun refus. Aucun seuil. Aucune comparaison.**

La version est une donnée d'**inventaire** : elle répond à « qui est en
retard », et rien d'autre. Un agent périmé se voit ; il n'est pas coupé.

C'est un arbitrage, et il tient à une chose : une règle de comparaison de
versions se trompe sur les cas limites — et se tromper ici voudrait dire fermer
la porte à un parc dont **le seul outil de réparation est l'agent qu'on vient de
refuser**.

---

## 7. Où la lire

| | |
|---|---|
| `version` | version de ce core |
| `get -c <machine>` | agent et SDK d'une machine |
| `cluster list` | version et SDK de chaque nœud |
| **Admin → Clients → détail** | affichées, non modifiables |

`version` ne demande **aucun droit**. Elle ne lit ni la base ni l'annuaire :
elle rend une constante du binaire. Toute personne capable de la taper est déjà
authentifiée, et lui cacher un numéro de version ne protège rien. Surtout, c'est
la première chose qu'on demande devant un comportement inattendu — une commande
de diagnostic qui exige un droit est une commande qu'on ne peut pas taper au
moment où on en a besoin.

### « inconnue » et non un tiret

Une case vide se lit comme un oubli d'affichage. « inconnue » dit que la machine
ne l'a **jamais déclarée** — agent d'une version antérieure, ou machine créée et
jamais connectée. C'est une information, pas une absence d'information.

---

## Voir aussi

| | |
|---|---|
| Le protocole et ses trames | [`Protocole_Ducky.md`](./Protocole_Ducky.md) |
| Le catalogue de types de clients | [`Protocole_Ducky.md`](./Protocole_Ducky.md) |
| La commande `version` | [`MAN.md`](../../Utilisation/MAN.md) |
