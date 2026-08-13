# Lexique Vaultaire

Le vocabulaire du produit, défini d'après **le code** et non d'après l'usage
oral. Quand un mot est employé pour deux choses, les deux sont ici, avec ce qui
les distingue.

> Les mots en **gras** dans les définitions renvoient à une autre entrée.

---

## Les programmes

### Core
Le serveur central : `vaultaire_serveur`. Il détient l'annuaire, la base, les
droits, les **GPO**, et il est le seul à décider quoi que ce soit. Tout le reste
lui parle.

Un parc peut en compter plusieurs — voir **Cluster**.

### Agent
Le programme installé sur une machine du parc : `vaultaire_client`. Il
authentifie les utilisateurs qui ouvrent une session, tire les **GPO** de sa
machine et applique les révocations.

Il est **créé sur le core** (`vlt create -c`), qui lui fabrique sa paire de clés
et sa configuration.

> « Agent » et « client » désignent souvent la même chose dans les conversations.
> Dans le code, `vaultaire_client` est le nom du binaire ; **client** est le mot
> générique. Voir ci-dessous.

### Proxy
`vaultaire_proxy`. Relais de découverte et de répartition de charge entre les
postes et les **cores**.

**Il ne déchiffre rien** : la session Ducky reste de bout en bout entre l'agent
et le core, et le proxy transporte les octets sans les lire. Ce n'est pas un
détail d'implémentation mais une décision — depuis que le mot de passe transite
dans le tunnel, un proxy qui terminerait la session deviendrait un point de
collecte des mots de passe du parc entier.

Il n'authentifie personne et ne reçoit aucune politique.

### Interface web
`vaultaire_web`, servie par le core sur le port 4443. Elle authentifie les
administrateurs et relaie leurs commandes.

Du point de vue du protocole, c'est un **service** comme un autre : elle s'enrôle
et ouvre une session Ducky.

### CLI locale / CLI distante
- `vlt` (`vaultaire_cli`) parle au core par un **socket UNIX local**. Elle suppose
  donc un accès à la machine du core.
- `vaultaire_ctl` fait les mêmes choses **à distance**, par l'API REST signée.

---

## Client, service, basic

Ces trois mots sont la source de confusion la plus fréquente, parce qu'ils ne
découpent pas la même chose.

### Client
Terme **générique** : tout programme qui ouvre une session Ducky vers le core.
L'agent en est un, le proxy aussi, l'interface web aussi.

Dans la base, un client est une ligne de `client_software`, identifiée par un
**ClientSoftwareID**.

### Famille : agent ou service
Le catalogue (`core/clienttype`) range chaque type de client dans une **famille**,
et c'est elle qui décide de la façon dont il naît :

| Famille | Comment il naît | Exemples |
|---|---|---|
| **agent** | **créé sur le core**, qui lui fabrique ses clés | `vaultaire_client` |
| **service** | **s'enrôle seul**, avec ses propres clés | `vaultaire_proxy`, `vaultaire_web` |

La distinction n'est pas cosmétique. Un **service** génère sa paire de clés sur
la machine qui l'exécutera : sa clé privée ne quitte jamais cet hôte. Un agent,
lui, reçoit la sienne du core.

C'est pourquoi `vlt create -c` ne sait créer qu'un agent, et pourquoi un service
passe par une **clé d'enrôlement**.

### « Client basic »
Employé à l'oral pour dire **« un agent »**, c'est-à-dire un client qui n'est pas
un service. Le mot n'existe pas dans le code : la famille s'appelle `agent`.

Quand vous lisez « client basic » dans la TO-DO, lisez **agent**.

---

## Identités et rattachements

### ClientSoftwareID
L'identifiant d'une machine ou d'un service dans l'annuaire. Figé à la poignée de
main `01_01` et vérifié à chaque trame : une trame qui en annonce un autre est
refusée et la connexion fermée.

C'est aussi ce qui sert de **source** à la limitation de débit sur le canal
Ducky — l'adresse IP y étant celle du poste, partagée par tous ses utilisateurs,
ou celle d'un proxy.

### Domaine
Un nom hiérarchique — `paris.example.fr` — qui sert de **périmètre de
délégation**. Un droit s'accorde sur un domaine, avec ou sans **propagation** aux
sous-domaines.

Ce n'est pas un domaine DNS, même si Vaultaire sait aussi servir du DNS.

### Groupe
Un rattachement. On y met des **utilisateurs**, des **clients**, des
**permissions** et des **GPO** ; ce qui est dans le groupe hérite de ce que le
groupe porte.

Un groupe appartient à un **domaine**.

### Permission utilisateur / permission client
Deux choses différentes qui portent le même mot :

| | Ce qu'elle gouverne |
|---|---|
| **permission utilisateur** | ce qu'un compte peut faire — annuaire, portail, API, LDAP. Structurée : une valeur par action **RBAC**, par domaine |
| **permission client** | ce que les **machines** d'un groupe accordent — droits d'administration locale, montages. Un simple nom + un drapeau admin |

`create -p` crée la première, `create -pc` la seconde.

### Clé d'enrôlement
Un secret à durée et à usages limités, émis par `vlt enroll create`, qui autorise
un **service** à s'inscrire seul auprès du core. Elle vise un type précis.

Révoquer une clé la **neutralise sans effacer sa trace** : ce qui s'est enrôlé
avec elle reste consultable, ce qu'on cherche précisément après une fuite.

### Groupe protégé
Le groupe `vaultaire`. Certaines actions l'exigent **au lieu** d'une clé RBAC,
parce qu'elles ne relèvent d'aucun domaine : supprimer un certificat, modifier
les restrictions GPO.

---

## Droits

### RBAC
Le modèle de droits. Une clé s'écrit `catégorie:action:objet` —
`write:create:user`. Les objets sont `user`, `group`, `client`, `permission`,
`gpo`.

Voir [`Actions_et_Permissions.md`](./Actions_et_Permissions.md) pour savoir quel
droit exige quelle opération.

### Propagation
Un droit accordé sur `example.fr` **avec propagation** couvre
`paris.example.fr` ; **sans propagation**, il ne couvre qu'`example.fr`.
Noté `1:` et `0:` dans la valeur stockée.

### Portée
Sur **quels domaines** un droit est exigé pour une opération donnée. Trois
réponses possibles selon ce qu'on fait — lister, consulter, modifier. Voir
[`Group-Permission.md`](./Group-Permission.md).

### Droit booléen
Un droit qui ne se délègue **pas** par domaine, parce que l'objet visé
n'appartient à aucun domaine : `read:log`, `read:certificate`, `write:server`…
On l'accorde avec `all`, ou pas du tout.

### Kill switch
La révocation d'urgence d'un compte (`vlt kill -u`). Elle coupe l'accès **partout
à la fois** — portail, LDAP, Ducky — et le refus précède toute évaluation du mot
de passe, pour que le verrouillage ne devienne pas un moyen de confirmer qu'un
compte existe.

---

## Protocole et politiques

### Ducky Network
Le protocole propriétaire entre les clients et le core. Session chiffrée,
établie par une poignée de main RSA, puis **trames** numérotées.

### Trame
Un message du protocole, numéroté `MM_SS` — catégorie et sous-trame :

| Catégorie | Sujet |
|---|---|
| `01` | authentification machine, enrôlement |
| `02` | authentification utilisateur |
| `03` | SSH / PAM |
| `04` | cluster, découverte de service |
| `05` | GPO |
| `06` | révocation |
| `07` | web |

Le **catalogue de types** décide quelle trame chaque type de client a le droit
d'émettre — et il est *fail-closed* : une trame ajoutée au protocole reste
interdite à tous tant que personne ne l'a déclarée.

### GPO
Une politique appliquée aux machines ou aux sessions utilisateur. Déclarative :
elle décrit un **état voulu**, et l'agent l'applique.

- **scope machine** : appliquée au démarrage puis périodiquement ;
- **scope user** : appliquée à l'ouverture de session.

### Module (de GPO)
Une brique d'une GPO, prise dans un catalogue : durcissement SSH, règle de
pare-feu, paquet à installer… Chaque module a des paramètres et un **applicateur**
côté agent.

### Empreinte (de politique)
Le SHA-256 de la forme canonique d'une GPO. C'est ce qui décide, côté agent, s'il
faut réappliquer : elle change dès qu'un module, un paramètre ou la version
bouge, et elle est stable quel que soit l'ordre de lecture en base.

### Dérive *(drift)*
L'écart entre l'état voulu par une GPO et l'état réel de la machine. Le scan de
conformité la détecte — **pour les fichiers**. Les effets non-fichier — un service
réactivé, une règle de pare-feu supprimée — ne sont pas encore vérifiés.

> « Non vérifié » ne veut pas dire conforme : cela veut dire que l'agent n'a pas
> encore rapporté de scan.

### Cluster
L'ensemble des **cores** et **services** enregistrés. `vlt cluster list` en donne
l'état.

---

## Voir aussi

| | |
|---|---|
| Les commandes | [`MAN.md`](./MAN.md) |
| Déléguer des droits | [`Group-Permission.md`](./Group-Permission.md) |
| Quel droit pour quelle opération | [`Actions_et_Permissions.md`](./Actions_et_Permissions.md) |
| Le protocole en détail | [`../Developement/how it work/Protocole_Ducky.md`](../Developement/how%20it%20work/Protocole_Ducky.md) |
| Les GPO en détail | [`../Developement/how it work/GPO.md`](../Developement/how%20it%20work/GPO.md) |
