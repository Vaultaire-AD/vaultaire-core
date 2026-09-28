# Audit LDAP du 28/09/2026 — sécurité, fonctionnalités, compatibilité clients

> Ce fichier porte ce qu'une entrée de `TO-DO.md` ne peut pas porter : ce que le
> code fait aujourd'hui, le scénario concret, et ce qui rend la correction
> délicate. Chaque constat a son entrée dans [`TO-DO.md`](./TO-DO.md), aux points
> **119 à 131**.
>
> Périmètre : `src/vaultaire_serveur/core/ldap` (75 fichiers, ~6 600 lignes) et
> ce qu'il appelle — `core/permission`, `core/domain`, `core/database/db_ldap`,
> `core/auth/*`.
>
> Méthode : relecture du code, pas d'exécution. Chaque constat porte le fichier
> et la ligne. Ce qui n'a pas été mesuré est marqué comme tel.

### État au 28/09/2026

| Point | État |
|---|---|
| **120** — RBAC évalué sur le seul baseDN | **traité** (2.2) — `security.PorteeDeRecherche` lue une fois, consultée par entrée ; `Domaines()` entre dans l'interface `LDAPEntry`, et une sentinelle AST garde le câblage |
| **121** — mot de passe du bind au journal DEBUG | **traité** (2.2) — le vidage du paquet est masqué pour les `BindRequest` et pour toute trame qu'on ne sait pas découper ; l'ExtendedRequest ne journalise plus son contenu (RFC 3062) |
| 119, 122 à 131 | ouverts |
| **132** — `memberOf` porte les groupes des sous-domaines | **ouvert**, relevé en traitant le 120 |

Les deux constats de **sécurité** de cet audit sont donc fermés ; ce qui reste
est fonctionnel ou de conformité, à une exception près — le **132**, découvert en
corrigeant le 120 et laissé ouvert parce que sa correction demande une décision
de conception. Le détail de ce qui a été fait, et de ce qui a été écarté, est dans
`DO/2.2/2.2.md`.

> Deux relectures ont été passées sur le correctif du 120. La première a trouvé
> qu'il ne filtrait que les **groupes** : les comptes portaient le domaine
> *demandé*, si bien que le filtre s'autorisait lui-même. La seconde a trouvé que
> le secours prévu pour un compte sans domaine était aussi atteint par une panne
> de lecture, ce qui reproduisait le même défaut. Les deux sont corrigés, et la
> première est désormais gardée par une sentinelle — c'est le genre de défaut
> qu'aucun test de la règle ne voit, puisque la règle, elle, était juste.

---

## 0. Ce qui est sain, et qu'il ne faut pas défaire en corrigeant le reste

Le chemin de bind a été repris récemment ; c'est aujourd'hui la partie la plus
propre du paquet, et plusieurs des points ci-dessous touchent des fichiers
voisins. À ne pas casser en passant :

- la limitation de débit s'applique **avant** toute lecture de l'annuaire, et sur
  les compteurs **partagés** avec le portail et Ducky : un balayage freiné sur le
  bind ne repart pas à zéro ailleurs ;
- la révocation est évaluée **avant** le mot de passe — le temps de réponse ne
  dit plus si le mot de passe d'un compte révoqué était le bon ;
- le second facteur est découpé avant la vérification, et un état illisible
  **refuse** ;
- `invalidCredentials` est uniforme pour compte inconnu, mauvais mot de passe,
  mot de passe expiré et droits refusés : le bind n'énumère pas l'annuaire ;
- le compte système `vaultaire` est refusé, LDAPv2 aussi, et un bind SASL reçoit
  `authMethodNotSupported` et non `invalidCredentials` ;
- `handleLDAPSession` a un `recover` par connexion : une panique dans le chemin
  LDAP ne coûte plus que la session. Le port 389 accepte des paquets d'inconnus,
  c'est la surface la moins maîtrisée du produit ;
- `sizeLimit` et `timeLimit` sont réellement appliqués, avec une borne serveur
  que le client ne peut que réduire ;
- un contrôle critique non supporté est refusé avec `unavailableCriticalExtension`
  (12), conformément à la RFC 4511 §4.1.11 ;
- le RootDSE n'annonce plus ce qu'il ne sait pas faire : ni StartTLS, ni
  pagination, ni mécanisme SASL.

Deux réserves de configuration, assumées et commentées dans
`LDAP_Storage/LDAP_Limits.go` : `RequireTLSForBind = false` et `MFABypass = false`.

---

## 1. Sécurité

### 1.1 — Le RBAC est évalué sur le baseDN, jamais sur les entrées rendues

*Point 120.*

`LDAP_SEARCH-REQUEST/newmodule/handler.go:53` appelle **une seule fois** :

```go
if !security.IsAuthorizedToSearch(username, baseDN) { … }
```

`baseDN` est le domaine déduit du `baseObject` demandé. Ensuite,
`scope.Resolve` charge les groupes par `domainpkg.GetGroupsUnderDomain`
(`core/domain/GET-GroupsUnderDomain.go:49`), qui retient :

```go
if dn == target || strings.HasSuffix(dn, "."+target) { … }
```

soit le domaine **et tous ses sous-domaines**. Aucun filtrage par entrée ne suit :
dans la boucle d'envoi du handler, seul `vaultaireServiceRights` est calculé
entrée par entrée.

Or `permission.IsUserAuthorizedToSearch`
(`core/permission/IsUserAllowToserachInDomain.go:16`) distingue explicitement
`WithPropagation` — `domain == d || HasSuffix(domain, "."+d)` — de
`WithoutPropagation` — `domain == d`.

**Le scénario.** Un compte délégué porte `search` en `custom` **sans
propagation** sur `enov.local`. Il passe le contrôle, puis reçoit dans la même
réponse les comptes et les groupes de `admin.enov.local`. La distinction
avec/sans propagation, qui est toute la raison d'être du mode « sans », est sans
effet sur le chemin LDAP.

**Pourquoi ce n'est pas trivial.** Filtrer après coup coûte un appel RBAC par
entrée, sur le chemin le plus chaud du serveur. Il faut plutôt résoudre **une
fois** l'ensemble des domaines autorisés au compte, puis écarter les entrées dont
le domaine n'y est pas — ce qui suppose que chaque entrée porte son domaine
(c'est le cas : `UserEntry.BaseDN`, `GroupEntry.BaseDN`).

**Ce qui limite la portée.** Il faut qu'une délégation sans propagation existe.
Sur une installation où les comptes d'administration sont en `all`, l'effet est
nul. C'est néanmoins la seule fuite de données de cet audit.

### 1.2 — Le mot de passe du bind part en clair dans le journal DEBUG

*Point 121.*

`LDAP_common.go:180`, avant toute analyse du paquet :

```go
logs.Write_Log("DEBUG", fmt.Sprintf("ldap: packet from %s: % X", clientAddr, packet))
```

La trame complète est vidée en hexadécimal. Sur un `BindRequest` simple, elle
contient le mot de passe — et, quand le second facteur est actif, le code TOTP
qui lui est accolé (voir la convention décrite dans `LDAP_Limits.go`). Le journal
est un fichier, il tourne, il part dans les sauvegardes.

**Ce qui atténue.** `debug: false` est livré depuis le point 99, et le dépôt ne
porte plus `true`.

**Ce qui n'atténue pas.** On active DEBUG exactement dans la situation où l'on
diagnostique un problème d'annuaire — c'est-à-dire au moment où tous les clients
LDAP du parc se lient en boucle. Une correction simple suffit : ne vider le
paquet que pour les opérations autres que `BindRequest`, ou masquer l'octet de
longueur et le contenu du champ `Authentication`.

### 1.3 — `scope=1` est silencieusement promu en `scope=2` sur `ou=users`

*Point 127.*

`LDAP_SEARCH-REQUEST/newmodule/scope/resolver.go:42` :

```go
if isUserContainerSearch(baseObject) && scope == 1 {
    loadScope = 2
}
```

Écrit pour JumpServer, qui cherche en one-level et attend malgré tout les
sous-domaines — le commentaire le dit.

**La conséquence est plus large.** Un administrateur qui configure une
application en `scope=one` sur `ou=users,dc=enov,dc=local` en attendant un
périmètre restreint obtient l'arbre entier, sous-domaines compris. Ce qui est
écrit dans la configuration cliente ne décrit plus ce qui est servi.

C'est d'abord un écart à la RFC 4511 §4.5.1, mais il a un effet de périmètre,
d'où sa place ici.

### 1.4 — Le bind non authentifié refusé n'est pas celui de la RFC 4513 §5.1.2

*Point 128.*

`LDAP_BIND-UNBIND/LDAP_bind.go:148`, sous un commentaire qui cite §5.1.2 :

```go
if op.Name == "" && len(op.Authentication) > 0 {
```

Les deux cas de la RFC 4513 :

- **§5.1.1** — DN vide **et** mot de passe vide : c'est l'anonyme, traité plus
  bas et correctement ;
- **§5.1.2** — DN **non vide** et mot de passe **de longueur nulle** : c'est le
  bind « non authentifié », celui qu'il faut refuser par défaut, et c'est celui
  qui n'est pas attrapé.

Le cas §5.1.2 descend jusqu'à `dbusers.VerifierMotDePasse` avec une chaîne vide.

**Ce n'est pas exploitable aujourd'hui** : argon2id d'une chaîne vide ne
correspond à aucune empreinte, et les mots de passe vides sont refusés à la
création depuis le point 100. Ce qui doit être corrigé est ailleurs : le
commentaire affirme une protection qui n'existe pas — la prochaine personne qui
lit ce fichier croira le cas couvert — et un client mal configuré consomme du
rate-limit au lieu de recevoir un refus de protocole immédiat.

---

## 2. Fonctionnalités

### 2.1 — Trois types de filtres sur dix ne sont pas évalués

*Point 119.*

`LDAP_SEARCH-REQUEST/newmodule/filter/logical.go`, fin du `switch` :

```go
default:
    // fmt.Printf("[WARN] Filtre LDAP inconnu Type=%v sur DN=%s\n", f.Type, entry.DN())
    return false
```

Le parseur décode pourtant correctement `FilterGreaterOrEqual` (5),
`FilterLessOrEqual` (6) et `FilterApprox` (8)
(`LDAP_Parser/LDAP-PARSE-SEARCHREQUEST.go:114-122`). Les trois tombent dans ce
`default`.

**L'effet.** `(uidNumber>=1000)`, `(whenCreated>=20260101000000Z)`, `(cn~=jon)`
renvoient **`success` avec zéro entrée**. Pas d'erreur côté client, pas de ligne
côté serveur — la seule trace prévue est commentée.

C'est le pire mode de panne possible : rien n'a l'air cassé d'aucun des deux
côtés, et le diagnostic prend des heures. Un `>= ` sur une date est la première
chose qu'essaie un outil de synchronisation incrémentale.

### 2.2 — `FilterExtensible` est traité comme une égalité simple

*Point 119.*

Même fichier : la règle de correspondance et le marqueur `dn:` sont ignorés, la
valeur est comparée en égalité insensible à la casse. La chaîne AD
`(memberOf:1.2.840.113556.1.4.1941:=cn=…)` — appartenance **transitive** — rend
donc un résultat **faux** plutôt qu'une erreur. Mieux vaut refuser une règle de
correspondance inconnue que d'y répondre à côté.

### 2.3 — Un compte sans groupe est invisible en recherche

*Point 122.*

`scope/resolver.go`, dans `loadGroupsAndUsers` : les utilisateurs ne sont
découverts **que** par les membres des groupes.

```go
for _, g := range groupesParDomaine[domain] {
    àLire = append(àLire, g.Users...)
}
utilisateurs, err := dbldap.GetUsersByUsernames(db, àLire)
```

Un compte qui n'appartient à aucun groupe n'apparaît dans aucune recherche `one`
ni `sub`. Il peut malgré tout **se lier** — le bind ne passe pas par là — et être
lu en `scope=base` sur son DN exact, parce que `resolveBaseScope` interroge
`dbldap.GetUserByUsername` directement.

**Deux symptômes.** Pour un humain : « il se connecte mais on ne le trouve pas ».
Pour un client qui synchronise (Keycloak, Nextcloud) : un compte retiré de son
dernier groupe **disparaît** de l'annuaire, ce que ces clients lisent comme une
suppression de compte.

### 2.4 — Les classes POSIX sont annoncées sans un seul attribut POSIX

*Point 123.*

`newmodule/candidate/user.go:36` déclare `posixAccount`,
`newmodule/candidate/group.go:19` déclare `posixGroup`. Aucune des deux cartes
d'attributs ne contient `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`,
`gecos` ni `memberUid`.

Un client RFC 2307 filtre sur `(objectClass=posixAccount)`, **trouve** l'entrée,
puis ne peut pas construire le compte. Combiné au 2.1, sa requête de plage
`(&(objectClass=posixAccount)(uidNumber>=1000))` rend zéro, et il conclut à un
annuaire vide.

**Il faut trancher, pas faire une demi-mesure.**

- **Servir POSIX** suppose une source **stable** pour `uidNumber` / `gidNumber` :
  un compteur en base, jamais un hachage du nom — deux comptes qui collisionnent
  partageraient l'UID, donc les fichiers.
- **Retirer `posixAccount` / `posixGroup`** des `objectClass` est cohérent avec
  le produit : le poste Linux est servi par le client Vaultaire et les modules
  PAM, pas par sssd.

Annoncer sans servir est le seul choix à exclure.

### 2.5 — Pas de `noSuchObject` (32)

*Point 124.*

`resolveBaseScope` rend `nil` quand le DN demandé n'existe pas ; le handler
(`handler.go:74`) envoie alors un `SearchResultDone` de **succès** avec zéro
entrée. Un client ne distingue plus « ce DN n'existe pas » de « ce DN existe et
ne contient rien » — distinction dont dépendent les outils qui testent
l'existence avant d'écrire ou de synchroniser.

### 2.6 — Pas de pagination

*Point 130.*

`1.2.840.113556.1.4.319` n'est ni annoncé ni supporté, et un contrôle critique
est refusé avec le code 12. **C'est le bon comportement** — mieux qu'un client
qui boucle indéfiniment sur la même page. La conséquence à connaître : au-delà de
`MaxSearchEntries = 10000`, la réponse est `sizeLimitExceeded`, pas une page.

### 2.7 — Annuaire en lecture seule

Add, Modify, Delete et ModifyDN reçoivent `unwillingToPerform` avec un message
explicite (`LDAP_common.go:190`). `Abandon` ne reçoit rien, conformément à la
RFC. Rien à corriger ; noté pour que ce ne soit pas redécouvert comme un défaut.

### 2.8 — Le sous-schéma n'est pas analysable par un client strict

*Point 125.*

`newmodule/candidate/SchemaEntry.go` :

- `2.5.6.0` est porté **deux fois** : par `top` et par `subschema`, dont l'OID est
  `2.5.20.1` ;
- `( vaultaireServiceRights-oid NAME 'vaultaireServiceRights' … )` n'est pas un
  `numericoid`. Un analyseur strict — Apache Directory Studio, python-ldap avec
  chargement de schéma, les outils OpenLDAP — rejette **toute** la liste
  `attributeTypes`, pas seulement cette ligne. C'est le constat le plus coûteux
  de la section, pour un caractère ;
- `posixAccount` est déclaré `2.5.6.30`, qui n'est pas son OID (RFC 2307 :
  `1.3.6.1.1.1.2.0`) ;
- classes annoncées par les entrées mais **absentes** du schéma :
  `inetOrgPerson`, `posixGroup`, `organizationalUnit`, `user`, `group` ;
- attributs servis mais non déclarés : `displayName`, `givenName`, `entryUUID`,
  `nsuniqueid`, `objectGUID`, `guid`, `ipaUniqueID` ;
- `createTimestamp` / `modifyTimestamp` figés au `20260314210522Z`.

Le sous-schéma n'a d'intérêt que pour les clients qui le lisent — et ceux-là sont
précisément les plus stricts.

### 2.9 — Détails relevés au passage

*Points 126, 129, 131.*

- **Pas de `createTimestamp` / `modifyTimestamp` par entrée.** C'est ce sur quoi
  s'appuie la synchronisation **incrémentale** de Keycloak ; sans eux, seule la
  synchronisation complète fonctionne. Point 126.
- **`entryuuid`, `objectguid`, `nsuniqueid` valent le nom d'utilisateur**
  (`candidate/user.go`). Ce ne sont donc pas des identifiants stables : renommer
  un compte le fait apparaître comme un compte **neuf** chez tout client qui
  s'appuie dessus. Point 129.
- **`GetGroupsWithUsersByNames` fait toujours une requête SQL par groupe**
  (`core/database/db_ldap/get_groups_with_users_by_names.go:18`), alors que le
  commentaire du résolveur annonce une lecture en lot. Le N+1 **par
  utilisateur** a bien été supprimé ; celui par groupe demeure. Point 131.
- **`isInScope`** (`filter/logical.go`) n'est appelé par personne. C'est du code
  mort — mais il décrit la règle du « saut de sous-domaine » et peut faire croire
  qu'elle est appliquée au filtrage, ce qui est trompeur au moment de traiter le
  point 120. Point 131.
- **Les noms d'attributs renvoyés sont les clés minuscules** de la carte
  (`displayname`, `memberof`, `samaccountname`). La RFC rend les descriptions
  d'attributs insensibles à la casse et tous les clients courants le respectent ;
  noté pour un client exotique, pas de point ouvert.
- **`dn` est renvoyé comme attribut** en plus de l'`objectName` de la trame. Non
  standard, sans gravité ; certains outils l'affichent en double.

---

## 3. Compatibilité, client par client

### Keycloak — fonctionne, avec deux limites

Bind simple, `memberOf`, `cn` / `uid` / `mail` / `sn` / `givenName` : servis. Le
chemin a été travaillé — `userMembershipMap` est calculé tous domaines confondus
« parce qu'un client comme Keycloak s'attend à les voir tous ».
Exploitation : [`../exploitation/ldaps_keycloak.md`](../exploitation/ldaps_keycloak.md).

1. **Pas de synchronisation incrémentale** — voir 2.9. Seule la synchronisation
   complète fonctionne.
2. **Identifiant instable** — voir 2.9. Un renommage crée un compte Keycloak en
   double au lieu de renommer l'existant.
3. Au-delà de 10 000 entrées, la synchronisation complète échoue en
   `sizeLimitExceeded`, faute de pagination.

### sssd / nslcd (RFC 2307) — inutilisable

Cumul de 2.1 et 2.4 : aucun attribut POSIX, et les filtres de plage que sssd
emploie rendent zéro.

Ce n'est pas nécessairement un défaut de conception — le poste Linux est servi
par le client Vaultaire et les modules PAM. Mais alors les classes
`posixAccount` / `posixGroup` ne doivent pas être annoncées : aujourd'hui elles
promettent un service qui n'existe pas.

### Nextcloud — fonctionne

C'est le client sur lequel les entrées ont été taillées : `displayname`,
`samaccountname`, et la classe `group` ajoutée « pour Nextcloud ». Recherche et
connexion fonctionnent. Écueils : les filtres avancés qui emploient `>=` rendent
zéro (2.1), et la détection de schéma échoue (2.8).

### JumpServer / django-auth-ldap — fonctionne

Le client le mieux servi : relecture en `scope=base` sur le DN exact après
authentification (`resolveBaseScope`), et promotion one-level → subtree sur
`ou=users`. À garder à l'esprit en traitant le point 127 : c'est ce client qui a
motivé la promotion.

### Outils d'administration AD (Softerra, ADUC, Apache Directory Studio, `ldapsearch`)

Navigation et recherche simples : correctes. Le reste bute sur trois murs —
pagination absente (refus explicite, donc au moins pas de boucle infinie),
sous-schéma non analysable (2.8), filtres `>=` sur les dates qui rendent zéro
(2.1).

### Équipements réseau (FortiGate, VPN, NAS…) — fonctionne

Ces clients ne font qu'un bind simple et une lecture de `memberOf`. Réserve : le
port 389 est en clair et `RequireTLSForBind` est désactivé par défaut. Sur un
parc qui sait faire du LDAPS, l'activer est la première chose à faire.

### Clients configurés « StartTLS obligatoire »

À basculer sur LDAPS 636. L'extension n'étant plus annoncée, l'échec est franc
au lieu d'être silencieux — c'était le but du changement.
