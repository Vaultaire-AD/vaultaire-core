# Vaultaire LDAP

Pour utiliser Vaultaire LDAP sur un de vos outils externes, vous devez **configurer correctement votre applicatif**.

---

## 🧾 Étape 1 : Créer un compte de connexion

Commencez par créer le compte LDAP **qui sera utilisé par votre applicatif** pour interroger l'annuaire.

> ⚠️ Le compte se lie avec son **DN et son mot de passe**, les deux. Un mot de
> passe vide est refusé d'emblée (`unwillingToPerform`), comme un mot de passe
> sans DN : si votre application reçoit ce code, c'est sa configuration qui est
> incomplète, pas le mot de passe qui est faux.

> ⚠️ Ce compte ne doit appartenir à **aucun groupe soumis au second facteur** :
> au bind, un compte MFA doit fournir son mot de passe suivi du code à 6
> chiffres, ce qu'une application ne sait pas faire. Le réglage
> `ldap.mfa_bypass: true` du core lève cette exigence, mais pour tout le parc.

---

## 🌲 Étape 2 : Définir le domaine de recherche

Vous devez ensuite définir le **domaine (ou base DN)** utilisé pour les recherches.

Par exemple, avec cette arborescence :

```bash
vaultaire eyes -g
└── com
    └── company
        ├── finance
        │   └── * Group: Finance_Group (finance.company.com)
        ├── hr
        │   └── * Group: HR_Group (hr.company.com)
        ├── it
        │   ├── * Group: IT_Group (it.company.com)
        │   └── infra
        │       └── * Group: InfraIT (infra.it.company.com)
        ├── legal
        │   └── * Group: Legal_Group (legal.company.com)
        └── marketing
            └── * Group: Marketing_Group (marketing.company.com)
```

Vous pouvez configurer un domaine de recherche comme :

```
dc=it,dc=company,dc=com
```

Cela limitera la recherche uniquement aux groupes sous `it.company.com` **et ses sous-domaines**.

> ℹ️ Les utilisateurs en dehors de ce domaine ne seront **pas visibles** pendant la synchronisation LDAP.

> 🔒 **Les droits du compte de connexion s'appliquent en plus du domaine de recherche.**
> Une entrée n'est rendue que si le compte a le droit de lire **son** domaine à
> elle, et pas seulement celui qui a été demandé. Concrètement : un compte dont la
> permission `search` porte sur `company.com` **sans propagation** obtient les
> entrées de `company.com` et **aucune** de `it.company.com`, même en recherchant
> sur toute l'arborescence. Pour qu'un compte de service voie les sous-domaines,
> donnez-lui la permission **avec propagation** sur le domaine parent.

---

## ⚠️ Important : syntaxe du DN

Veillez à toujours **séparer chaque niveau du domaine** avec `dc=`, comme dans l'exemple :

```
dc=infra,dc=it,dc=company,dc=com
```

---

# 🔧 Exemple de configuration (Keycloak)

---

## 🔐 LDAP Connection Settings

| Champ                | Valeur d’exemple                                       |
|----------------------|--------------------------------------------------------|
| **Connection URL**   | `ldap://<ip_ou_fqdn>` *(ou `ldaps://...` si TLS)*     |
| **TLS**              | `Disabled`                                             |
| **Bind Type**        | `Simple`                                               |
| **Bind DN**          | `cn=proxmox_ldap_account,dc=company,dc=com`           |
| **Bind Credentials** | `<mot_de_passe_du_compte>`                            |

> Le compte utilisé (`proxmox_ldap_account`) doit disposer de **droits de lecture** sur le domaine ciblé (`company.com` ici).  
> Une future mise à jour permettra de spécifier un chemin de droits plus précis.

---

## 👤 LDAP Searching and Updating (Utilisateurs)

| Champ                       | Valeur                                                                    |
| --------------------------- | ------------------------------------------------------------------------- |
| **Edit Mode**               | `READ_ONLY`                                                               |
| **Users DN**                | `dc=it,dc=company,dc=com`                                                 |
| **Username LDAP attribute** | `uid`                                                                     |
| **RDN LDAP attribute**      | `uid`                                                                     |
| **UUID LDAP attribute**     | `entryUUID` *(voir « L'identifiant d'une entrée » plus bas)*              |
| **User object classes**     | `inetOrgPerson`, `organizationalPerson`, `person`, `user`                 |
| **Search scope**            | `Subtree` *(voir l'avertissement ci-dessous)*                             |
| **Group member attribute**  | `member`                                                                  |
| **Group naming attribute**  | `group`                                                                   |
|                             |                                                                           |


> ⚠️ **`One Level` ne remonte plus les sous-domaines** (point 127). Le serveur
> promouvait silencieusement ces recherches en recherche d'arborescence quand le
> conteneur s'appelait `users` ; ce n'est plus le cas, `One Level` rend un niveau.
> Si vos comptes vivent dans des sous-domaines, mettez **`Subtree`** — ou
> `onelevel_subtree: true` côté serveur, qui rétablit l'ancien comportement pour
> toutes les recherches `One Level`.

> ⚠️ **`posixaccount` a été retiré de cette liste** (point 123). Le serveur ne
> l'annonce plus : il ne servait aucun attribut POSIX. Keycloak compose ces
> classes en **conjonction** — une instance encore configurée avec `posixaccount`
> ne trouvera plus aucun utilisateur, et une synchronisation peut alors supprimer
> les comptes. Retirez-le **avant** de mettre le core à jour.

> ⚠️ **N'activez PAS le mode RFC 2307.** L'avertissement qui figurait ici disait
> le contraire ; il était faux et il l'a toujours été. Le serveur ne sert aucun
> attribut POSIX — ni `uidNumber`, ni `gidNumber`, ni `memberUid` — et ne déclare
> plus les classes correspondantes. Un client en mode RFC 2307 cherche les
> appartenances par `memberUid` et n'en trouve aucune : les groupes ne se lient
> pas. C'est **`member`** qui porte les appartenances, avec des DN, et c'est la
> ligne « Group member attribute » ci-dessus qui le dit.

---

## 👥 LDAP Group Mapping

| Champ                             | Valeur                             |
|-----------------------------------|------------------------------------|
| **LDAP Groups DN**                | `dc=it,dc=company,dc=com`          |
| **Group Name LDAP Attribute**     | `cn`                               |
| **Group Object Classes**          | `groupOfNames`                     |
| **Preserve Group Inheritance**    | `OFF` *(IMPORTANT)*                |
| **Membership LDAP Attribute**     | `member`                           |
| **Membership Attribute Type**     | `UID`                              |
| **Membership User LDAP Attribute**| `uid`                              |
| **Mode**                          | `READ_ONLY`                        |
| **Member-Of LDAP Attribute**      | `memberOf`                         |

---

# 🪪 L'identifiant d'une entrée : `entryUUID`

Chaque compte et chaque groupe porte un **identifiant stable** : un UUID tiré à
sa création, qui ne change **jamais** — ni quand le compte est renommé, ni quand
il change de groupe. Un compte supprimé puis recréé sous le même nom en reçoit
un autre : ce sont bien deux comptes.

```
dn: uid=alice.dupont,ou=users,dc=acme,dc=lan
entryuuid: 40a84997-8698-4b14-9579-06f3b8d5496b
```

| Règle | Détail |
|---|---|
| Attribut **opérationnel** | il ne sort que demandé par son nom, ou par `+` |
| Sur un compte | servi aussi sous `nsUniqueId`, `objectGUID`, `guid` et `ipaUniqueID`, avec la **même** valeur en texte — pour les clients réglés sur l'un de ces noms |
| Sur un groupe | `entryUUID` seulement |
| Recherche | `(entryUUID=40a84997-…)` retrouve le compte, quel que soit son nom du moment |

**C'est l'attribut à donner à une application qui synchronise**, à la place de
`uid` : avec `uid`, renommer un compte dans Vaultaire en crée un second dans
l'application, et l'ancien y reste avec ses droits.

> ⚠️ **À la mise à jour vers la 2.2, cet identifiant change UNE fois.** Il valait
> jusque-là le nom du compte (`alice`, ou `vaultaire-alice` pour les variantes).
> Une application déjà synchronisée **sur `entryUUID`** ne reconnaît donc plus
> ses comptes au premier passage, et doit être resynchronisée — pour Keycloak,
> voir [`ldaps_keycloak.md`](../exploitation/ldaps_keycloak.md). Une application
> réglée sur `uid` ne voit rien changer ; elle garde le défaut du renommage.

---

# 📄 Lire un grand annuaire : la pagination

Une recherche ordinaire rend au plus **10 000 entrées**, puis s'arrête sur
`sizeLimitExceeded`. Au-delà, le client doit **paginer** : le contrôle
`1.2.840.113556.1.4.319` (RFC 2696), que le serveur annonce dans son RootDSE.

```bash
ldapsearch -H ldaps://vaultaire.acme.lan -D 'uid=svc_app,ou=users,dc=acme,dc=lan' -W \
  -b 'dc=acme,dc=lan' -E pr=1000/noprompt '(objectClass=inetOrgPerson)' uid mail
```

| Règle | Détail |
|---|---|
| Taille de page | celle que le client demande, **plafonnée à 1 000** — le serveur peut rendre moins que demandé, tous les clients le gèrent |
| Ce qui est lu | l'annuaire **tel qu'il était à la première page** : un compte créé pendant la lecture n'y figure pas, un compte supprimé y figure encore. Chaque entrée est servie une fois |
| Délai entre deux pages | **5 minutes**. Au-delà, la recherche est à refaire |
| Limite | 200 000 entrées par recherche ; au-delà, la dernière page porte `sizeLimitExceeded` |
| Le cookie | vaut une fois, sur la connexion qui l'a reçu, pour le même compte et la même recherche. Changer de filtre en route, ou rejouer une page, est refusé (`unwillingToPerform`) |
| `busy` (51) | trop de lectures paginées en cours sur le serveur : rejouer la recherche un peu plus tard |

Dans Keycloak : **Pagination = On**. Nextcloud pagine de lui-même dès que le
serveur l'annonce.

Ces limites sont les valeurs livrées. Elles se règlent dans `serveur_conf.yaml`,
section `ldap.limites` — comment les choisir, et ce qu'elles coûtent en
mémoire : [`../exploitation/ldap_bornes.md`](../exploitation/ldap_bornes.md).

---

# 👥 `memberOf` : les groupes qu'un compte peut lire

L'attribut `memberOf` d'un utilisateur ne nomme que les groupes que **le compte
de connexion a le droit de lire** — ceux qu'il recevrait en cherchant les
groupes.

Un compte autorisé sur `acme.lan` **sans propagation** ne voit donc, dans le
`memberOf` d'un utilisateur, que ses groupes de `acme.lan` : ceux de
`dev.acme.lan` n'y figurent pas, et un filtre `(memberOf=…)` qui nomme l'un
d'eux ne trouve rien. Avec la propagation, tous y sont.

Si une application ne retrouve pas les groupes d'un sous-domaine, c'est ce
droit qu'il faut regarder : `get -p -u <permission>`, ligne `search`.

---

# 🔎 Comprendre ce que fait un client : le journal

Pour voir ce qu'une application demande réellement, allumez le détail de
l'annuaire **seul** — sans le reste du mode debug :

```text
vlt update -debug ldap debug     # une ligne par opération
vlt update -debug ldap off       # quand c'est fini
```

Chaque opération écrit **une** ligne sur la sortie du core, sous le numéro de sa
connexion :

```
ldap conn=17 ouverte LDAPS depuis 10.0.0.5:51234
ldap conn=17 msg=1 BIND dn="uid=svc_app,ou=users,dc=acme,dc=lan" → 0 success, 38 ms
ldap conn=17 msg=2 SEARCH base="dc=acme,dc=lan" scope=sub filtre="(uid=alice)" attrs="uid mail" → 0 success, 1 entrée(s), 4 ms ; candidats=214
ldap conn=17 msg=3 UNBIND → sans réponse, 0 ms
ldap conn=17 fermée (unbind) après 52 ms : 3 opération(s), 1 entrée(s), compte svc_app
```

| Ce qu'on y lit | |
|---|---|
| `conn=17` | la connexion : `grep 'conn=17 '` rend toute la conversation, refus compris |
| `msg=2` | le numéro du message, celui que le client écrit dans ses propres journaux |
| `filtre="…"` | le filtre **tel que le serveur l'a reçu** — à rejouer avec `ldapsearch` |
| `→ 0 success` | le code rendu au client (`32 noSuchObject`, `49 invalidCredentials`, `50 insufficientAccessRights`…) |
| `candidats=`, `hors-droits=` | combien d'entrées étaient dans la portée, combien ont été écartées par les droits du compte |

Zéro entrée avec `hors-droits=` renseigné : la recherche est juste, c'est le
droit `search` du compte qui ne couvre pas ces entrées. Zéro entrée sans lui :
c'est le filtre ou la base.

`vlt update -debug ldap trace` ajoute le déroulé — paquets reçus, contenu des
entrées rendues. À réserver à un diagnostic : ces lignes portent des données de
l'annuaire. Ce détail ne part jamais dans le journal commun (`vlt logs`) : il se
lit sur le core lui-même.

---

# 🔑 Droits de service : l'attribut `vaultaireServiceRights`

Une application qui a ses propres niveaux d'accès — le dépôt **Nexus**, par
exemple — peut lire dans l'annuaire les **droits de service** accordés à un
compte dans Vaultaire, au lieu de les déduire des noms de groupe.

```bash
ldapsearch -H ldaps://vaultaire.acme.lan -D 'uid=bob.durand,dc=acme,dc=lan' -W \
  -b 'dc=acme,dc=lan' '(uid=bob.durand)' uid memberOf vaultaireServiceRights
```

```
dn: uid=bob.durand,ou=users,dc=acme,dc=lan
uid: bob.durand
memberof: cn=Dev,ou=groups,dc=acme,dc=lan
vaultaireservicerights: write:nexus
```

| Règle | Détail |
|---|---|
| Attribut **opérationnel** | il n'est renvoyé que s'il est **demandé par son nom** — ni `*` ni `+` ne le déclenchent |
| Valeurs | les clés de service accordées au compte : aujourd'hui `read:nexus`, `write:nexus`, `write:nexus_admin` |
| Absent | le compte n'a aucune de ces clés (un attribut LDAP ne peut pas être vide) |
| Qui peut le lire | le **compte lui-même**, ou un compte qui porte `read:get:user` sur le domaine de l'entrée ; pour les autres il est simplement absent |
| Révocation | un compte révoqué n'a plus aucune clé |

Les droits s'accordent dans l'interface d'administration (**Permissions →
Actions hors matrice**) ou avec `vlt update -pu <permission> read:nexus all`.
Voir [`Actions_et_Permissions.md`](./Actions_et_Permissions.md) § « Droits de
service ».

> **Second facteur.** LDAP ne sait pas porter de code TOTP. Pour les comptes
> soumis au second facteur, préférez l'authentification par le réseau Ducky
> (trame `08_01`), que Nexus sait utiliser.
