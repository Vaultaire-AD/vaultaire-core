# Vaultaire LDAP

Pour utiliser Vaultaire LDAP sur un de vos outils externes, vous devez **configurer correctement votre applicatif**.

---

## 🧾 Étape 1 : Créer un compte de connexion

Commencez par créer le compte LDAP **qui sera utilisé par votre applicatif** pour interroger l'annuaire.

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
| **UUID LDAP attribute**     | `uid`                                                                     |
| **User object classes**     | `inetOrgPerson`, `organizationalPerson`, `posixaccount`, `person`, `user` |
| **Search scope**            | `One Level` *(remontera aussi les sous-domaines)*                         |
| **Group member attribute**  | `member`                                                                  |
| **Group naming attribute**  | `group`                                                                   |
|                             |                                                                           |


## **WARNING** penser a activer la RFC 2307 quand c'est possible sinon vos user ne pourront pas se lier automatiquement a des groupes
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
