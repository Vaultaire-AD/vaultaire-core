# Schéma de la base de données — Vaultaire

> **Public : développeurs.** Schéma consommé par `core/database`.
> Pour l'usage au quotidien, voir [`docs/Utilisation/`](../../Utilisation/).

## Arbre ASCII

```
DATABASE: DUCKY
│
├─ users
│   ├─ PK: id_user
│   ├─ username (UNIQUE), firstname, lastname, email (UNIQUE)
│   ├─ password, salt, date_naissance, created_at
│   └─ Relations:
│       ├─ users_group.d_id_user  ← FK -> users.id_user
│       ├─ did_login.d_id_user    ← FK -> users.id_user
│       ├─ users_logiciel.d_id_user ← FK -> users.id_user
│       └─ user_public_keys.id_user ← FK -> users.id_user
│
├─ client_permission
│   ├─ PK: id_permission
│   ├─ name_permission (UNIQUE), is_admin
│   └─ Relations:
│       └─ group_permission_logiciel.d_id_permission ← FK -> client_permission.id_permission
│
├─ user_permission
│   ├─ PK: id_user_permission
│   ├─ name (UNIQUE), description
│   ├─ none, web_admin, auth, compare, search
│   └─ Relations:
│       ├─ group_user_permission.d_id_user_permission ← FK -> user_permission.id_user_permission
│       └─ user_permission_action.id_user_permission ← FK -> user_permission.id_user_permission
│
├─ user_permission_action   [RBAC : clés catégorie:action:objet]
│   ├─ PK composite: (id_user_permission, action_key)
│   ├─ id_user_permission FK -> user_permission.id_user_permission
│   ├─ action_key (ex: read:get:user, write:create:group)
│   └─ value (nil, all, ou domaines 0:/1:)
│
├─ groups
│   ├─ PK: id_group
│   ├─ group_name (UNIQUE)
│   └─ Relations:
│       ├─ domain_group.d_id_group           ← FK -> groups.id_group
│       ├─ users_group.d_id_group            ← FK -> groups.id_group
│       ├─ group_user_permission.d_id_group  ← FK -> groups.id_group
│       ├─ group_permission_logiciel.d_id_group ← FK -> groups.id_group
│       ├─ logiciel_group.d_id_group         ← FK -> groups.id_group
│       └─ group_linux_gpo.d_id_group        ← FK -> groups.id_group
│
├─ domain_group
│   ├─ PK: id_domain_group
│   ├─ d_id_group (FK -> groups.id_group)
│   └─ domain_name
│
├─ users_group    [* association users ↔ groups *]
│   ├─ PK composite: (d_id_user, d_id_group)
│   ├─ d_id_user FK -> users.id_user
│   └─ d_id_group FK -> groups.id_group
│
├─ group_user_permission   [* association groups ↔ user_permission *]
│   ├─ PK composite: (d_id_group, d_id_user_permission)
│   ├─ d_id_group FK -> groups.id_group
│   └─ d_id_user_permission FK -> user_permission.id_user_permission
│
├─ group_permission_logiciel   [* association groups ↔ client_permission *]
│   ├─ PK composite: (d_id_group, d_id_permission)
│   ├─ d_id_group FK -> groups.id_group
│   └─ d_id_permission FK -> client_permission.id_permission
│
├─ id_logiciels
│   ├─ PK: id_logiciel
│   ├─ public_key (TEXT), logiciel_type, computeur_id, hostname
│   ├─ serveur (BOOLEAN), processeur (INT), ram, os
│   └─ Relations:
│       ├─ logiciel_group.d_id_logiciel      ← FK -> id_logiciels.id_logiciel
│       ├─ did_login.d_id_logiciel           ← FK -> id_logiciels.id_logiciel
│       ├─ sessions.ordinateur_id_d          ← FK -> id_logiciels.id_logiciel
│       └─ users_logiciel.d_id_logiciel      ← FK -> id_logiciels.id_logiciel
│
├─ logiciel_group   [* association logiciels ↔ groups *]
│   ├─ PK composite: (d_id_logiciel, d_id_group)
│   ├─ d_id_logiciel FK -> id_logiciels.id_logiciel
│   └─ d_id_group FK -> groups.id_group
│
├─ did_login   [* une ligne = une session DUCKY : un tunnel, une clé *]
│   ├─ PK: id_login
│   ├─ d_id_user FK -> users.id_user
│   ├─ session_key BLOB, key_time_validity TIMESTAMP
│   └─ d_id_logiciel FK -> id_logiciels.id_logiciel
│
├─ user_sessions   [* une ligne = une session PAM : qui est devant quel poste *]
│   ├─ PK: id_user_session
│   ├─ UNIQUE (d_id_user, d_id_logiciel)   ← porté par la BASE, pas par le code
│   ├─ d_id_user FK -> users.id_user
│   ├─ opened_at, key_time_validity TIMESTAMP
│   └─ d_id_logiciel FK -> id_logiciels.id_logiciel

> **`did_login` et `user_sessions` ne se croisent jamais.** `status -c` lit la
> première pour énumérer les machines ; `status -u` lit la seconde pour dire qui
> est connecté et où. Écrire les sessions PAM dans `did_login` — ce qu'a fait la
> première version du point 68 — faisait apparaître une machine deux fois dès
> que quelqu'un s'y connectait. Un test-sentinelle analyse les littéraux SQL des
> deux paquets et refuse qu'un nom de table passe dans l'autre.
>
> L'unicité `(compte, machine)` est cette fois une contrainte de la base :
> celle de `did_login` n'existait que dans le code, et rien n'empêchait une
> ligne en double.

## Second facteur et expiration des mots de passe

Ajoutés par `core/database/db_authpolicy/schema.go`, appelé à chaque démarrage.
Ces colonnes **ne sont pas dans `CreateDataBase.go`** : elles étendent des tables
existantes, donc elles passent par un `ALTER TABLE` conditionné à
`information_schema` plutôt que par le `CREATE TABLE IF NOT EXISTS` initial. Les
bases existantes les reçoivent sans script de migration à lancer à la main.

| Table | Colonne | Type | Rôle |
|-------|---------|------|------|
| `users` | `mfa_secret` | `VARCHAR(64) NULL` | Secret TOTP partagé, base32 sans remplissage |
| `users` | `mfa_enabled` | `BOOLEAN NOT NULL DEFAULT FALSE` | Second facteur **actif**. Distinct de la présence du secret : entre la génération et la validation du premier code, le compte a un secret sans second facteur |
| `users` | `mfa_enrolled_at` | `DATETIME NULL` | Date d'activation |
| `users` | `mfa_last_counter` | `BIGINT NULL` | Dernier pas de temps consommé (anti-rejeu). En base et non en mémoire : un code vaut 90 s, un registre volatil le rendrait rejouable à chaque redémarrage |
| `users` | `password_changed_at` | `DATETIME NULL` | Base du calcul d'expiration. Posé à la création et dans la même requête que tout changement de mot de passe |
| `groups` | `mfa_required` | `BOOLEAN NOT NULL DEFAULT FALSE` | Le groupe impose le second facteur à ses membres |

```sql
CREATE TABLE IF NOT EXISTS server_settings (
    setting_key   VARCHAR(64) PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL,
    updated_by    VARCHAR(255) NULL,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

Clés reconnues : `password_max_age_days` (0 = pas d'expiration),
`password_warn_days`. Table clé/valeur et non colonnes typées — le projet n'avait
aucun endroit où poser un réglage serveur, et il en viendra d'autres. La
contrepartie, l'absence de typage en base, est absorbée par
`db_authpolicy/settings.go`, qui valide et borne chaque valeur ; **aucun appelant
ne lit cette table directement**.

À la mise à jour, les comptes existants reçoivent `password_changed_at =
created_at`. Laisser NULL aurait donné deux lectures possibles, toutes deux
mauvaises : « jamais changé donc infiniment expiré » verrouille l'annuaire d'un
coup, « inconnu donc valide » crée une population qui n'expirera jamais.

Détails et raisonnement dans [`MFA_et_Expiration.md`](./MFA_et_Expiration.md).

## Notes rapides / observations

* Les tables **d'association** (`users_group`, `logiciel_group`, `group_user_permission`, `group_permission_logiciel`, `group_linux_gpo`, `users_logiciel`) implémentent des relations N-N et ont des PK composites — c'est correct pour l'intégrité.
* Tous les `FOREIGN KEY` ont `ON DELETE CASCADE` → suppression propre (attention aux suppressions en cascade massives).
* `user_public_keys` a une contrainte `UNIQUE KEY unique_pubkey (public_key(255))` — attention : indexer une préfixe peut être ok, mais si des clés dépassent 255 caractères, la partie non indexée ne sera pas incluse dans l'unicité complète (selon MySQL/MariaDB).
* `did_login.session_key BLOB` : si ces clés ont taille limitée, préfère `VARBINARY(n)` pour pouvoir indexer si besoin.
* `user_permission` est toujours sous forme de colonnes booléennes dans ton SQL initial — tu as évoqué les transformer en texte formaté ; ici j'ai laissé la structure telle qu'elle est dans le SQL fourni.

## Prochaines actions possibles

* Générer une **version visuelle (ERD)** à partir de ce schéma (export PNG/SVG).
* Préparer un **script SQL** pour ajouter des index sur les FK.
* Écrire la **fonction Go `HasPermission`** pour parser ton format `1(...),0(...)` et résoudre l'héritage LDAP.

Dis-moi laquelle tu veux, je m'en occupe.
