# Schéma de la base de données — Vaultaire

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
├─ did_login
│   ├─ PK: id_login
│   ├─ d_id_user FK -> users.id_user
│   ├─ session_key BLOB, key_time_validity TIMESTAMP
│   └─ d_id_logiciel FK -> id_logiciels.id_logiciel
│
├─ sessions
│   ├─ PK: id
│   ├─ ordinateur_id_d FK -> id_logiciels.id_logiciel
│   └─ session_nom
│
├─ users_logiciel   [* historique utilisateurs ↔ logiciels *]
│   ├─ PK composite: (d_id_user, d_id_logiciel)
│   ├─ d_id_user FK -> users.id_user
│   ├─ d_id_logiciel FK -> id_logiciels.id_logiciel
│   └─ recent_utilisation TIMESTAMP
│
├─ linux_gpo_distributions
│   ├─ PK: id
│   ├─ gpo_name, ubuntu (TEXT), debian (TEXT), rocky (TEXT)
│   └─ Relations:
│       └─ group_linux_gpo.d_id_gpo ← FK -> linux_gpo_distributions.id
│
├─ group_linux_gpo   [* association groups ↔ linux_gpo_distributions *]
│   ├─ PK composite: (d_id_group, d_id_gpo)
│   ├─ d_id_group FK -> groups.id_group
│   └─ d_id_gpo FK -> linux_gpo_distributions.id
│
├─ user_public_keys
│   ├─ PK: id_key
│   ├─ id_user FK -> users.id_user
│   ├─ public_key (TEXT) UNIQUE (unique_pubkey on first 255 chars)
│   ├─ label VARCHAR(100), created_at DATETIME
│   └─ ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
│
└─ (Insert initial data)
    └─ INSERT IGNORE INTO users (username, password, salt, date_naissance)
       VALUES ('vaultaire','5f4dcc3b5aa765d61d8327deb882cf99','abc123salt','1990-01-01');
```

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
