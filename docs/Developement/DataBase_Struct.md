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
├─ gpo   [* créée par core/database/db_gpo, pas par Create_DataBase *]
│   ├─ PK: id_gpo
│   ├─ gpo_name VARCHAR(64) UNIQUE
│   ├─ scope VARCHAR(16)  -- 'machine' ou 'user' (jamais 'both' : réservé aux schémas de module)
│   ├─ description TEXT, version INT, enabled BOOLEAN
│   ├─ created_at / updated_at DATETIME
│   └─ Relations:
│       ├─ gpo_module.d_id_gpo ← FK -> gpo.id_gpo (ON DELETE CASCADE)
│       └─ gpo_group.d_id_gpo  ← FK -> gpo.id_gpo (ON DELETE CASCADE)
│
├─ gpo_module   [* un module déclaratif par ligne *]
│   ├─ PK: id_gpo_module
│   ├─ d_id_gpo FK -> gpo.id_gpo
│   ├─ module_type VARCHAR(64)   -- type du catalogue core/gpo (registry.go)
│   ├─ module_scope VARCHAR(16)  -- recopie du scope de la GPO porteuse
│   ├─ apply_order INT           -- issu du catalogue, pas de l'ordre de saisie
│   └─ params TEXT (JSON)        -- champs validés contre le schéma du module
│
├─ gpo_group   [* association groups ↔ gpo ; une GPO ne cible que des groupes *]
│   ├─ PK composite: (d_id_gpo, d_id_group)
│   ├─ d_id_gpo FK -> gpo.id_gpo
│   └─ d_id_group FK -> groups.id_group
│
├─ gpo_restriction   [* restrictions éditables, réservées au groupe vaultaire *]
│   ├─ PK: id_gpo_restriction
│   ├─ kind VARCHAR(24)      -- allow_value | path_allow | path_deny | env_deny | meta
│   ├─ module_type, field_name  -- renseignés pour kind='allow_value'
│   ├─ scope VARCHAR(16)     -- any | machine | user
│   ├─ value VARCHAR(512)    -- valeur autorisée, préfixe de chemin, ou nom de variable
│   ├─ note, updated_by, updated_at
│   └─ UNIQUE (kind, module_type, field_name, scope, value(191))
│
├─ gpo_value_definition   [* valeurs nommées porteuses d'un contenu *]
│   ├─ PK: id_gpo_value_definition
│   ├─ module_type, field_name, name
│   ├─ payload_kind VARCHAR(32)  -- command_list (extensible : core/gpo/payload.go)
│   ├─ payload TEXT              -- contenu réel (ex. une commande sudo par ligne)
│   ├─ note, updated_by, updated_at
│   └─ UNIQUE (module_type, field_name, name)
│
│  Table distincte de gpo_restriction car le contenu est long et multiligne, ce
│  qui ne tient pas dans une colonne indexée. Premier utilisateur : les jeux de
│  commandes sudo (sudoers_rule/command_set).
│
├─ gpo_field_rule   [* mode de validation d'un champ de module *]
│   ├─ PK: id_gpo_field_rule
│   ├─ module_type, field_name
│   ├─ mode VARCHAR(16)          -- list | pattern | free
│   ├─ allow_pattern VARCHAR(512) -- regex, requis en mode pattern
│   ├─ deny_pattern VARCHAR(512)  -- regex d'exclusion, prioritaire dans tous les modes
│   ├─ note, updated_by, updated_at
│   └─ UNIQUE (module_type, field_name)
│
│  Peuplement initial : core/database/db_gpo/seed/gpo_seed.sql, embarqué dans le
│  binaire (go:embed). Une instruction n'est exécutée que si sa TABLE CIBLE vient
│  d'être créée — l'existence des tables est constatée avant leur création. Une
│  valeur supprimée depuis l'interface ne peut donc pas réapparaître au
│  redémarrage, et une base créée par une version antérieure ne reçoit que les
│  tables qui lui manquaient.
│
│  Exception : les lignes de gpo_field_rule sont vérifiées à chaque démarrage
│  (INSERT IGNORE). Une règle définit COMMENT un champ se valide, pas quelles
│  valeurs sont permises ; un champ ajouté au catalogue sans règle refuserait tout.
│  Les règles existantes, même modifiées, ne sont jamais écrasées.
│
│  Lecture fail-closed : si la base ne répond pas, le jeu de restrictions est vide
│  et aucune GPO ne valide. Aucun repli sur un socle codé en dur, pour qu'une
│  panne ne rétablisse pas une valeur volontairement retirée.
│
│  Toute écriture est journalisée en SECURITY avec son auteur.
│
│  Tables supprimées (ancien modèle) : linux_gpo_distributions, group_linux_gpo.
│  Elles stockaient une commande shell brute par distribution, donc de l'exécution
│  de code arbitraire en root. dbgpo.CreateTables les DROP si elles subsistent.
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
