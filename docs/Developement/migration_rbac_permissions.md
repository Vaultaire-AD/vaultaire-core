# Migration RBAC : anciennes colonnes → user_permission_action

Si votre base existait avant la refactorisation RBAC (catégorie:action:objet), exécutez ce script **une fois** après mise à jour du code.

## Prérequis

- Sauvegarder la base avant migration.
- Les colonnes `can_read`, `can_write`, `api_read_permission`, `api_write_permission` doivent encore exister dans `user_permission`.

## Script SQL (MySQL / MariaDB)

```sql
-- 1) Créer la table des actions granulaires si elle n'existe pas
CREATE TABLE IF NOT EXISTS user_permission_action (
    id_user_permission INT NOT NULL,
    action_key VARCHAR(128) NOT NULL,
    value TEXT DEFAULT 'nil',
    PRIMARY KEY (id_user_permission, action_key),
    FOREIGN KEY (id_user_permission) REFERENCES user_permission(id_user_permission) ON DELETE CASCADE
);

-- 2) Copier les anciennes valeurs vers les clés RBAC (exemple : même valeur pour read/get:user, read:status:user, etc.)
INSERT IGNORE INTO user_permission_action (id_user_permission, action_key, value)
SELECT id_user_permission, 'read:get:user', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:status:user', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:create:user', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:delete:user', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:update:user', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:add:user', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:get:group', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:status:group', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:create:group', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:delete:group', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:update:group', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:add:group', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:get:client', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:status:client', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:create:client', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:delete:client', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:update:client', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:add:client', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:get:permission', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:status:permission', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:create:permission', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:delete:permission', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:update:permission', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:add:permission', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:get:gpo', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'read:status:gpo', COALESCE(NULLIF(TRIM(can_read), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:create:gpo', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:delete:gpo', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:update:gpo', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission
UNION ALL SELECT id_user_permission, 'write:add:gpo', COALESCE(NULLIF(TRIM(api_write_permission), ''), 'nil') FROM user_permission;

-- 3) Supprimer les anciennes colonnes
ALTER TABLE user_permission DROP COLUMN can_read;
ALTER TABLE user_permission DROP COLUMN can_write;
ALTER TABLE user_permission DROP COLUMN api_read_permission;
ALTER TABLE user_permission DROP COLUMN api_write_permission;

-- 4) Supprimer l'ancienne table de sous-actions write si elle existe
DROP TABLE IF EXISTS user_permission_write_action;
```

En cas d’erreur sur un `DROP COLUMN` (déjà supprimé), ignorer cette ligne et poursuivre.
