# Passage du RBAC à l'appartenance stricte aux groupes

## Ce qui change

`permission.GetGroupIDsForUser` retournait **tous les groupes des domaines** de
l'utilisateur. Elle retourne désormais **les groupes dont il est membre**.

Avant :

```sql
-- 1. domaines des groupes de l'utilisateur
SELECT DISTINCT dg.domain_name FROM domain_group dg
JOIN groups g       ON dg.d_id_group = g.id_group
JOIN users_group ug ON ug.d_id_group = g.id_group
WHERE ug.d_id_user = ?;

-- 2. TOUS les groupes de ces domaines
SELECT g.id_group FROM groups g
INNER JOIN domain_group dg ON dg.d_id_group = g.id_group
WHERE dg.domain_name IN (...);
```

Après :

```sql
SELECT ug.d_id_group FROM users_group ug
INNER JOIN users u ON ug.d_id_user = u.id_user
WHERE u.username = ?;
```

L'aller-retour groupe → domaine → groupe ne revenait pas au point de départ, il
élargissait : un utilisateur héritait des permissions de groupes auxquels il
n'appartient pas, du seul fait de partager leur domaine.

## Ce que ça touche

Les quatre appelants sont les seuls chemins RBAC du produit :

| Fichier | Couvre |
|---|---|
| `core/command/command_manager.go:69` | toutes les commandes CLI et l'API signée |
| `core/command/command_manager.go:78` | `clear` |
| `core/web_serveur/web_admin.go:60` | `requireWebAdminWithGroupIDs`, donc toute l'interface |
| `core/permission/pre-permission-check.go:33` | `PrePermissionCheck` → `web_admin`, `auth` LDAP |

**Des comptes vont perdre des droits.** C'est l'objet même du correctif, mais il
faut savoir lesquels avant de basculer en production.

## Requête de diagnostic — à lancer AVANT la bascule

Liste les utilisateurs qui perdent des groupes, et lesquels. À exécuter sur une
copie de la base de production.

```sql
SELECT
    u.username                                   AS utilisateur,
    dg_perdu.domain_name                         AS domaine,
    g_perdu.group_name                           AS groupe_perdu,
    GROUP_CONCAT(DISTINCT up.name ORDER BY up.name SEPARATOR ', ') AS permissions_perdues
FROM users u
-- domaines auxquels l'utilisateur touche, via ses groupes réels
JOIN users_group ug        ON ug.d_id_user  = u.id_user
JOIN domain_group dg_moi   ON dg_moi.d_id_group = ug.d_id_group
-- tous les groupes de ces domaines...
JOIN domain_group dg_perdu ON dg_perdu.domain_name = dg_moi.domain_name
JOIN groups g_perdu        ON g_perdu.id_group = dg_perdu.d_id_group
-- ...dont l'utilisateur n'est PAS membre
LEFT JOIN users_group ug_verif
       ON ug_verif.d_id_user  = u.id_user
      AND ug_verif.d_id_group = g_perdu.id_group
-- permissions que ces groupes portent
LEFT JOIN group_user_permission gup ON gup.d_id_group = g_perdu.id_group
LEFT JOIN user_permission up        ON up.id_user_permission = gup.d_id_user_permission
WHERE ug_verif.d_id_user IS NULL
GROUP BY u.username, dg_perdu.domain_name, g_perdu.group_name
ORDER BY u.username, dg_perdu.domain_name;
```

**Lecture du résultat.**

- **Aucune ligne** — chaque domaine n'a qu'un groupe, ou tout le monde est dans tous les groupes de son domaine. Bascule sans effet, rien à faire.
- **Des lignes avec `permissions_perdues` vide** — les groupes concernés ne portent aucune permission. Aucun impact réel.
- **Des lignes avec des permissions** — ce sont les droits réellement retirés. Pour chacun : soit l'utilisateur devait les avoir, et il faut l'ajouter explicitement au groupe (`add -u <user> -g <groupe>`), soit il ne devait pas les avoir, et c'est précisément la faille qui se referme.

## Vérification ciblée sur les comptes sensibles

Qui perd `web_admin` ou une permission RBAC en écriture :

```sql
SELECT DISTINCT u.username, up.name AS permission_perdue
FROM users u
JOIN users_group ug        ON ug.d_id_user = u.id_user
JOIN domain_group dg_moi   ON dg_moi.d_id_group = ug.d_id_group
JOIN domain_group dg_perdu ON dg_perdu.domain_name = dg_moi.domain_name
LEFT JOIN users_group ug_verif
       ON ug_verif.d_id_user  = u.id_user
      AND ug_verif.d_id_group = dg_perdu.d_id_group
JOIN group_user_permission gup ON gup.d_id_group = dg_perdu.d_id_group
JOIN user_permission up        ON up.id_user_permission = gup.d_id_user_permission
LEFT JOIN user_permission_action upa
       ON upa.id_user_permission = up.id_user_permission
      AND upa.action_key LIKE 'write:%'
      AND upa.value <> 'nil'
WHERE ug_verif.d_id_user IS NULL
  AND (up.web_admin <> 'nil' OR upa.action_key IS NOT NULL)
ORDER BY u.username;
```

Si un administrateur légitime apparaît ici, **ajoutez-le au groupe avant la
bascule**, pas après : entre les deux, il n'a plus accès à l'interface pour se
corriger lui-même.

## Filet de sécurité

Le compte `vaultaire` est membre du groupe `vaultaire`, qui porte
`vaultaire_all` — une appartenance directe, créée par `Create_DataBase`. Il
n'est donc pas concerné par la bascule et reste le chemin d'accès garanti si un
autre compte se retrouve verrouillé dehors.
