[⌂ Ducky Network](../README.md) › [Chapitre 6 — Révocation — kill switch (06)](./README.md) › 6.3

# 6.3 — RBAC, schéma de base et décisions

[← Les trames 06_01 à 06_06](./02-trames.md) · [Chapitre 7 — Interface web (07) →](../07-interface-web/README.md)

---


**Point de passage unique.** `permission.GetGroupIDsForUser` est traversé par
tous les chemins RBAC : le routeur CLI, `requireWebAdminWithGroupIDs`,
`PrePermissionCheck`. Un compte révoqué y retourne zéro groupe, donc aucune
permission nulle part — CLI, web, API et LDAP compris.

**Refus explicite aux points d'authentification**, en plus, pour la trace et
pour couper avant même d'évaluer un mot de passe :

| Chemin | Fonction |
|--------|----------|
| Ducky | `SendAuthRequest` (02_01) |
| SSH | `SSH_SEND_Pubkey_AUTH` (03_01), `SSH_SEND_Fetch_Pubkey` (03_06), `SSH_SEND_SALT` (03_04 — **obsolète**, refuse) |
| LDAP | `CanUserConnectToDomain` |
| Web | `LoginHandler` |
| API | `commandHandler`, avant la vérification de signature |

**Déclenchement** : action spéciale `write:killswitch`, ajoutée à
`specialActions` — donc aucune colonne supplémentaire dans la matrice objet ×
verbe. Vérifiée sur **tous** les domaines de l'utilisateur visé, via
`CheckPermissionsAllDomains`. Le mode `hard` exige en plus `write:delete:user`.

**Le compte `vaultaire` n'est pas révocable.** Nouvelle garde
`GuardProtectedUserRevocation` dans `core/database/protected.go`, au même
endroit que les autres : la couche base couvre ainsi le CLI, le web et l'API
d'un seul coup.

## Schéma de base

```sql
CREATE TABLE IF NOT EXISTS user_revocation (
    id_revocation  INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(255) NOT NULL,   -- texte, pas de clé étrangère : voir ci-dessous
    mode           VARCHAR(16)  NOT NULL,   -- soft | hard
    reason_code    VARCHAR(32)  NOT NULL,
    issued_by      VARCHAR(255) NOT NULL,
    issued_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    lifted_by      VARCHAR(255) NULL,
    lifted_at      DATETIME NULL,
    INDEX (username)
);

CREATE TABLE IF NOT EXISTS user_revocation_target (
    d_id_revocation INT NOT NULL,
    computeur_id    VARCHAR(255) NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending | acked | failed
    last_attempt    DATETIME NULL,
    detail          TEXT NULL,
    PRIMARY KEY (d_id_revocation, computeur_id),
    FOREIGN KEY (d_id_revocation) REFERENCES user_revocation(id_revocation) ON DELETE CASCADE
);
```

**`username` est stocké en texte, sans clé étrangère vers `users`, et c'est
délibéré.** En mode `hard` le compte est supprimé de l'annuaire : une clé
étrangère `ON DELETE CASCADE` effacerait la révocation au moment même où elle
devient utile, et le parc n'aurait plus rien à appliquer. La trace doit survivre
à son sujet.

Le marquage `soft` se lit dans `user_revocation` (une ligne active, `lifted_at`
nul), plutôt que par une colonne ajoutée à `users` — sans quoi le mode `hard`
n'aurait nulle part où vivre une fois le compte supprimé.

## Décisions validées

1. **Numérotation 06_01 à 06_06**, demandes et réponses contiguës. Libre à partir de 06_07.
2. **`delete -u` déclenche une révocation `hard`.** Corrige un défaut réel : la suppression retirait le compte de l'annuaire et laissait le compte local vivant sur chaque machine, mot de passe compris dans `/etc/shadow`. Le compte survivait à sa propre suppression.
3. **Confirmation** : aucune pour le mode `soft` (réversible, c'est un bouton d'urgence) ; saisie du nom du compte exigée pour le mode `hard` (irréversible, détruit le répertoire personnel).
4. **Lecture des groupes** : `GetGroupIDsForUser` retournait tous les groupes des domaines de l'utilisateur au lieu de ceux dont il est membre. C'était bien un défaut — une élévation de privilèges silencieuse — et il est corrigé. Procédure de bascule et requêtes de diagnostic dans `migrations/rbac_groupes_stricts.md`.

---

[← Les trames 06_01 à 06_06](./02-trames.md) · [Chapitre 7 — Interface web (07) →](../07-interface-web/README.md)
