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
│   ├─ UNIQUE uq_did_login (d_id_user, d_id_logiciel)   ← porté par la BASE (TO-DO 107)
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
> L'unicité `(compte, machine)` est **des deux côtés** une contrainte de la
> base. Celle de `did_login` n'existait que dans le code jusqu'au point 107 —
> voir ci-dessous.

### `did_login` : l'unicité a quitté le code *(TO-DO 107)*

Elle était tenue par deux séquences **lecture-puis-écriture** : `AddLoginEntry`
faisait `SELECT EXISTS` puis `INSERT`, `RafraichirConnexion` faisait `COUNT(*)`
puis `UPDATE`. Donc deux courses. Deux authentifications simultanées de la même
paire y trouvaient toutes les deux « la ligne n'existe pas » et inséraient chacune
la leur : la machine apparaissait **deux fois** dans `status -c`.

Ce n'était pas théorique : le `--fetch-key` de sshd ouvre une session à chaque
connexion SSH, en parallèle du tunnel permanent. La fenêtre s'ouvre en
fonctionnement normal, sans que personne ne cherche à la provoquer — et c'est
exactement le doublon que le point 92 a fermé pour les sessions PAM, par une
autre porte.

Les deux écritures passent désormais par un `INSERT … ON DUPLICATE KEY UPDATE`,
et la contrainte est dans le schéma.

**Migration.** `EnsureDidLoginUnicite` (`db_schema/did_login_unicite.go`)
dédoublonne **puis** contraint : `ADD UNIQUE KEY` échoue si la table porte déjà
des doublons, c'est-à-dire précisément sur les bases qui en ont besoin. La ligne
gardée est celle dont l'identifiant est le plus grand — la dernière insérée, donc
celle qui porte la clé de session la plus récente : garder une ancienne ferait
échouer le prochain rafraîchissement, qui la cherche par sa clé.

L'appel est **non fatal** au démarrage : un core qui ne peut pas poser cet index
doit continuer à servir, en le disant en WARNING. Le nombre de lignes retirées est
journalisé.

Un test-sentinelle (`did_login_unicite_test.go`) vérifie trois choses : que le
`CREATE TABLE` d'une base neuve porte l'index, que son **nom** est le même que
celui de la migration — sinon elle tente de le reposer à chaque démarrage —, et
qu'aucun littéral SQL des deux fichiers d'écriture ne relit la table avant de
l'écrire.

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

## Mot de passe provisoire et robustesse — TO-DO 99 et 100

Deux colonnes de plus sur `users`, posées par `db_authpolicy/create_schema.go`
comme les colonnes `mfa_*` :

| Colonne | Type | Rôle |
|---|---|---|
| `must_change_password` | `BOOLEAN NOT NULL DEFAULT FALSE` | le mot de passe en place est provisoire |
| `provisional_password_until` | `DATETIME NULL` | son échéance ; NULL = pas de limite de temps, le changement reste obligatoire |

- **En base et non dans la session** : le drapeau doit survivre à une
  déconnexion, et surtout être lu par les chemins qui n'ont **pas** de session
  web — Ducky/PAM et le bind LDAP. La session web en porte une copie, que cette
  colonne renseigne.
- **Une DATE et non une durée** : la durée est un réglage global qui peut changer
  entre la pose du mot de passe et sa première utilisation. Recalculer l'échéance
  à partir de la durée du jour déplacerait celle des mots de passe déjà posés,
  dans les deux sens.
- **`BOOLEAN NOT NULL DEFAULT FALSE`** donne la bonne valeur aux lignes
  existantes sans rattrapage : un annuaire en service ne voit rien changer.
- Les deux colonnes sont lues par `GetAuthState`, dans la **même requête** que
  l'état du second facteur. Les chemins d'authentification la font déjà : leur
  faire relire le compte doublerait les requêtes sur le trajet le plus fréquent
  du serveur, et ouvrirait une fenêtre où les deux lectures ne verraient pas le
  même compte.

Un réglage de plus dans `server_settings` :

| Clé | Bornes | Défaut |
|---|---|---|
| `password_min_length` | 8 à 128, **le plancher ne se désactive pas** | 12 |

Le plancher est appliqué **à la lecture** autant qu'à l'écriture : une ligne
posée à la main, ou héritée d'une version où la borne était plus basse, ne doit
pas pouvoir abaisser la règle. Voir
[`MFA_et_Expiration.md`](./MFA_et_Expiration.md) §4 ter.

## Journal commun des cores — `server_logs`

Créée par `core/database/db_journaux/schema.go`, appelé à chaque démarrage juste
après `Create_DataBase`. Table **neuve** : `CREATE TABLE IF NOT EXISTS` suffit.
Une colonne ajoutée plus tard devra passer aussi par `EnsureColumn`.

```sql
CREATE TABLE IF NOT EXISTS server_logs (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME(6)      NOT NULL,   -- UTC
    severity   TINYINT UNSIGNED NOT NULL,   -- RFC 5424 : 0 le plus grave
    level      VARCHAR(16)      NOT NULL,
    code       VARCHAR(32)      NOT NULL DEFAULT '',
    core_name  VARCHAR(255)     NOT NULL,   -- os.Hostname() du core émetteur
    message    TEXT             NOT NULL,   -- tronqué à 8 Ko, marqué
    request_id VARCHAR(64)      NOT NULL DEFAULT '',
    user_id    VARCHAR(64)      NOT NULL DEFAULT '',
    INDEX idx_server_logs_created  (created_at),
    INDEX idx_server_logs_core     (core_name, created_at),
    INDEX idx_server_logs_severity (severity, created_at),
    INDEX idx_server_logs_code     (code, created_at)
);
```

- **`core_name` en texte, sans clé étrangère** vers `cluster_nodes` : un core
  retiré du cluster laisse ses lignes — c'est souvent pour comprendre pourquoi il
  est tombé qu'on les relit.
- **`DATETIME(6)`** : à la seconde, deux lignes de deux cores émises dans la même
  seconde ne se départagent pas. L'heure est écrite et relue en **UTC**.
- **Troncature avant insertion** : en mode SQL strict, une valeur trop longue
  fait échouer l'INSERT — et avec lui tout le lot de 200 lignes.
- **Rétention** : `log_retention_days` (30 j par défaut), purge par lots de
  10 000. La table est bornée par le temps, pas par le nombre de lignes.

## Mesures des nœuds — `proxy_metrics`

Créée par `create_data_base.go`. Une ligne par trame `04_05`.

```sql
proxy_metrics (
    id_metric      INT AUTO_INCREMENT PRIMARY KEY,
    proxy_hostname VARCHAR(255) NOT NULL,   -- celui de la ligne du DEMANDEUR
    proxy_ip       VARCHAR(45)  NOT NULL,
    metric_type    VARCHAR(64)  NOT NULL,   -- « relais » pour un vlt-proxy
    metric_value   DOUBLE       NOT NULL,   -- connexions actives
    extra          JSON,                    -- tous les autres compteurs
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_proxy (proxy_hostname),
    INDEX idx_created (created_at)
)
```

- **Une seule ligne par battement** (20 s), et non une par compteur *(TO-DO
  108)*. Six lignes toutes les vingt secondes feraient vingt-cinq mille par jour
  et par proxy — près d'un million sur la rétention, pour une vue qui n'en lit
  jamais qu'une : la dernière. `extra` est du JSON exactement pour cela.
- **`proxy_hostname` n'est pas celui du contenu de la trame** : c'est celui de la
  ligne `cluster_nodes` du demandeur. Sinon n'importe quel nœud décrivait l'état
  d'un pair. L'écart est journalisé en `SECURITY`.
- **Lecture** : `DernieresMetriquesRelais` ne prend que la **dernière** ligne par
  nœud, par `MAX(id_metric)` — et non par date : deux mesures de la même seconde
  portent la même date, ce qui arrive dès qu'un nœud rattrape un retard. Une
  mesure de plus de **trois minutes** n'est pas rendue.
- **Rétention** : `proxy_metrics_retention_days` (30 j par défaut, 0 = illimité),
  purge par lots de 10 000. Débit borné à 60 écritures par nœud et par minute.
- **Rien ne s'en sert pour décider.** Le tri de la liste servie aux agents ne lit
  pas cette table, et c'est volontaire : une `04_05` est déclarative.

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
