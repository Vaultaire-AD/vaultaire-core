# Vaultaire Nexus — authentification par le réseau Ducky (proposition)

> **Statut : spécification, non implémentée.** La première version de Nexus
> authentifie les comptes Vaultaire par **LDAP** (voir README § 4). Ce document décrit
> le processus proposé pour passer par le **réseau Ducky**, et les **nouvelles trames**
> qu'il demande au core (catégorie `08`). Les changements côté core sont récapitulés
> dans [CORE_CHANGEMENTS.md](CORE_CHANGEMENTS.md) § 1, 2 et 4.
>
> Format des trames : celui de `docs/Developement/how it work/Protocole_Ducky.md`.

---

## 1. Pourquoi quitter LDAP

| | LDAP (v1) | Ducky (proposé) |
|---|---|---|
| Canal | TLS vers le port 636 du core | session Ducky déjà ouverte, chiffrée, **authentifiée par clé** des deux côtés |
| Identité de Nexus | aucune (ou un compte de service à mot de passe) | client **enrôlé**, type `vaultaire_nexus`, révocable dans le core |
| Second facteur | **impossible** (LDAP ne sait pas le porter) | code TOTP transporté, vérifié par le core |
| Expiration du mot de passe | refus générique « invalid credentials » | code `expired` → message clair à l'utilisateur |
| Droits | noms de groupe interprétés par Nexus | **clés RBAC** `read:nexus` / `write:nexus` / `write:nexus_admin` évaluées par le core |
| Révocation (kill switch) | vue au prochain rafraîchissement des groupes | vue au prochain rafraîchissement, avec un refus explicite |
| Traçabilité côté core | « ldap bind: success » sans savoir qui a demandé | journal nommant le **service** demandeur et l'adresse d'origine |
| Charge | une connexion TCP + bind par connexion | une trame sur une session persistante |

Le mode LDAP reste disponible : c'est le repli si le cluster n'est pas raccordé.

---

## 2. Vue d'ensemble

```
 navigateur / docker / dnf                 Nexus                          core
 ─────────────────────────                 ─────                          ────
                                   (au démarrage)
                                   01_01 … 02_03  ─────────────────────▶  session de service
                                   04_09          ─────────────────────▶  cluster_nodes
                                                  ◀─────────────────────  04_10

 POST /login  alice / ●●●● / 123456
        ───────────────────────────▶
                                   08_01 alice / ●●●● / otp / ip  ─────▶  débit, mot de passe,
                                                                          expiration, MFA,
                                                                          révocation, « auth »,
                                                                          clés nexus
                                                  ◀─────────────────────  08_02 alice@acme.lan
                                                                                groups, rights
        ◀───────────────────────────  session Nexus (rôle déduit des clés)

                                   (toutes les 5 min, par compte actif)
                                   08_04 alice@acme.lan ───────────────▶
                                                  ◀─────────────────────  08_05 (ou 08_06 : fin)

                                   (toutes les 15 min, facultatif)
                                   08_07 agrégats d'utilisation ───────▶  service_usage
                                                  ◀─────────────────────  08_08
```

Le mot de passe voyage **dans la session Ducky**, déjà chiffrée et authentifiée —
exactement comme sur les autres portes du core (portail web, bind LDAP, `02_03`,
`03_01`). Nexus ne le conserve pas ; il garde au plus une empreinte courte durée pour
le cache Basic de docker (2 minutes, déjà en place en v1).

---

## 3. Tableau des trames — catégorie 08

Dans la colonne 1, **la partie qui reçoit** la trame (convention du protocole).

| Name_trames | Main | Second | description | Exemple |
|---|---|---|---|---|
| Service auth | 08 | | (plage réservée : 08_01 à 08_19) | un service vérifie un compte pour son propre usage |
| serveur | | 01 | service_user_auth | le service transmet identifiant, mot de passe, code TOTP facultatif |
| client | | 02 | service_user_auth_ok | compte canonique, nom affiché, groupes, clés accordées |
| client | | 03 | service_user_auth_failed | `<code>` puis raison lisible |
| serveur | | 04 | service_user_refresh | relire groupes et clés d'un compte déjà authentifié |
| client | | 05 | service_user_refresh_ok | même contenu que 08_02 |
| client | | 06 | service_user_refresh_denied | le compte ne doit plus avoir de session |
| serveur | | 07 | service_usage_report | agrégats d'utilisation (facultatif) |
| client | | 08 | service_usage_report_ack | accusé |
| client | | 09 | service_usage_report_error | rapport refusé |

**Pourquoi une catégorie et pas des trames 02 ou 03.**
`02_0x` authentifie **le programme** qui se connecte ; `03_01` authentifie un compte
**pour ouvrir une session sur une machine** (clés SSH, `is_admin`, groupes du poste).
Un service qui vérifie un compte pour son propre usage n'est ni l'un ni l'autre : il n'a
pas de clés SSH à recevoir ni de machine à laquelle rattacher le droit `auth`.
Une catégorie à part garde aussi la restriction par sous-trame précise : l'agent n'a
aucune raison d'émettre `08_01`, Nexus aucune d'émettre `03_01`.

**Pourquoi 08.** `01` à `06` sont utilisées, `07` est déclarée pour l'interface web
(`07_01`, `07_04`). `08` est la première libre. Le nom est générique
(*service auth*) : le futur service d'API ou tout autre service web la réutilisera.

---

## 4. Format des trames

Rappel — client → serveur :

```
XX_YY
serveur_central
<session_integrity_key>
vaultaire                     ← compte du service (toujours « vaultaire »)
<client_software_id>          ← identifiant de Nexus, contrôlé contre la session
<contenu…>
```

serveur → client :

```
XX_YY
serveur_central
<session_integrity_key>
<contenu…>
```

### 08_01 — service_user_auth (service → core)

```
08_01
serveur_central
<clé de session>
vaultaire
<id Nexus>
<identifiant>                 alice  |  alice@infra.acme.lan
<mot de passe>
otp:<code>                    facultatif — ligne absente ou « otp: » vide
from:<adresse du client>      facultatif — adresse de l'utilisateur final
```

- Lignes **préfixées** (`otp:`, `from:`) plutôt que positionnelles : le mot de passe
  peut contenir n'importe quel caractère sauf le saut de ligne, et un champ ajouté plus
  tard ne décale rien (même choix que `groups:` dans `03_02`).
- **Mot de passe contenant un saut de ligne** : refusé par Nexus avant envoi.
- `from:` sert au journal et à la limitation de débit par source. Le core **ne lui fait
  pas confiance** pour une décision d'accès : il limite aussi par service.

### 08_02 — service_user_auth_ok (core → service)

```
08_02
serveur_central
<clé de session>
user:alice@infra.acme.lan
name:Alice Martin
groups:Infra@infra.acme.lan,Dev@dev.acme.lan
rights:read:nexus,write:nexus
ttl:300
```

| Ligne | Sens |
|---|---|
| `user:` | compte **canonique** `utilisateur@domaine` — c'est lui que Nexus enregistre (jetons, journal) |
| `name:` | nom affiché, facultatif |
| `groups:` | groupes `nom@domaine`, séparés par des virgules ; vide si aucun |
| `rights:` | **uniquement** les clés de la famille du service demandeur (`*:nexus*` pour Nexus) accordées au compte |
| `ttl:` | secondes avant laquelle Nexus doit relire (08_04) ; le core choisit |

Le core ne renvoie **que** les clés du service demandeur : Nexus n'a pas à savoir qu'un
compte peut réinitialiser des mots de passe.

### 08_03 — service_user_auth_failed (core → service)

```
08_03
serveur_central
<clé de session>
<code>
<raison lisible>
```

| Code | Quand | Ce que Nexus affiche |
|---|---|---|
| `bad_credentials` | compte inconnu **ou** mot de passe faux (indistinguables) | « Identifiant ou mot de passe incorrect » |
| `expired` | mot de passe expiré | « Mot de passe expiré — changez-le sur le portail Vaultaire » |
| `mfa_required` | second facteur imposé, `otp:` absent | champ « code » ajouté au formulaire, même identifiants |
| `mfa_invalid` | code faux ou rejoué | « Code invalide » |
| `locked` | limitation de débit atteinte | « Trop de tentatives, réessayez plus tard » |
| `revoked` | compte révoqué (kill switch) | message générique |
| `denied` | pas de permission `auth` sur le domaine, ou aucune clé nexus et `require_right` actif | « Accès refusé » |
| `unavailable` | base illisible, erreur interne | « Service d'authentification indisponible » — **Nexus bascule sur LDAP si configuré** |
| `obsolete` | trame d'un format que le core ne comprend plus | journalisé, message générique |

`mfa_required` n'est renvoyé **qu'après** un mot de passe correct — même règle que
`LDAP_bind.go` : qui le voit connaît déjà le mot de passe.

### 08_04 — service_user_refresh (service → core)

```
08_04
serveur_central
<clé de session>
vaultaire
<id Nexus>
user:alice@infra.acme.lan
```

Aucun secret : le compte a été authentifié par `08_01` sur **cette** session de service.
Le core le vérifie — il garde, par session de service, l'ensemble des comptes
authentifiés dans les 24 dernières heures — et refuse (`08_06 unknown`) un compte que
ce service n'a jamais présenté. Sans ce contrôle, un service compromis pourrait
énumérer les droits de tout l'annuaire.

### 08_05 — service_user_refresh_ok

Contenu identique à `08_02`.

### 08_06 — service_user_refresh_denied

```
08_06
serveur_central
<clé de session>
<code>                        revoked | deleted | expired | denied | unknown
<raison>
```

Nexus **ferme toutes les sessions** du compte et **suspend ses jetons** (ils
redeviennent valides si un `08_05` ultérieur rétablit le compte).

### 08_07 — service_usage_report (service → core, facultatif)

```
08_07
serveur_central
<clé de session>
vaultaire
<id Nexus>
period:2026-09-17T10:00:00Z/2026-09-17T10:15:00Z
<dépôt>|<paquet>|<version>|<téléchargements>|<octets>|<comptes distincts>
…
```

- **Agrégats**, jamais le journal brut : pas d'adresses, pas d'agents, pas de noms de
  comptes. Le détail reste dans Nexus.
- 500 lignes maximum par trame ; au-delà, plusieurs trames pour la même `period:`.
- Sert une vue « Dépôts » dans l'administration du core (versions déployées, adoption
  d'une release).

### 08_08 / 08_09

```
08_08\nserveur_central\n<clé>\nperiod:<…>\n<lignes retenues>
08_09\nserveur_central\n<clé>\n<code>\n<raison>
```

---

## 5. Ordre des contrôles côté core (08_01)

Le même que `SSH_SEND_Pubkey_AUTH` et `LDAP_bind.go`, pour que les trois portes se
comportent de la même façon :

1. **Type** — `clienttype.MayEmit(type, "08_01")` (déjà fait par `Split_Action`).
2. **Limitation de débit** — `ratelimit`, par compte **et** par service
   (`client_software_id`), avant même de savoir si le compte existe.
3. **Compte inconnu** → `bad_credentials`, même délai qu'un mot de passe faux.
4. **Mot de passe** — une panne de lecture n'est pas comptée comme un échec (`unavailable`).
5. **Révocation** — `permission.IsRevoked` → `revoked`.
6. **Expiration** — `passwordpolicy.Check` → `expired`.
7. **Second facteur** — `dbauthpolicy.IsMFARequired` ; si oui : `otp:` absent →
   `mfa_required`, sinon `totp.Validate` puis `dbauthpolicy.ConsumeMFACounter`
   (anti-rejeu) → `mfa_invalid` en cas d'échec.
   *Contrairement au bind LDAP, ce contrôle n'est pas optionnel* : le canal sait le porter.
8. **Permission `auth`** — `PrePermissionCheck(user, "auth")` puis
   `CheckPermissionsMultipleDomains` sur le **domaine du compte** → `denied`.
9. **Clés du service** — `permission.HasActionAnywhere` pour `read:nexus`,
   `write:nexus`, `write:nexus_admin`.
10. **Groupes** — nom et domaine, depuis la même requête que `memberOfForUser`.
11. `ratelimit.Reussite`, journal
    `service auth: success user=… service=<id Nexus> from=<from:>`, réponse `08_02`.

Chaque refus est journalisé en `SECURITY` avec le service demandeur.

---

## 6. Côté Nexus

### Configuration

```yaml
auth:
  mode: ducky
  ducky:
    fallback_ldap: true        # si le core répond « unavailable » ou si la session tombe
    require_right: false       # true : un compte sans aucune clé nexus est refusé
    refresh_seconds: 300       # plafond ; le ttl: du core peut le réduire
  roles:                       # toujours lu : complète les clés du core
    admin: []
    publisher: []
    reader: ["*"]
ducky:
  enable: true                 # obligatoire en mode ducky
```

### Rôle effectif

```
write:nexus_admin  ∈ rights  → admin
write:nexus        ∈ rights  → publisher
read:nexus         ∈ rights  → reader
sinon                        → auth.roles (groupes), sinon refus si require_right
```

Le rôle retenu est le **plus élevé** des deux sources (clés du core, table `roles`).
Les listes `readers` / `publishers` par dépôt comparent désormais `nom@domaine`
**et** `nom` (compatibilité avec la configuration v1).

### Implémentation prévue

| Fichier | Contenu |
|---|---|
| `internal/auth/ducky.go` | `Ducky.Authenticate(user, pass, otp, ip)`, `Ducky.Refresh(user)` — même interface que `LDAP` |
| `internal/clusterlink/serviceauth.go` | émission 08_01/08_04/08_07, corrélation des réponses |
| `internal/auth/service.go` | `Login` : `mode ducky` → Ducky, repli LDAP sur `unavailable` |
| `internal/web/templates/login.html` | champ « code » affiché sur `mfa_required` |
| `internal/usage/report.go` | agrégation par quart d'heure pour 08_07 |

**Corrélation des réponses.** Le protocole n'a pas d'identifiant de requête : la
réponse à `08_01` ne dit pas à quelle demande elle répond. Deux connexions simultanées
pourraient donc recevoir la réponse de l'autre. Nexus sérialise : **une seule `08_01`
en vol à la fois** par session Ducky (file d'attente, délai 7 s — celui de l'agent PAM),
et vérifie que `user:` de la réponse correspond au compte demandé (casse et domaine
normalisés). Les `08_04` passent par la même file.

Si le core ajoute un jour un identifiant de corrélation au protocole, la file pourra
être levée ; la vérification de `user:` restera.

### Cache et charge

- Docker s'authentifie à **chaque couche** : le cache Basic (2 min, empreinte
  sha256 du couple identifiant/mot de passe, en mémoire) évite une `08_01` par couche.
- Les **jetons** Nexus ne passent jamais par le core : ils sont vérifiés localement,
  avec les droits du propriétaire relus par `08_04`.
- Un compte **sans session active ni jeton utilisé** depuis 24 h n'est plus rafraîchi.

---

## 7. Séquences

### Connexion avec second facteur

```
Nexus → core   08_01  alice / ●●●● / (pas d'otp)
core  → Nexus  08_03  mfa_required
Nexus → navigateur    formulaire : code à 6 chiffres (identifiants conservés 2 min, chiffrés en mémoire)
Nexus → core   08_01  alice / ●●●● / otp:123456
core  → Nexus  08_02  user:alice@acme.lan …
```

### Compte révoqué pendant une session

```
(kill switch sur alice)
Nexus → core   08_04  user:alice@acme.lan         (au plus tard 5 min après)
core  → Nexus  08_06  revoked
Nexus                 sessions d'alice fermées, jetons suspendus, évènement « deny » au journal
```

### Core injoignable

```
Nexus → core   08_01  …  (pas de réponse en 7 s, ou session Ducky tombée)
Nexus                 fallback_ldap: true  → bind LDAP (v1)
                      fallback_ldap: false → « Service d'authentification indisponible »
                      compte local           → toujours disponible
```

---

## 8. Sécurité — ce que le core doit garantir

- **Pas d'`AssertsUser`** pour `vaultaire_nexus` : vérifier un mot de passe fourni n'est
  pas agir au nom d'un compte. Nexus ne peut déclencher aucune action d'annuaire.
- **Limitation par service** en plus de la limitation par compte : un Nexus compromis
  ne doit pas pouvoir tester l'annuaire à grande vitesse.
- **08_04 limité aux comptes présentés** par ce service (§ 4).
- **`rights:` filtré** sur la famille du service.
- **Réponses sans détail exploitable** : `bad_credentials` couvre compte inconnu et
  mot de passe faux, au même délai.
- **Journal** : chaque 08_01 nomme le service, le compte et l'adresse `from:` — jamais
  le mot de passe ni le code.

---

## 9. Plan de mise en œuvre

1. Core : type `vaultaire_nexus` (CORE_CHANGEMENTS § 1) — **Nexus s'enregistre déjà**
   (04_09/04_12/04_14 sont implémentées dans cette version).
2. Core : clés RBAC (§ 2).
3. Core : gestionnaire `08` + trames dans le catalogue du type (§ 4), tests :
   refus par type, ordre des contrôles, MFA, anti-rejeu, 08_04 hors périmètre.
4. Nexus : `auth.mode: ducky`, file de corrélation, repli LDAP, champ TOTP.
5. Nexus : 08_07 (facultatif), puis la vue « Dépôts » dans l'administration du core.
6. Documentation : `Protocole_Ducky.md` (tableau + section « Authentification par un
   service (catégorie 08) »), README de Nexus.
