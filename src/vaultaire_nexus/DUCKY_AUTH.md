# Vaultaire Nexus — authentification par le réseau Ducky

> **Statut : implémenté.** Le core porte la catégorie générique `08`
> (`src/vaultaire_serveur/ducky-network/serviceauth`) ; Nexus s'en sert en
> `auth.mode: ducky`. La référence du protocole est côté core :
> `docs/Developement/how it work/ducky-network/08-authentification-service/`.
> Cette page décrit **ce que fait Nexus**.

---

## 1. Pourquoi ce mode

| | LDAP | Ducky |
|---|---|---|
| Canal | TLS vers le port 636 du core | session Ducky déjà ouverte, chiffrée, **authentifiée par clé** des deux côtés |
| Identité de Nexus | aucune (ou un compte de service à mot de passe) | client **enrôlé**, type `vaultaire_nexus`, révocable dans le core |
| Second facteur | **impossible** | code TOTP transporté, vérifié et consommé par le core |
| Mot de passe expiré | refus générique | code `expired` → message clair |
| Droits | attribut `vaultaireServiceRights` + noms de groupe | ligne `rights:` + groupes `nom@domaine` |
| Révocation | vue à la relecture (compte de service requis) | vue à la relecture (`08_06 revoked`) |
| Journal du core | « ldap bind: success » | « service auth: succès … service=<id Nexus> from=<ip> » |

LDAP reste utilisable, et sert de **repli** (`auth.ducky.fallback_ldap`).

---

## 2. Déroulé

```
navigateur                  Nexus                                   core
    | identifiant + mdp        |                                       |
    |------------------------->|-- 08_01 id, mdp, from:, ref:a ------->|
    |                          |<-- 08_03 ref:a code:mfa_required -----|
    |<-- étape « code » -------|   (identifiants gardés en mémoire)    |
    | code                     |                                       |
    |------------------------->|-- 08_01 id, mdp, otp:, ref:b -------->|
    |                          |<-- 08_02 ref:b user: groups: rights: -|
    |<-- session --------------|                                       |
    |                          |-- 08_04 ref:c user: (toutes les 5 min)|
    |                          |<-- 08_05 (ou 08_06 revoked…) ---------|
```

- **Compte local** : jamais envoyé au core.
- **Basic** (docker, dnf, apt, API) : `08_01` sans `otp:`. Un compte à second
  facteur est refusé — utiliser un **jeton** `nxs_…`. Les identifiants valides sont
  mis en cache 2 minutes (docker s'authentifie à chaque couche).
- **Jetons** : vérifiés localement ; ils portent les groupes et droits du titulaire,
  mis à jour à chaque relecture. Un titulaire révoqué rend ses jetons inutilisables.

---

## 3. Code

| Fichier | Rôle |
|---|---|
| `internal/clusterlink/serviceauth.go` | émission `08_01` / `08_04`, corrélation par `ref:`, délai, traduction des codes |
| `internal/clusterlink/clusterlink.go` | raccordement, `04_09` / `04_12` / `04_14`, gestionnaire `08` branché avant toute émission |
| `internal/auth/ducky.go` | `DuckyVerifier` (interface injectée par `main`), `Ducky.Authenticate` |
| `internal/auth/service.go` | `Login(user, mdp, otp, ip)`, repli LDAP, relecture et coupure (`refreshUser`) |
| `internal/auth/auth.go` | rôle = max(droits du core, table `auth.roles`) ; groupes `nom@domaine` |
| `internal/web/mfa.go`, `ui.go` | connexion en deux étapes, identifiants en mémoire (2 min, 3 essais) |

### Traduction des réponses

| Code du core | Erreur Nexus | Effet |
|---|---|---|
| `bad_credentials`, `invalid_request` | `ErrBadCredentials` | échec compté (verrouillage) |
| `mfa_required` | `ErrMFARequired` | étape « code » |
| `mfa_invalid` | `ErrMFAInvalid` | échec compté ; nouvel essai (3 au plus) |
| `mfa_enroll_required` | `ErrMFAEnroll` | « enrôlez un second facteur sur le portail » |
| `expired` | `ErrExpired` | « changez votre mot de passe sur le portail » |
| `locked` | `ErrLocked` | « réessayez plus tard » |
| `denied` | `ErrDenied` | accès refusé |
| `revoked`, `deleted`, `unknown` | `ErrRevoked`, `ErrDeleted`, `ErrUnknown` | à la relecture : sessions fermées, droits retirés |
| `unavailable`, code inconnu, délai dépassé | `ErrUnavailable` | repli LDAP si configuré ; à la relecture, identité précédente conservée |

### Deux gardes contre les réponses croisées

1. **`ref:`** aléatoire (96 bits) par demande ; une réponse sans demande en attente
   est ignorée.
2. **`user:`** de la réponse comparé au compte demandé.

---

## 4. Configuration

```yaml
auth:
  mode: ducky
  ducky:
    fallback_ldap: false
    require_right: false
    timeout_seconds: 7
ducky:
  enable: true
  config: /etc/vaultaire_nexus/ducky.yaml
```

Sur le core, pour un groupe qui doit publier :

```bash
vlt create -p nexus-publication non --desc "Publier dans Nexus"
vlt update -pu nexus-publication auth -a 1 acme.lan
vlt update -pu nexus-publication write:nexus all
vlt add -gu Dev -p nexus-publication
```

---

## 5. Vérifié

| Test | Où |
|---|---|
| second facteur, repli, relecture, révocation, jetons | `internal/auth/auth_test.go` (`TestModeDucky`) |
| corrélation, codes, garde `user:` | `internal/clusterlink/serviceauth_test.go` |
| ordre des contrôles côté core | `ducky-network/serviceauth/handler_test.go` (core) |
| **bout en bout** contre un vrai core (MariaDB) | enrôlement, `vlt cluster list`, connexion avec droits `write:nexus` → publieur, compte sans droit refusé, second facteur (code faux, code juste, rejeu refusé), Basic refusé pour un compte à second facteur, mode LDAP avec `vaultaireServiceRights` |
