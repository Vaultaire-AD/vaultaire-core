[⌂ Ducky Network](../README.md) › [Chapitre 8 — Authentification par un service (08)](./README.md) › 8.2

# 8.2 — Les trames 08_01 à 08_06

[← Principe et séquence](./01-principe.md) · [Ordre des contrôles et sécurité →](./03-controles-et-securite.md)

---

Rappel : client → serveur = 5 lignes d'en-tête (`action`, `destination`,
`session_key`, `username`, `client_software_id`) ; serveur → client = 3 lignes.
Ce qui suit est le **contenu**.

**Règle des champs** : toutes les lignes sont **préfixées** (`clé:valeur`), sauf
l'identifiant et le mot de passe de `08_01`. Un champ absent est vide, un champ
ajouté plus tard ne décale rien. Une clé répétée garde sa **première** valeur.

**Corrélation** : `ref:` est choisi par le service (`[A-Za-z0-9._:-]{1,64}`) et
renvoyé tel quel. Le protocole n'a pas d'identifiant de requête : sans lui, deux
vérifications simultanées sur la même session ne sauraient pas à qui revient
chaque réponse. Le service vérifie en plus que `user:` correspond au compte
demandé.

## 08_01 — service_user_auth (service → core)

```
08_01
serveur_central
<session_integrity_key>
vaultaire
<client_software_id>
<identifiant>            alice   ou   alice@acme.lan   (domaine principal)
<mot de passe>           tel quel, « : » compris ; jamais de saut de ligne
otp:<code>               facultatif
from:<adresse>           facultatif — journal seulement
ref:<id>                 facultatif — recommandé
```

Bornes : identifiant `[A-Za-z0-9._-]{1,128}` suivi éventuellement de
`@domaine` ; mot de passe 1 à 1024 octets ; `otp:` 16 caractères au plus.
Au-delà : `invalid_request`.

## 08_02 — service_user_auth_ok (core → service)

```
08_02
serveur_central
<session_integrity_key>
ref:r2
user:alice
name:Alice Martin
groups:Dev@dev.acme.lan,Infra@infra.acme.lan
rights:read:nexus,write:nexus
ttl:300
```

| Champ | Contenu |
|---|---|
| `user:` | nom canonique du compte (sans domaine — les noms sont uniques) |
| `name:` | prénom et nom, sauts de ligne retirés |
| `groups:` | `groupe@domaine`, triés, séparés par des virgules |
| `rights:` | les clés accordées au compte **parmi** `UserRights` du type du service, triées |
| `ttl:` | secondes avant laquelle le service devrait relire (`08_04`) |

## 08_03 — service_user_auth_failed (core → service)

```
08_03
serveur_central
<session_integrity_key>
ref:r1
code:mfa_required
reason:code du second facteur requis
```

| Code | Quand | Compté comme échec |
|---|---|---|
| `invalid_request` | trame malformée | non |
| `locked` | limitation de débit atteinte | — |
| `bad_credentials` | compte inconnu **ou** mot de passe faux — indistinguables | oui |
| `unavailable` | lecture impossible (base, état MFA…) | non |
| `revoked` | compte révoqué (kill switch) | non |
| `expired` | mot de passe expiré | non |
| `mfa_required` | second facteur actif, `otp:` absent | non |
| `mfa_invalid` | code faux ou déjà consommé | oui |
| `mfa_enroll_required` | second facteur imposé par un groupe mais pas encore posé | non |
| `denied` | pas de permission `auth`, ou compte d'amorçage `vaultaire` | non |

Tous les codes après `bad_credentials` ne sont rendus **qu'après un mot de passe
correct** : qui les lit connaît déjà le mot de passe.

`reason:` est destinée au journal du service, pas à l'utilisateur.

## 08_04 — service_user_refresh (service → core)

```
08_04
serveur_central
<session_integrity_key>
vaultaire
<client_software_id>
ref:r3
user:alice
```

Aucun secret. Le core n'accepte que les comptes que **ce service** a vérifiés en
`08_01` dans les 24 dernières heures (mémoire par `client_software_id`) :
sinon `08_06 unknown`.

## 08_05 — service_user_refresh_ok

Même contenu que `08_02`.

## 08_06 — service_user_refresh_denied

```
08_06
serveur_central
<session_integrity_key>
ref:r3
code:revoked
reason:compte révoqué
```

| Code | Ce que fait le service |
|---|---|
| `revoked`, `deleted`, `expired`, `denied`, `unknown` | ferme les sessions du compte et retire ses droits (jetons compris) |
| `unavailable` | garde l'identité précédente et réessaie plus tard |
| `invalid_request` | corrige son émission |

---

[← Principe et séquence](./01-principe.md) · [Ordre des contrôles et sécurité →](./03-controles-et-securite.md)
