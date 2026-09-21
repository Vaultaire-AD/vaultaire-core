[⌂ Ducky Network](../README.md) › [Chapitre 8 — Authentification par un service (08)](./README.md) › 8.3

# 8.3 — Ordre des contrôles et sécurité

[← Les trames 08_01 à 08_06](./02-trames.md) · [Brancher un nouveau service →](./04-brancher-un-service.md)

---

## Ordre des contrôles sur 08_01

Le même que `03_01` et le bind LDAP, pour que les portes se comportent de la
même façon. Chaque étape appelle la fonction déjà utilisée ailleurs — aucune
règle n'est réécrite (`serviceauth/deps_db.go`).

| # | Contrôle | Fonction | Refus |
|---|---|---|---|
| 0 | le type peut émettre `08_01` | `clienttype.MayEmit` (Spliter) | connexion fermée |
| 0 | le type est un service | `clienttype.IsService` | aucune réponse, `SECURITY` |
| 1 | limitation de débit, par compte **et** par service | `ratelimit.Autorise` | `locked` |
| 2 | compte connu | `dbusers.Get_User_ID_By_Username` | `bad_credentials` (+ échec) |
| 3 | mot de passe | `dbusers.VerifierMotDePasse` | `bad_credentials` (+ échec) — panne : `unavailable` |
| 4 | révocation | `permission.IsRevoked` | `revoked` |
| 5 | expiration | `passwordpolicy.Check` | `expired` — panne : on continue |
| 6 | second facteur actif | `dbauthpolicy.GetAuthState`, `totp.Validate`, `dbauthpolicy.ConsumeMFACounter` | `mfa_required`, `mfa_invalid` (+ échec) |
| 6 bis | second facteur imposé, non posé | `dbauthpolicy.IsMFARequired` (fail-closed) | `mfa_enroll_required` |
| 7 | permission `auth` sur un domaine du compte | `permission.CanUserConnectToDomain` | `denied` |
| 7 bis | compte d'amorçage `vaultaire` | — | `denied` |
| 8 | groupes et clés | `dbldap.GetMemberOfByUsername`, `permission.GetGroupIDsForUser`, `permission.HasActionAnywhere` | `unavailable` |
| 9 | succès | `ratelimit.Reussite`, journal `INFO` | — |

**Le domaine.** Un agent présente toujours `compte@domaine`. Un service reçoit
ce que l'utilisateur a tapé, le plus souvent le nom seul. Dans les deux cas, le
seul domaine valide est un **domaine principal** du compte — les deux derniers
labels du domaine d'un de ses groupes (`alice@acme.lan` pour un membre de
`infra.acme.lan`) ; un sous-domaine ou un domaine étranger est refusé. Sans
domaine, le core essaie **chacun des domaines principaux** du compte : un seul
suffit. Règle commune avec `03_01` : voir
[3.1](../03-ssh-et-groupes/01-authentification-ssh.md#le-domaine-de-connexion).

**Le second facteur est obligatoire dès qu'il est posé.** Contrairement au bind
LDAP (`ldap.mfa_bypass`), aucun réglage ne le rend facultatif sur ce canal : il
le porte dans un champ à part (`otp:`). Le compteur consommé est celui du portail — un code
utilisé ici ne sert plus nulle part.

## Ce que le core garantit

- **Pas d'`AssertsUser`.** Vérifier un mot de passe fourni n'est pas agir au nom
  d'un compte : le service ne peut déclencher aucune action d'annuaire.
- **Clés filtrées.** Le service n'apprend que les clés de sa liste `UserRights` ;
  un compte qui peut réinitialiser des mots de passe ne le lui révèle pas.
- **Limitation par service.** Un service compromis ne teste pas l'annuaire à
  grande vitesse : le compteur par source est celui du `client_software_id`.
- **Relecture bornée.** `08_04` ne vaut que pour les comptes présentés par ce
  service (24 h, 20 000 comptes au plus par service).
- **Réponses sans oracle.** `bad_credentials` couvre compte inconnu et mot de
  passe faux.
- **Journal.** Chaque vérification nomme le compte, le service et l'adresse
  `from:` — jamais le mot de passe ni le code.

```
service auth: succès (1 groupe(s), droits: write:nexus) user=bob.durand service=PJiWfemV07m5-17-09-2026 from=10.0.4.12
service auth: refusé, code de second facteur rejoué user=bob.durand service=PJiWfemV07m5-17-09-2026 from=10.0.4.12
```

## Tests

`ducky-network/serviceauth/handler_test.go` couvre : succès et filtrage des
clés, indistinction compte inconnu / mot de passe faux, second facteur (demande,
code faux, rejeu), second facteur imposé non posé, refus explicites seulement
après le mot de passe, limitation avant tout, trames malformées, mot de passe
contenant « : », relecture (périmètre par service, droit retiré, panne,
expiration de la mémoire), refus des types non service.

---

[← Les trames 08_01 à 08_06](./02-trames.md) · [Brancher un nouveau service →](./04-brancher-un-service.md)
