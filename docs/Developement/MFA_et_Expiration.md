# Second facteur et expiration des mots de passe

Deux fonctionnalités traitées ensemble parce qu'elles répondent à la même
question — *cette authentification est-elle encore recevable ?* — et qu'elles
sont interrogées par les mêmes chemins.

---

## 1. Les décisions, en une page

| Sujet | Décision |
|-------|----------|
| Exigence du second facteur | **Par groupe** (`groups.mfa_required`) |
| Portée de l'expiration | **Tous les chemins** : LDAP, Ducky/PAM, web |
| Recours à l'expiration | Le web laisse entrer, mais **uniquement** sur la page de changement |
| Préavis | Bandeau sur le profil pendant les N derniers jours |
| TOTP | **Implémentation maison**, RFC 6238, aucune dépendance ajoutée |
| Réinitialisation du MFA d'un tiers | Nouveau droit **`write:mfa`** |
| Politique globale | Réservée au groupe `vaultaire`, désactivée par défaut |

---

## 2. Où vit quoi

| Élément | Emplacement |
|---------|-------------|
| Algorithme TOTP | `core/global/security/totp/totp.go` |
| Lecture/écriture (secrets, dates, réglages) | `core/database/db_authpolicy/` |
| Règle d'expiration | `core/auth/passwordpolicy/policy.go` |
| Étape web du second facteur | `core/web_serveur/web_login_mfa.go` |
| Enrôlement utilisateur | `core/web_serveur/web_profil_mfa.go` |
| Page de politique globale | `core/web_serveur/web_admin_authpolicy.go` |
| Sessions intermédiaires | `core/web_serveur/session/pending.go` |
| Tests | `core/testrunner/run_totp.go`, `run_password_policy.go` |

**La décision est séparée de la donnée.** `passwordpolicy.Evaluate` est une
fonction pure — politique, date, instant en entrée, état en sortie. Elle est
donc testable sans base ni attente, ce qui compte pour une règle capable de
couper l'accès à tout un annuaire.

### Schéma

Ajouté par `db_authpolicy.CreateSchema`, appelé au démarrage. Idempotent, via
`information_schema` : `ALTER TABLE ... ADD COLUMN` échoue si la colonne existe,
et avaler l'erreur 1060 masquerait aussi les vraies.

| Table | Colonne | Rôle |
|-------|---------|------|
| `users` | `mfa_secret` | Secret partagé, base32 |
| `users` | `mfa_enabled` | Distinct de la présence du secret — voir §3 |
| `users` | `mfa_enrolled_at` | Date d'activation |
| `users` | `mfa_last_counter` | Anti-rejeu, en base et non en mémoire |
| `users` | `password_changed_at` | Base du calcul d'expiration |
| `groups` | `mfa_required` | Exigence portée par le groupe |
| `server_settings` | clé/valeur | `password_max_age_days`, `password_warn_days` |

---

## 3. Le second facteur

### Pourquoi une implémentation maison

L'algorithme tient en trente lignes et n'a pas bougé depuis 2011 : compteur de
8 octets, HMAC-SHA1, troncature dynamique, modulo. Tout est dans la
bibliothèque standard. Une dépendance externe ajouterait une surface
d'approvisionnement à un projet qui en compte dix, pour du code figé.

**SHA-1 est un choix, pas un oubli.** Les applications d'authentification
ignorent en pratique le paramètre `algorithm` de l'URL `otpauth://` et supposent
SHA-1. Publier SHA-256 donnerait des codes refusés sur une partie du parc, sans
message compréhensible. Ce n'est pas un affaiblissement : les collisions de
SHA-1 ne portent pas sur les MAC à clé.

La conformité est vérifiée contre les **six vecteurs de test de la RFC 6238**
(`run_totp.go`). C'est ce qui distingue « mon code produit des chiffres » de
« mon code produit les bons chiffres » : une erreur d'offset dans la troncature
donnerait un générateur cohérent avec lui-même — le serveur validerait ses
propres codes — mais incompatible avec toutes les applications du marché.

### L'enrôlement se fait en deux temps

```
start    → secret généré, écrit en base, mfa_enabled = FALSE
confirm  → un premier code est validé  → mfa_enabled = TRUE
```

Écrire secret et activation d'un seul geste enfermerait dehors quiconque ferme
l'onglet entre l'affichage de la clé et son enregistrement dans le téléphone.
Tant que `mfa_enabled` est faux, le compte fonctionne normalement.

Recharger la page réaffiche **le même secret**, jamais un nouveau : l'utilisateur
l'a peut-être déjà enregistré, et lui en donner un autre invaliderait
silencieusement l'entrée qu'il vient de créer.

Le secret est **relu en base** à la confirmation, jamais repris d'un champ caché.
Un secret transmis par le client serait un secret *choisi* par le client :
n'importe qui pourrait activer un second facteur dont il connaît la graine sur
un compte compromis, et le verrouiller contre son propriétaire.

### Pas de QR code, et pas de script tiers

La page d'enrôlement affiche la clé et un lien `otpauth://`. Charger une
bibliothèque QR depuis un CDN était la solution facile, et la mauvaise sur cette
page précise :

- **le secret y est affiché en clair.** Un script tiers exécuté sur la même page
  peut le lire. Une compromission du CDN donnerait le second facteur de tous les
  comptes enrôlés ce jour-là ;
- un annuaire s'installe couramment sur un réseau fermé, où l'appel sortant
  échoue — la page serait cassée là où elle sert le plus ;
- l'appel révèle l'existence de l'instance à un tiers, à chaque enrôlement.

Si un QR devient nécessaire, il faudra le générer **côté serveur** ou depuis
`/static`, jamais depuis un tiers.

### L'étape intermédiaire : deux registres, pas un drapeau

Entre le mot de passe et l'ouverture de session, le jeton vit dans un registre
**séparé** (`session/pending.go`), avec son propre cookie (`mfa_pending`).

C'est le point structurant. Avec un drapeau « étape » sur la session ordinaire,
tout handler appelant `ValidateToken` sans penser à le consulter accorderait
l'accès à quelqu'un n'ayant pas présenté son second facteur. Il y a une trentaine
de handlers, et le prochain sera écrit par quelqu'un qui n'aura pas ce fichier en
tête. Avec deux registres, `ValidateToken` **ne peut pas** voir un jeton en
attente : la protection est dans la structure, pas dans la vigilance de
l'appelant.

| Propriété | Valeur | Pourquoi |
|-----------|--------|----------|
| Durée | 5 min | Le temps de sortir son téléphone, avec de la marge |
| Essais | 3 | La fenêtre accepte 3 codes ; sans borne, des dizaines de milliers d'essais en 5 minutes deviendraient une menace réelle |
| Anti-rejeu | `mfa_last_counter` en base | Un code vaut 90 s : un registre en mémoire le rendrait rejouable à chaque redémarrage — que l'attaquant peut provoquer |

L'anti-rejeu tient dans la condition SQL :

```sql
UPDATE users SET mfa_last_counter = ?
WHERE username = ? AND (mfa_last_counter IS NULL OR mfa_last_counter < ?)
```

Lire puis écrire laisserait deux requêtes concurrentes accepter le même code —
exactement le scénario d'un code intercepté et rejoué en parallèle.

### Exigence par groupe

« Au moins un groupe l'exige », jamais « tous ». Le second facteur est une
contrainte, pas un droit : un administrateur appartenant aussi à un groupe
ordinaire ne doit pas voir son exigence levée par ce second groupe.

`IsMFARequired` est **fail-closed** : une erreur de lecture conduit à *exiger* le
second facteur. Refuser à tort demande un code que l'utilisateur a déjà ;
accorder à tort lèverait la protection de tous les administrateurs pendant
l'incident.

---

## 4. L'expiration des mots de passe

### Ce que ça change, par chemin

| Chemin | Mot de passe expiré |
|--------|---------------------|
| Bind LDAP | refusé, `invalidCredentials` |
| Ducky / PAM | refusé, **avec un message explicite** |
| Interface web | connexion acceptée, **seule** la page de changement accessible |
| CLI (`vlt`) | non concerné — l'authentification y est par clé, pas par mot de passe |

**Pourquoi le message diffère entre LDAP et Ducky.** LDAP n'a pas de moyen
standard de signaler une expiration, et de l'autre côté d'un bind il y a une
application, pas un humain : elle ne peut rien faire de l'information. Ducky
porte PAM, donc quelqu'un devant une invite — lui répondre « identifiants
invalides » alors qu'il vient de taper le bon mot de passe l'enverrait au
support.

**Aucun oracle n'est créé.** Le contrôle est placé *après* la comparaison du mot
de passe : qui voit ce message connaît déjà un mot de passe valide. C'est
l'inverse du kill switch, dont le refus est muet parce qu'il *précède* toute
vérification.

### Ordre des contrôles au login web

```
1. mot de passe
2. second facteur
3. expiration du mot de passe
```

L'expiration vient **en dernier**. La placer avant le second facteur
permettrait à qui détient un mot de passe volé d'apprendre qu'il est expiré sans
avoir franchi le second facteur : un oracle offert précisément à celui contre
qui le second facteur protège.

### Le repli est OUVERT, contrairement au reste du projet

La convention Vaultaire est le fail-closed : une restriction GPO illisible
n'autorise aucune valeur, un domaine illisible exige un droit global. Ici, la
même règle donnerait « politique illisible, donc tous les mots de passe sont
expirés » — l'annuaire entier verrouillé sur une erreur de lecture, tous chemins
confondus.

**L'asymétrie des conséquences tranche.** Un repli fermé transforme un incident
de base en panne d'authentification totale ; un repli ouvert laisse passer un mot
de passe expiré, ce qui suppose que l'attaquant en connaisse déjà un valide. Le
premier risque est certain et total, le second conditionnel et borné.

Un cache de 30 secondes réduit encore la fenêtre : une lecture réussie sert de
repli aux suivantes. L'échec est journalisé en `ERROR` à chaque fois.

Même raisonnement pour une `password_changed_at` absente : le compte est
considéré **valide**, jamais expiré. Un compte ne doit pas être verrouillé par
une donnée manquante.

### Le calcul se fait en jours entiers

Un mot de passe valide « 90 jours » doit expirer le même jour quelle que soit
l'heure de sa dernière modification. Comparer des durées à la seconde ferait
expirer deux comptes changés le même jour à des moments différents —
incompréhensible pour l'utilisateur, ingérable pour le support.

Zéro jour restant vaut **expiré** : une politique à 90 jours doit refuser au 90e,
sinon elle en dure 91.

### La date est mise à jour dans la même requête que le mot de passe

```sql
UPDATE users SET ..., password = ?, salt = ?, password_changed_at = NOW() WHERE ...
```

Un appel séparé aurait fonctionné, et aurait fini par être oublié : ce chemin est
appelé depuis la page profil, la page d'administration et le CLI. Un oubli
donnerait un compte au mot de passe changé mais toujours marqué expiré, renvoyé
en boucle sur la page de changement. Ici, changer le mot de passe sans changer la
date est impossible.

À la création, `password_changed_at` est posé explicitement : le rattrapage du
schéma ne s'exécute qu'au démarrage, donc un compte créé ensuite garderait une
date nulle — un mot de passe qui n'expire jamais, invisible, et refermé au hasard
des redémarrages.

---

## 5. Le compte d'amorçage `vaultaire` est exempté

Il est déjà protégé contre la suppression, le renommage et le kill switch
(`core/database/protected.go`). L'expiration le priverait de LDAP et de
Ducky/PAM sur une simple absence d'entretien — précisément dans la situation où
l'on en a besoin, quand plus rien d'autre ne fonctionne.

> **Point de vigilance.** Ce compte porte tous les droits et son mot de passe
> n'expire jamais. Il doit être traité comme un secret d'infrastructure :
> changé à l'installation, conservé hors ligne, non utilisé au quotidien.

---

## 6. Le droit `write:mfa`

Action **spéciale**, pas clé RBAC : le second facteur n'est pas un objet de
l'annuaire, et les six clés qu'un objet `mfa` engendrerait n'auraient qu'un seul
sens utile.

Séparée de `write:update:user` dans les deux sens :

- débloquer un téléphone perdu est une tâche de support, fréquente et peu
  risquée — l'y confier ne doit pas emporter le droit de reconfigurer des
  comptes ;
- qui gère l'annuaire au quotidien ne devrait pas pouvoir retirer discrètement
  le second facteur d'un administrateur, ce qui serait le meilleur préalable à
  une reprise de compte.

Contrairement à `read:log` et `write:dns`, **elle n'est pas dans
`globalOnlyActions`** : réinitialiser un MFA vise un compte, qui appartient à des
domaines. Elle se délègue donc par domaine, et est vérifiée sur **tous** les
domaines de la cible.

Le même droit garde le réglage `mfa_required` d'un groupe : imposer ou lever le
second facteur d'un groupe entier pèse plus lourd que d'y ajouter un membre.

`write:mfa` arrive automatiquement dans `vaultaire_all` — `EnsureSuperadminActions`
part de `permission.AllActionKeys()`, pas d'une liste recopiée en SQL.

---

## 7. Page d'administration

`/admin/authpolicy`, **réservée au groupe `vaultaire`** comme les restrictions
GPO et pour la même raison : le réglage ne porte pas sur une entité d'un domaine,
il décide du jour où l'annuaire cesse d'accepter ses mots de passe.

Atteinte depuis le tableau de bord, **pas depuis le bandeau de navigation**, qui
n'est pas à modifier — même schéma que les restrictions GPO, atteintes depuis la
page GPO.

**Durée 0 par défaut = expiration désactivée.** La fonctionnalité ne s'impose pas
aux installations existantes. Activer une politique à 90 jours expire d'un coup
tout ce qui n'a pas été changé depuis trois mois : c'est le comportement correct,
et le message de confirmation le dit explicitement.

---

## 8. Diagnostic

| Symptôme | Piste |
|----------|-------|
| Codes toujours refusés | Horloge du téléphone décalée de plus de 30 s. La tolérance est de ±1 pas |
| « Ce code a déjà été utilisé » | Anti-rejeu : attendre le code suivant. Normal si la page a été soumise deux fois |
| Boucle sur la page de mot de passe | `ClearMustChangePassword` non appelé — vérifier que le changement est bien passé par `update_info` avec un mot de passe non vide |
| Un compte n'expire jamais | `password_changed_at` à NULL, ou compte `vaultaire` (exempté) |
| L'exigence de groupe ne s'applique pas | Elle est évaluée à la **connexion** ; les sessions ouvertes ne sont pas coupées |
| Politique modifiée sans effet | Cache de 30 s — mais `SetPasswordPolicy` l'invalide, donc vérifier plutôt que l'écriture a réussi |

---

## Voir aussi

- [`Permissions.md`](./Permissions.md) — modèle RBAC, actions spéciales
- [`DataBase_Struct.md`](./DataBase_Struct.md) — schéma
- `core/testrunner/run_totp.go` — vecteurs RFC 6238
