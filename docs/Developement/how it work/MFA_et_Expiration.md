# Second facteur et expiration des mots de passe

> **Public : développeurs.** Second facteur et expiration : où vit quoi, et pourquoi.
> Pour l'usage au quotidien, voir [`docs/Utilisation/`](../../Utilisation/).

Deux fonctionnalités traitées ensemble parce qu'elles répondent à la même
question — *cette authentification est-elle encore recevable ?* — et qu'elles
sont interrogées par les mêmes chemins.

---

## 1. Les décisions, en une page

| Sujet | Décision |
|-------|----------|
| Exigence du second facteur | **Par groupe** (`groups.mfa_required`) |
| Portée de l'expiration | **Tous les chemins** : LDAP, Ducky/PAM, service (`08_01`), web |
| Second facteur hors du portail | **Ducky/PAM** (`03_01`, TO-DO 95) : une invite après le mot de passe, `0000` quand le compte n'en a pas ; **service du cluster** (`08_01`) : obligatoire dès qu'il est posé ; **bind LDAP** : mot de passe **suivi** du code, sauf `ldap.mfa_bypass: true` |
| Mot de passe provisoire | Drapeau `must_change_password` (TO-DO 99) : la session s'ouvre, l'utilisateur est **averti** ; passée l'échéance, c'est un mot de passe **expiré** |
| Robustesse des mots de passe | Longueur minimale 12, **plancher 8 non désactivable** (TO-DO 100) ; aucune règle de complexité |
| Recours à l'expiration | Le web laisse entrer, mais **uniquement** sur la page de changement |
| Préavis | Bandeau sur le profil pendant les N derniers jours |
| TOTP | **Implémentation maison**, RFC 6238, aucune dépendance ajoutée |
| Réinitialisation du MFA d'un tiers | Nouveau droit **`write:mfa`** |
| Politique globale | Réservée au groupe `vaultaire`, expiration désactivée par défaut — la longueur minimale, elle, ne se désactive pas |
| Migration du second facteur Ducky | Réglage poussé `mfa_ducky_required`, `vlt mfa ducky on\|off` |

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

### Hors du portail : les services du cluster

Un service qui vérifie ses utilisateurs par la trame `08_01` (Nexus) porte le
second facteur **sans réglage** : le code voyage sur une ligne `otp:`, le core le
valide avec `totp.Validate` et le **consomme** avec `ConsumeMFACounter` — le même
compteur que le portail, donc un code utilisé sur l'un ne sert plus sur l'autre.

| État du compte | Réponse du core |
|---|---|
| second facteur posé, pas de code | `mfa_required` (le service affiche le champ) |
| code faux ou rejoué | `mfa_invalid` (compté comme un échec) |
| exigé par un groupe, pas encore posé | `mfa_enroll_required` — l'enrôlement se fait sur le portail |

Les clients sans saisie (docker, dnf, apt) utilisent les **jetons** du service.
Détail : [protocole, chapitre 8](./ducky-network/08-authentification-service/README.md).

### Hors du portail : le bind LDAP

LDAP n'a pas de champ pour un code. Un compte **lié** au second facteur — posé
par lui, ou imposé par un de ses groupes — fournit donc au bind son mot de
passe **suivi** du code à 6 chiffres : `MonMotDePasse123456`. C'est la
convention des annuaires qui portent un second facteur (FreeIPA, par exemple).

| État du compte | Bind LDAP (défaut) |
|---|---|
| sans second facteur | mot de passe seul |
| second facteur posé | mot de passe + code ; code validé puis **consommé** (même compteur que le portail et `08_01`) |
| imposé par un groupe, pas encore posé | refusé — l'enrôlement se fait sur le portail |
| état illisible (panne de base) | **refusé** |

Le réglage `ldap.mfa_bypass: true` (`serveur_conf.yaml`, lu au démarrage) laisse
ces comptes se lier avec le **seul** mot de passe, pour des applications
incapables de transmettre le code. Chaque bind concerné est journalisé
(`SECURITY`, « second facteur … contourné »). Préférez des comptes de service
hors des groupes soumis au second facteur.

**Ce qui a changé.** LDAP contournait le second facteur par défaut ; le seul
réglage — `RefuseBindWhenMFARequired`, jamais relié à la configuration —
refusait le bind sans offrir de moyen de le passer. La contrainte posée dans le
portail se contournait donc par LDAP. À la mise à jour, une application qui se
lie avec un compte soumis au second facteur est **refusée** : sortez ce compte
des groupes concernés, ou posez `ldap.mfa_bypass: true` le temps de la
migration.

### Le second facteur sur le chemin Ducky *(TO-DO 95)*

#### Ce qui manquait

`grep -rn "mfa\|totp" ducky-network/authentification/` ne rendait **rien**. Le
second facteur vivait sur le portail, au bind LDAP et sur les trames `08` — pas
sur le canal qui ouvre les sessions des postes, c'est-à-dire le plus utilisé de
tous.

Un compte marqué `mfa_required` dont le mot de passe fuitait était donc bloqué
sur le portail et ouvrait une session SSH sur n'importe quelle machine du parc.
Cette page annonçait par ailleurs l'expiration sur « tous les chemins, Ducky/PAM
compris » et ne signalait nulle part que le second facteur, lui, n'y était pas.

#### Comment il voyage

```
03_01   <user@domaine>
        <mot de passe>
        otp:<code>          ← en QUEUE, préfixée (TO-DO 95)
```

En queue et préfixée, comme `groups:`, `sig:`, `refresh:` et `notice:` : un core
resté à l'ancienne version lit les deux premières lignes et ignore le reste, au
lieu de prendre le code pour autre chose.

Le canal PAM transporte le champ `otp` dans son JSON, **toujours écrit, même
vide** — c'est sa *présence* qui dit au core qu'il parle à un agent récent.
Omis parce que vide, il se confondrait avec un agent ancien.

#### La convention `0000`

Le code est demandé à **chaque** ouverture de session, y compris pour les comptes
qui n'ont pas de second facteur. L'invite dit quoi taper :

```
Code a 6 chiffres (0000 si vous n'en avez pas) :
```

Côté core, pour un compte **sans** second facteur, `0000` est la **seule** valeur
acceptée. Un vrai code envoyé pour un tel compte est **refusé**, pas ignoré : cela
signale soit un agent qui se trompe de compte, soit quelqu'un qui sonde la
porte, et l'ignorer masquerait les deux.

L'inverse ne se produit pas : `0000` sur un compte qui **a** un second facteur
part à `totp.Validate`, qui le refuse. L'accepter aurait ouvert une porte
universelle — il aurait suffi de taper `0000` pour contourner le MFA de
n'importe qui.

#### Une invite, et non un code accolé au mot de passe

C'est la recette du bind LDAP, et elle y est **subie** : le protocole LDAP n'a
pas de place pour un second champ. Ici, si. Accoler rendrait ambigu tout mot de
passe qui finit par six chiffres, et mettrait le code dans la même variable que
le mot de passe — donc dans les mêmes journaux, les mêmes tampons et les mêmes
gestionnaires de mots de passe.

#### ⚠️ SSH par CLÉ PUBLIQUE

Quand sshd authentifie par clé, il **n'ouvre pas de conversation PAM** : le
module n'a personne à qui demander un code. Il envoie alors `0000`, c'est-à-dire
« je n'ai pas de second facteur ».

Conséquence, et elle est voulue : **une connexion par clé sur un compte à second
facteur est REFUSÉE**. Le chemin est fermé, pas contourné.

Pour qu'elle fonctionne avec un code, sshd doit être configuré ainsi :

```
AuthenticationMethods publickey,keyboard-interactive
KbdInteractiveAuthentication yes
```

La pile PAM tourne alors **après** la clé, et l'invite apparaît. À vérifier sur
Rocky et Debian, et à poser par GPO si besoin.

> `KbdInteractiveAuthentication yes` est de toute façon nécessaire pour que
> l'invite apparaisse, y compris sur le chemin par mot de passe.

#### La migration : `mfa_ducky_required`

Un agent d'une version antérieure n'envoie **aucun** code. Le core doit donc
l'accepter — sinon sa mise à jour coupe l'accès à tout le parc d'un coup, y
compris à la machine depuis laquelle on administre. Mais tant qu'il l'accepte, le
second facteur se contourne en installant un vieil agent.

D'où le réglage poussé, repris du point 52 (signature des GPO) parce qu'il répond
au même problème — une exigence qu'on ne peut pas activer d'un coup, et dont on
doit pouvoir sortir :

```bash
vlt mfa ducky          # lit l'état, et compte les comptes enrôlés
vlt mfa ducky on       # exige un code de tout agent
vlt mfa ducky off      # retire l'exigence, en une commande
```

`on` est **refusé** tant qu'aucun compte n'a enrôlé de second facteur : l'activer
alors n'apporterait rien — tout le monde taperait `0000` — et couperait l'accès
de toute machine dont l'agent est trop ancien.

| | Agent ancien (pas de ligne `otp:`) | Agent à jour |
|---|---|---|
| Compte **sans** second facteur, `mfa_ducky_required` off | passe | `0000` attendu |
| Compte **sans** second facteur, `mfa_ducky_required` on | **refusé** | `0000` attendu |
| Compte **avec** second facteur | **refusé**, quel que soit le réglage | code exigé et validé |

La dernière ligne mérite d'être lue : le réglage décide du sort des comptes
**ordinaires** pendant la migration. Dispenser ceux qui ont activé le second
facteur reviendrait à désactiver la fonctionnalité pour ses seuls utilisateurs.

#### Ce qui n'est pas touché : LDAP

Le protocole LDAP n'a pas de place pour un second facteur — le bind ne porte
qu'un DN et un mot de passe. L'arrangement en vigueur (code accolé, plus
`ldap.mfa_bypass`) reste ce qu'il est. **Rien n'y est changé.**

#### Où le refus s'arrête

Le motif détaillé va au **journal du core** ; le poste reçoit `permission denied`
ou `mfa required`. Distinguer les deux facteurs dans la réponse renseignerait qui
essaie des mots de passe sur le fait qu'il a trouvé le bon.

Le code n'apparaît dans **aucun** journal, et n'est mémorisé ni dans
`pamstate.AuthResult`, ni dans le tampon de la tuile Windows — qui l'efface par
`SecureZeroMemory` comme le mot de passe. C'est la règle déjà tenue pour le mot
de passe : un code TOTP vaut 90 secondes, ce qui suffit à qui lit la mémoire d'un
processus, et l'anti-rejeu ne protège que d'un **second** usage.

---

## 4. L'expiration des mots de passe

### Ce que ça change, par chemin

| Chemin | Mot de passe expiré |
|--------|---------------------|
| Bind LDAP | refusé, `invalidCredentials` |
| Ducky / PAM | refusé, **avec un message explicite** |
| Service du cluster (`08_01`, Nexus…) | refusé, code **`expired`** — le service affiche « changez-le sur le portail » |
| Interface web | connexion acceptée, **seule** la page de changement accessible |
| CLI (`vlt`) | non concerné — l'authentification y est par clé, pas par mot de passe |

Un **mot de passe provisoire périmé** (TO-DO 99) se comporte exactement comme une
ligne de ce tableau : il *est* un mot de passe expiré. C'est ce qui fait qu'il
est refusé partout sans qu'une ligne ait été ajoutée à ces quatre chemins.

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

## 4 bis. Le mot de passe provisoire *(TO-DO 99)*

### Ce à quoi il répond

Le compte d'amorçage naissait avec le mot de passe **publié dans le dépôt Git du
produit**, sans aucun drapeau « à changer », et `password_changed_at` posée au
jour même : il n'était même pas expiré. Mais le besoin dépasse ce cas — c'est
aussi ce qu'il faut pour créer un compte, pour le dépanner, et pour qu'un
administrateur réinitialise le mot de passe de quelqu'un sans le connaître
ensuite indéfiniment.

### La session s'ouvre, et l'utilisateur est averti

Un mot de passe provisoire **n'empêche pas d'ouvrir une session** — ni sur SSH,
ni sur GDM, ni sur Windows. L'utilisateur est averti à chaque connexion, et le
changement se fait sur le portail.

C'est un choix, et il se justifie : le chemin PAM est celui par lequel on se
connecte *vraiment*. Y refuser la session demanderait de changer son mot de
passe… sans pouvoir ouvrir de session pour le faire. Un employé dont le poste est
la seule porte d'entrée serait enfermé dehors par la mesure censée le protéger.

Le **portail**, lui, enferme la session sur la page de changement — et c'est
cohérent : c'est justement là qu'on change son mot de passe.

### L'échéance, elle, refuse

Un mot de passe provisoire porte une date au-delà de laquelle il ne vaut plus
rien (24 h par défaut). Passée cette date, il devient un `StateExpired`
**ordinaire** : même état, même refus, mêmes chemins.

Ce n'est pas une approximation. Un provisoire périmé et un mot de passe trop
vieux posent le même problème et appellent la même réponse, et réutiliser l'état
existant évite d'écrire une seconde fois, dans quatre handlers, la logique de
refus qui y est déjà. **C'est ce qui fait que LDAP en hérite sans qu'une ligne y
soit écrite.**

### Qui pose le drapeau, qui le lève

| Geste | Drapeau |
|---|---|
| `user.create` (création d'un compte) | **posé**, 24 h — dérogation par `temporary=non` pour un compte de service |
| `user.change_password` (réinitialisation par un tiers) | **posé**, 24 h |
| Amorçage (`CreateDefaultAdminUser`) | **posé, sans échéance** — voir ci-dessous |
| Portail `/profil` (le titulaire change son mot de passe) | **levé** |

Le compte d'amorçage est marqué **sans échéance**. L'échéance fait cesser de
fonctionner un mot de passe qu'on n'a pas remplacé à temps ; l'appliquer là
condamnerait une installation dont personne ne s'est occupé pendant deux jours —
sans laisser de recours, puisque ce compte *est* le recours.

### Le canal d'avertissement

L'avertissement est un **canal**, pas un message. Il transporte aujourd'hui « votre
mot de passe est provisoire » et « votre mot de passe expire dans N jours » — ce
préavis n'était jusqu'ici affiché que sur le portail, c'est-à-dire à l'endroit où
l'utilisateur ne va justement pas.

```
03_02   …
        notice:<texte>       ← en queue, préfixée
```

L'agent le transmet **sans l'interpréter** jusqu'au champ `notice` du JSON PAM,
et les modules C l'affichent par `pam_info`. Sur Windows, il voyage dans le champ
`message` de la réponse du tube, que la tuile sait déjà afficher.

Le **texte est composé par le core** : lui seul connaît l'état du compte, et
trois clients — PAM, GDM, Windows — auraient sinon trois formulations, dont deux
finiraient périmées. Une **seule** ligne est présentée, quelle qu'en soit la
cause : quelqu'un dont le mot de passe est à la fois provisoire et bientôt expiré
n'a pas besoin de deux messages, il a besoin de savoir qu'il doit aller sur le
portail.

> Sur SSH **par clé**, il n'y a pas de conversation PAM : le message n'atteint
> pas l'utilisateur. Sans conséquence — la session s'ouvre — mais c'est la raison
> pour laquelle l'avertissement ne peut pas tenir lieu de contrainte : il
> informe, il n'impose rien.

### La configuration livrée ne fonctionne plus

`deployments/configs/serveur_conf.yaml` ne porte plus que des marqueurs
`CHANGEZ_MOI`, et **le core refuse de démarrer** tant qu'ils sont là — ou tant
que le mot de passe d'amorçage est l'une des valeurs publiées.

Un avertissement au démarrage est lu une fois, le jour de l'installation, par
quelqu'un qui regarde si le service monte. Il est ensuite noyé dans le journal,
et personne ne le relit — surtout pas six mois plus tard, quand la préproduction
est devenue la production. Le refus arrive au seul moment où quelqu'un est devant
l'écran **et** peut corriger.

Le mot de passe de la **base**, lui, n'est qu'un avertissement : il n'ouvre pas
l'annuaire, le port de la base n'étant pas exposé par défaut, et un refus
casserait les piles de développement qui se montent tous les jours — donc serait
contourné par une variable posée une fois pour toutes.

> **`administrateur:` et non `administreur:`.** Le fichier livré écrivait
> `administreur`, la structure Go attend `administrateur` : toute la section
> était ignorée **en silence**, et le compte d'amorçage naissait avec les valeurs
> par défaut du code quoi que contienne le fichier. Le défaut restait invisible
> parce que ces valeurs étaient identiques. Le core refuse désormais de démarrer
> sur l'ancienne clé, **en la nommant**.

---

## 4 ter. La robustesse des mots de passe *(TO-DO 100)*

### Ce qui manquait

`passwordpolicy` ne portait **que** l'expiration. Aucune longueur minimale, aucun
interdit, nulle part : le portail acceptait n'importe quelle chaîne non vide,
`1234` compris, et la ligne de commande aussi.

argon2id (19 Mio, 2 passes) protège d'une attaque **hors ligne**, sur une base
volée. Il ne fait rien contre une attaque **en ligne**, et le freinage du produit
ne verrouille jamais : trois essais gratuits, puis un refus plafonné à trente
secondes, oublié au bout de quinze minutes — soit environ deux essais par minute,
indéfiniment. Les dix mots de passe les plus courants tombent en une soirée.

### La longueur, et presque rien d'autre

| | |
|---|---|
| Longueur minimale | **12** par défaut, **plancher 8 non désactivable** |
| Complexité | **aucune règle** |
| Interdits | l'identifiant du compte, les libellés de son domaine, le nom du produit, une courte liste de classiques |
| Réglage | `vlt mfa policy --min-length <n>`, ou **Admin → Politique d'authentification** |

Pas de règle de complexité : elle produit `Password1!`, qui est dans toutes les
listes, et pousse à écrire le mot de passe sur un papier. C'est la longueur qui
coûte à l'attaquant, et c'est la recommandation de l'ANSSI comme du NIST.

La comparaison des interdits se fait **après normalisation** : `P@ssw0rd` et
`password` sont le même mot de passe pour qui attaque. La longueur se compte en
**runes** et non en octets — sans quoi la règle serait plus laxiste pour qui écrit
en ASCII et plus stricte pour les autres, sans que rien ne le dise.

### Le plancher ne se désactive pas

Un réglage de sécurité qu'on peut mettre à zéro finit à zéro : il suffit d'une
installation pressée ou d'un script recopié. La valeur 0 est **refusée à
l'écriture** et **relevée au plancher à la lecture** — y compris pour une ligne
posée à la main dans `server_settings`.

Et, contrairement à l'expiration, la longueur minimale se replie **fermée** : une
politique illisible garde la valeur par défaut. Les conséquences ne sont pas
symétriques — un repli fermé sur l'expiration verrouillerait tout l'annuaire sur
une erreur de lecture, alors qu'un repli ouvert sur la longueur laisserait
seulement créer un mot de passe faible pendant la panne. Ce mot de passe-là reste
faible une fois la panne finie.

### Le point d'écriture est unique

```
passwordpolicy.PreparerNouveauMotDePasse(db, username, motDePasse)
        ├─ contrôle de robustesse
        └─ security.Hacher (argon2id)
```

Le portail, `vlt`, la réinitialisation par un administrateur et l'amorçage
passent **tous** par là, parce qu'ils ont tous besoin de la même chose :
transformer un mot de passe en clair en empreinte. Brancher le contrôle sur ce
*besoin* plutôt que sur chaque appelant est ce qui garantit qu'une cinquième
façade, écrite plus tard, sera couverte sans que personne n'y pense — c'est
exactement l'erreur que ce point corrige.

Un **test-sentinelle** (`robustesse_test.go`) parcourt le module par son arbre
syntaxique et refuse que `security.Hacher` soit appelée ailleurs. Deux exceptions,
nommées avec leur raison : le paquet qui la définit, et le **réencodage à la
connexion** — qui remplace une empreinte par une autre sans que l'utilisateur ait
choisi un nouveau mot de passe. Le contrôler là refuserait la connexion d'un
compte dont le mot de passe était acceptable le jour où il l'a choisi.

### Elle ne s'applique qu'aux mots de passe NEUFS

On ne peut pas recalculer ce qu'on refuserait : le mot de passe n'existe nulle
part, seulement son empreinte. Le parc s'y conforme à la première écriture de
chacun — exactement comme pour le passage à argon2id.

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

- [`Permissions_RBAC.md`](./Permissions_RBAC.md) — modèle RBAC, actions spéciales
- [`Base_de_donnees.md`](./Base_de_donnees.md) — schéma
- `core/testrunner/run_totp.go` — vecteurs RFC 6238
