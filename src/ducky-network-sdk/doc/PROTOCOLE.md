# Ducky Network — format et chiffrement

Référence de ce que `duckynetwork/` implémente. Utile pour déboguer une trame
refusée, ou pour écrire un client dans un autre langage.

## Cadrage

Chaque message sur le fil :

```
[1 octet]  taille de l'en-tête   ← vaut toujours 2
[2 octets] taille du payload     ← uint16 big-endian
[N octets] payload               ← chiffré
```

Le premier octet est redondant aujourd'hui, mais il autorise un en-tête plus
large sans casser les clients existants : ils rejetteront une valeur autre que 2
au lieu de lire n'importe quoi.

Le plafond est donc de **65 535 octets** par trame. C'est pour cela que les GPO
sont fragmentées (05_09 / 05_10) au lieu d'être transmises d'un bloc.

## Payload en clair

Lignes séparées par `\n` :

```
CC_SS              code de la trame : catégorie _ sous-trame
destination        « serveur_central » dans le sens montant
clé_de_session     vide avant la poignée de main
username
identifiant_client
contenu…           zéro ou plusieurs lignes
```

Les cinq premières lignes sont toujours présentes, même vides. Le contenu
commence à la sixième et peut lui-même contenir des `\n`.

## Chiffrement : le drapeau `IsSafe`

| `IsSafe` | Algorithme | Quand |
|----------|-----------|-------|
| faux | RSA-OAEP, SHA-256, label nul | avant la poignée de main |
| vrai | AES-256-GCM, nonce en préfixe, base64 | après |

**Se tromper de phase produit un échec de déchiffrement qui ressemble en tout
point à une mauvaise clé.** C'est la première chose à vérifier devant un
« déchiffrement impossible » inexpliqué.

RSA-OAEP plafonne le clair à `taille_clé - 2·taille_hash - 2` octets, soit
**446 octets pour une clé de 4096 bits**. D'où l'échange d'une clé symétrique
dès que possible : le RSA ne sert qu'à l'amorçage.

> **Note de migration.** Les versions antérieures utilisaient PKCS#1 v1.5, dont
> l'oracle de remplissage se prête à l'attaque de Bleichenbacher. Un client
> PKCS#1 v1.5 ne parlera pas à un core OAEP, et réciproquement : les deux côtés
> doivent être à jour.

## Le flux de connexion, pour tout programme

```
askkey            obtenir la clé publique du core        (en clair, une seule fois)
01_03 → 01_04     enrôlement                             (services, au premier démarrage)
01_01 → 01_02     défi : le serveur est authentifié      ← le tunnel s'ouvre ici
02_01 → 02_02     défi de session
02_03 → 02_04     une PERSONNE est authentifiée
       ou 02_11   un PROGRAMME est authentifié → 02_12 inventaire
03_04 → 03_05     sel et aléa d'un utilisateur tiers
03_01 → 03_02     preuve HMAC → verdict
```

Les catégories 01, 02 et 03 sont **identiques pour tous les programmes**. Ce qui
change d'un programme à l'autre, c'est ce qu'il fait ensuite : 04 pour un
service, 05 et 06 pour un agent.

## Les trois amorçages

### `askkey` — obtenir la clé publique du core

Le seul échange **en clair**, et il ne peut pas en être autrement : c'est
justement la clé qu'on vient chercher.

```
client → core   askkey
core → client   getkey\n-----BEGIN PUBLIC KEY-----…
```

Une clé publique n'est pas un secret. Ce qui reste ouvert, c'est la substitution
par un intermédiaire actif — la parade est de **pré-déployer** la clé du core
avec la configuration quand le réseau n'est pas de confiance. `askkey` est le
chemin commode, pas le chemin sûr.

### 01_01 / 01_02 — poignée de main, dans les deux sens

```
client → core   01_01  contenu = 16 octets d'aléa   (chiffré, clé publique du core)
core → client   01_02  contenu = le MÊME aléa       (chiffré, NOTRE clé publique)
                       ligne 3 = clé de session, 32 caractères
```

Un seul aller-retour, deux authentifications.

**Le serveur est authentifié** par le défi : nous tirons un aléa, seul le
détenteur de la clé privée du core peut le déchiffrer, le renvoyer intact prouve
qu'il l'a. Un serveur qui aurait substitué sa clé pendant le `askkey` ne peut pas
lire notre 01_01, donc ne peut pas répondre juste. **Ne pas vérifier ce retour
revient à faire confiance à n'importe qui ayant réussi à nous donner une clé.**
C'est `ErrServerNotAuthentic`, et on ne réessaie pas : reconnecter en boucle ne
fait que redonner des occasions à qui se fait passer pour le core.

**Nous sommes authentifiés** dans le même échange, sans défi supplémentaire : le
core chiffre 01_02 avec la clé publique de l'identifiant annoncé, et seul son
vrai propriétaire peut la lire. Ne pas savoir la lire signifie que le core ne
nous connaît plus sous cet identifiant — client supprimé, base réinstallée.
C'est `ErrIdentityRejected`, et la seule issue est le réenrôlement.

La clé de session voyage en ligne 3. Ce sont **32 caractères hexadécimaux
utilisés tels quels** comme clé AES-256 — les 32 octets ASCII, pas les 16 qu'ils
représentent. Les décoder casserait le tunnel.

### 01_03 → 01_04 — enrôlement d'un service

```
client → core   01_03  clé_d_enrôlement
                       clé_publique_du_client (base64)
                       libellé
core → client   01_04  identifiant_attribué      (chiffré avec la clé soumise)
                       type_de_client
        ou      01_05 / 01_06  refus, EN CLAIR
```

Trois choses à retenir :

- **la clé privée ne quitte jamais l'hôte** ; elle est produite localement. C'est
  la différence avec un agent, dont le core génère la paire et la livre avec sa
  configuration ;
- **le client ne choisit ni son identifiant ni son type** ; le premier est
  attribué, le second est porté par la clé d'enrôlement. Laisser un client
  annoncer son type reviendrait à lui laisser choisir ses privilèges ;
- **un refus arrive en clair**, une acceptation est chiffrée. Le core n'a pas
  forcément de clé publique exploitable pour nous quand il refuse : c'est
  précisément ce qui a pu échouer. Lisez un éventuel refus avant de tenter de
  déchiffrer.

## Catégorie 02 — les deux issues

```
02_01  →  identifiant + mot de passe        (dernière trame en RSA)
02_02  ←  défi                              ← IsSafe bascule ici, des deux côtés
02_03  →  défi renvoyé TEL QUEL
02_04  ←  une PERSONNE est authentifiée : droits et clés publiques
 ou
02_11  ←  un PROGRAMME est authentifié : décline ton inventaire
02_12  →  hostname, système, mémoire, processeurs
02_07  ←  refus
```

Un programme qui se présente lui-même — agent au démarrage, proxy, interface web
— s'annonce sous le compte **`vaultaire`** et reçoit 02_11. Le core ne vérifie
pas son mot de passe, et il n'a pas à le faire : l'identité de la machine a déjà
été prouvée en 01_02. Redemander un secret ici n'ajouterait qu'un secret de plus
à déployer.

Le défi 02_02 est **renvoyé intact**. Le core ne vérifie pas qu'on l'a compris,
il vérifie qu'on a pu le LIRE — or il a voyagé chiffré avec la clé de session.

`IsSafe` bascule **après** l'envoi de 02_01, des deux côtés. Inverser l'ordre
d'un seul côté produit un échec de déchiffrement indistinguable d'une mauvaise
clé.

## Catégorie 03 — authentifier quelqu'un d'autre

```
03_04  →  donne-moi le sel de cet utilisateur
03_05  ←  sel + aléa
   ── calcul local : HMAC(condensé_du_mot_de_passe, "user|aléa|session") ──
03_01  →  la preuve
03_02  ←  autorisé : clés publiques + indicateur admin
03_03  ←  refusé

03_06  →  donne-moi les clés publiques de cet utilisateur
03_07  ←  les clés
```

**Le mot de passe ne quitte jamais la machine.** C'est toute la différence avec
02_01, qui le transporte en clair dans une trame chiffrée. Ici le programme
prouve qu'il le connaît sans le dire — ce qui compte quand celui qui pose la
question n'est pas celui qui devrait détenir le secret.

L'aléa empêche de rejouer une preuve capturée ; l'identifiant de session
l'attache à cette connexion précise.

Deux pièges qui coûtent des heures :

- le HMAC se calcule sur le nom **entier, domaine compris**, tel que le core l'a
  renvoyé en 03_05. Le raccourcir donne deux condensés différents et un refus
  que rien n'explique ;
- l'ordre du condensé est **sel puis mot de passe**. L'inverser produit le même
  refus muet.

Sur 03_06, le core **ne répond pas du tout** si le compte n'existe pas, est
révoqué, ou n'a pas de droit sur la machine : répondre « refusé » ferait de cette
trame un moyen d'énumérer l'annuaire. L'appelant doit donc borner son attente.

## Catégories

| Code | Nom | Émetteurs |
|------|-----|-----------|
| 01 | Authentification serveur, enrôlement | tous |
| 02 | Authentification | tous |
| 03 | Authentification d'un utilisateur tiers | tous |
| 04 | Cluster | agent (01–08), services (09–14) |
| 05 | GPO | agent |
| 07 | Interface web | `vaultaire_web` |

## Autorisation : le catalogue

Le core décide de ce qu'un client peut émettre à partir de son **type**, lu dans
la session et fixé à la poignée de main depuis une identité prouvée — jamais
depuis le contenu d'une trame.

Le catalogue est **fermé par défaut** : ce qui n'y figure pas est refusé, et le
refus est journalisé en `SECURITY`. C'est la première chose à regarder quand une
trame nouvelle « ne passe pas » alors que le client tourne.

Le core ne s'y trouve pas lui-même : il juge les trames qu'il reçoit d'après le
type de leur émetteur, et n'a pas à juger les siennes.

## Cycle de vie d'un service dans le cluster

```
04_09  s'enregistrer      → 04_10 accepté, 04_11 refusé
04_12  battre             → 04_13 acquitté
04_14  sortir             → aucune réponse
```

Le core bascule hors ligne un service sans battement depuis **trois minutes**.
Le passage hors ligne est écrit par le serveur, pas déduit à la lecture : une vue
calculée à la volée donnerait une réponse différente selon l'instant de la
requête et ne garderait aucune trace du moment de la panne.

Un service hors ligne depuis trop longtemps est **purgé** (délai réglable,
24 h par défaut, `vlt cluster purge-delay`). Après purge, un battement reçoit
`unknown_service` : il faut rejouer 04_09. L'identité, elle, reste valable —
c'est un réenregistrement, pas un réenrôlement.
