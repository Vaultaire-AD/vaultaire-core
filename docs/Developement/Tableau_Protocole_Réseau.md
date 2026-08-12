dans la colone 1 serveur ou client c'est le partie qui recoit la tramme pas qui l'envoie

| Name_trames                 | Main Number | Second Number | desciption                       | Example                                                                                   |
| --------------------------- | ----------- | ------------- | -------------------------------- | ----------------------------------------------------------------------------------------- |
| Server auth                 | 01          |               |                                  |                                                                                           |
| serveur                     |             | 01            | client ask server auth           |                                                                                           |
| client                      |             | 02            | serveur proof of work            |                                                                                           |
|                             |             |               |                                  |                                                                                           |
| server                      |             | 05            | service ask for enrollement      | le client envoie une trame avec une clé tmp et la clé d'enrollement                       |
| client                      |             | 06            | server respond                   | le serveur valide les infos et lui renvoie les infos du client qu'il vient de crée        |
| server                      |             | 07            | client send pubkey               | apres avoir recu les infos et les avoir enregistré le client envoit sa clé via la clé TMP |
| client                      |             | 08            | server respond ok                | le serveur chiffre ok via la clé public du client pour validé l'enregistrement             |
| client                      |             | 09            | enroll denied                    | refus, EN CLAIR : le serveur n'a ni clé publique du client ni clé tmp utilisable            |
|                             |             |               |                                  |                                                                                           |
| User auth                   | 02          |               |                                  |                                                                                           |
| serveur                     |             | 01            | ask auth                         | le client demande une auth pour le user qui tente de se co                                |
| client                      |             | 02            | proof of work                    | 02_03\nserveur_central\nvisiteur\nIJVSEMNJA\nfeisfjsefijsmefjsmefj                        |
| serveur                     |             | 03            | check auth                       | verifie les informations envoyépar le user pour valider l'auth                            |
| client                      |             | 04            | auth_succes                      | quand l'auht a reussit                                                                    |
| serveur                     |             | 05            | close session                    | ferme la session pour que le user se logout                                               |
|                             |             |               |                                  |                                                                                           |
| client                      |             | 07            | failed                           | trame que recoit le client si echec de l'auth                                             |
|                             |             |               |                                  |                                                                                           |
| client                      |             | 11            | ask_information                  | le serveur va demander des information au pc hostname etc                                 |
| serveur                     |             | 12            | serveur_information              | la trame d'information envoyé par les softwares serveur                                   |
| serveur                     |             | 13            | client_information               | la trame d'information envoyé par les softwares client                                    |
|                             |             |               |                                  |                                                                                           |
| server                      |             | 17            | ask list proxy/core              | le client Demande la liste des serveurs a joindre pour se connecter au réseau             |
| client                      |             | 18            | respond list                     | le serveur repond la liste des serveur joignable                                          |
|                             |             |               |                                  |                                                                                           |
| SSH                         | 03          |               |                                  |                                                                                           |
| server                      |             | 01            | client ask if user can login     | le client envoie un username/password et attend  d'auth avec les clé public du user       |
| client                      |             | 02            | server awnser   succes           | le server renvoie un succes  avec les clé public du user et le boolean admin              |
| client                      |             | 03            | server anwser failed             | le server renvoie un failed avec la raison de l'echec                                     |
| server                      |             | 04            | client ask for salt              | le client demande le salt d'un user                                                       |
| client                      |             | 05            | server respond with key          | le serveur repond simplement le salt du user                                              |
|                             |             |               |                                  |                                                                                           |
| Cluster / Service discovery | 04          |               | (plage réservée : 04_01 à 04_19) |                                                                                           |
| client (host/proxy)         |             | 01            | register_host                    | enregistrement d’un hôte (proxy, etc.) : hostname, fqdn, ip, role, domain                 |
| serveur                     |             | 02            | register_host_ok                 | confirmation + session considérée établie pour le host                                    |
| client                      |             | 03            | list_cores                       | demande la liste des Cores en ligne (service discovery)                                   |
| serveur                     |             | 04            | list_cores_response              | liste des Cores (id, hostname, ip, port, stress, capabilities)                            |
| client                      |             | 05            | proxy_metrics                    | envoi des métriques du proxy vers le Core (pour table proxy_metrics)                      |
| serveur                     |             | 06            | proxy_metrics_ack                | accusé de réception                                                                       |
| client                      |             | 07            | host_heartbeat                   | heartbeat du host pour rester dans cluster_nodes (online)                                 |
| serveur                     |             | 08            | host_heartbeat_ack               | accusé heartbeat                                                                          |
|                             |             |               |                                  |                                                                                           |
| GPO                         | 05          |               | (plage utilisée : 05_01 à 05_17) | voir « Détail du transport GPO » en fin de document                                       |
| serveur                     |             | 01            | ask_gpo_machine                  | le client demande ses GPO machine, en annonçant l'empreinte qu'il applique déjà           |
| client                      |             | 02            | gpo_machine_manifest             | réponse succès à 05_01 : version, empreinte, découpage                                    |
| client                      |             | 03            | gpo_machine_unchanged            | réponse à 05_01 : l'empreinte du client est à jour, rien à appliquer                      |
| client                      |             | 04            | gpo_machine_error                | réponse erreur à 05_01                                                                    |
| serveur                     |             | 05            | ask_gpo_user                     | le client demande les GPO user après authentification, avec son empreinte courante        |
|                             |             |               |                                  | attention ne seront appliquées que les GPO user des groupes auxquels appartiennent        |
|                             |             |               |                                  | a la fois la machine et a la fois l'utilisateur                                           |
|                             |             |               |                                  | et non l'ensemble des GPO user liées a l'utilisateur                                      |
| client                      |             | 06            | gpo_user_manifest                | réponse succès à 05_05 : version, empreinte, découpage                                    |
| client                      |             | 07            | gpo_user_unchanged               | réponse à 05_05 : l'empreinte du client est à jour, rien à appliquer                      |
| client                      |             | 08            | gpo_user_error                   | réponse erreur à 05_05                                                                    |
| serveur                     |             | 09            | ask_gpo_chunk                    | le client réclame un fragment de la politique annoncée (les deux scopes)                  |
| client                      |             | 10            | gpo_chunk                        | réponse succès à 05_09 : un fragment de politique                                         |
| client                      |             | 11            | gpo_chunk_error                  | réponse erreur à 05_09 : empreinte périmée, index invalide, transfert inconnu             |
| serveur                     |             | 12            | gpo_apply_report                 | le client rapporte le résultat de l'application, module par module (les deux scopes)      |
| client                      |             | 13            | gpo_apply_report_ack             | réponse succès à 05_12                                                                    |
| client                      |             | 14            | gpo_apply_report_error           | réponse erreur à 05_12 : rapport malformé ou empreinte inconnue                           |
| serveur                     |             | 15            | gpo_drift_report                 | le client rapporte le résultat d'un scan de conformité : fichiers vérifiés, écarts        |
| client                      |             | 16            | gpo_drift_report_ack             | réponse succès à 05_15                                                                    |
| client                      |             | 17            | gpo_drift_report_error           | réponse erreur à 05_15 : rapport malformé ou enregistrement impossible                    |
|                             |             |               |                                  |                                                                                           |
| Révocation (kill switch)    | 06          |               | (plage utilisée : 06_01 à 06_06) | voir « Détail de la révocation » en fin de document                                       |
| client                      |             | 01            | revoke_order                     | le serveur ordonne de verrouiller, déverrouiller ou supprimer un compte local             |
| serveur                     |             | 02            | revoke_ack                       | réponse succès à 06_01 : ordre appliqué                                                   |
| serveur                     |             | 03            | revoke_error                     | réponse erreur à 06_01                                                                    |
| serveur                     |             | 04            | ask_revocations                  | le client réclame les ordres en attente (démarrage, reconnexion)                          |
| client                      |             | 05            | revocations_list                 | réponse succès à 06_04 : liste des ordres non acquittés                                   |
| client                      |             | 06            | revocations_error                | réponse erreur à 06_04                                                                    |


## Chiffrement du canal

Deux régimes se succèdent sur une même connexion, et la bascule se fait à
l'établissement de la clé de session (`duckysession.IsSafe`).

| Phase | Schéma | Clé |
|-------|--------|-----|
| Avant `IsSafe` | **RSA-4096 OAEP, SHA-256, label nil** | clé publique du destinataire |
| Après `IsSafe` | AES-GCM | clé de session |

### RSA-OAEP et non PKCS#1 v1.5

Le bourrage PKCS#1 v1.5 était utilisé jusqu'à la version 2.1. Il est vulnérable à
l'attaque de Bleichenbacher — un oracle de bourrage à texte chiffré choisi — et
les trois conditions étaient réunies pour l'exploiter **sans posséder le moindre
identifiant** :

- la clé publique du serveur s'obtient par un `askkey` non authentifié ;
- tant que `IsSafe` est faux, le serveur déchiffre avec sa clé privée **toute**
  trame reçue (`trames_manager/ReadMessageContent.go`) ;
- l'échec de déchiffrement était observable — journal `CRITICAL`, et comportement
  différent en aval.

Un attaquant ayant enregistré un échange de clé de session pouvait donc la
déchiffrer hors ligne. OAEP ferme ce chemin : bourrage probabiliste, et
vérification qui ne laisse pas fuir d'information exploitable.

**Les clés n'ont pas changé.** OAEP est un schéma de bourrage posé au-dessus de
RSA, pas un format de clé : mêmes paires, mêmes fichiers PEM, mêmes lignes en
base. Seul le texte chiffré diffère, ce qui rend la version 2.1 incompatible avec
les agents antérieurs — bascule simultanée du serveur et du parc.

### Conséquence sur la taille

OAEP consomme `2×hLen + 2` octets de bourrage contre 11 pour PKCS#1 v1.5. Sur les
clés RSA-4096 du canal :

```
501 octets utiles (PKCS#1 v1.5)  →  446 octets utiles (OAEP-SHA256)
```

Le chiffrement asymétrique porte sur la **trame entière**, en-tête compris. La
plus grosse trame antérieure à `IsSafe` est le `02_01` :

```
02_01\nserveur_central\n<uuid 36>\n<username>\n<clientID 12>\n<password>
≈ 112 octets + le mot de passe
```

Il reste donc plus de 330 caractères de marge. **Aucune fragmentation n'est
nécessaire** — contrairement au transport GPO, qui lui bute sur la limite
`uint16` du fil (voir plus bas).

### Où sont les paramètres

Les deux modules Go étant séparés, les paramètres sont nécessairement dupliqués.
C'est la seule duplication assumée du projet, et elle impose une règle : **les
deux fichiers se modifient ensemble ou pas du tout.**

| Côté | Fichier |
|------|---------|
| serveur | `ducky-network/key_decode_encode/oaep_params.go` |
| agent | `duckynetworkClient/key_encode_decode/oaep_params.go` |

Une divergence de hachage ou de label produit un échec de déchiffrement
**indistinguable d'une mauvaise clé**, ce qui envoie chercher au mauvais endroit.

---

## Format Client → Serveur

```go
lines := strings.Split(trames, "\n")
action              = lines[0]          // "XX_YY"
Destination_Server  = lines[1]
SessionIntegritykey = lines[2]
Username            = lines[3]          // peut contenir un domaine (ex: admin@vaultaire.fr)
ClientSoftwareID    = lines[4]
Content             = lines[5:]         // tout le reste, rejoint par \n

//Structure exacte à respecter, ligne par ligne :
XX_YY
<destination>
<session_integrity_key>
<username>
<client_software_id>
<contenu ligne 1>
<contenu ligne 2>
...

//EXEMPLE
msg := "03_01\nserveur_central\n" + SessionKey + "\nvaultaire\n" + Computeur_ID + "\n" + req.User + "\n" + req.Password
```

## Format Serveur → Client

```go
lines := strings.Split(trames, "\n")
action              = lines[0]          // "XX_YY"
Destination_Server  = lines[1]
SessionIntegritykey = lines[2]
Content             = lines[3:]         // tout le reste, rejoint par \n

//Structure exacte à respecter :
XX_YY
<destination>
<session_integrity_key>
<contenu ligne 1>
<contenu ligne 2>
...
//EXEMPLE
return "03_02\nserveur_central\n" + SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\n" + isAdmin + "\n" + clesPubliques
```
---

# Authentification SSH / PAM (catégorie 03)

## Ce qui a changé, et pourquoi

L'échange comptait DEUX allers-retours :

```
03_04  le poste demande le sel du compte
  03_05  le serveur rend sel + nonce
03_01  le poste renvoie HMAC(clé = SHA-256(sel‖mot de passe), nonce)
  03_02  le serveur rend is_admin + clés publiques
  03_03  refus
```

Le mot de passe ne traversait jamais le réseau — mais le serveur devait
recalculer le même HMAC, donc **stocker la clé qui servait à le produire**.
L'empreinte en base était par conséquent directement rejouable : la lire
suffisait à ouvrir une session SSH sur n'importe quel compte, sans connaître le
mot de passe et sans rien casser. Le hachage ne protégeait rien sur ce chemin,
et interdisait de passer à argon2id — le poste aurait dû le calculer à
l'identique, et l'empreinte serait restée la clé.

## Échange actuel

```
03_01  <utilisateur@domaine>\n<mot de passe>
  03_02  <utilisateur@domaine>\n<is_admin>\n<clé publique 1>\n<clé publique 2>…
  03_03  <utilisateur@domaine>\n<raison>

03_06  <utilisateur@domaine>              demande des clés publiques seules
  03_07  vaultaire\n\n<utilisateur@domaine>\n<clés>

03_04  OBSOLÈTE — refusée par « obsolete client, update required »
03_05  OBSOLÈTE — l'agent la journalise en WARNING
```

Le mot de passe transite à l'intérieur de la session Ducky, déjà chiffrée et
authentifiée, exactement comme sur les trois autres portes du serveur : portail
web, bind LDAP, et trame `02_03`. L'empreinte stockée redevient vérifiable sans
être rejouable.

`03_04` et `03_05` ne sont pas simplement effacées : chaque camp répond
explicitement quand l'autre est resté à l'ancienne version. Sans cela, un agent
non mis à jour attendrait sept secondes puis rendrait « timeout » à PAM, et
l'administrateur chercherait une panne réseau.

## Ordre des contrôles dans `SSH_SEND_Pubkey_AUTH`

L'ordre n'est pas indifférent :

1. **limitation de débit** — avant tout, y compris avant de savoir si le compte
   existe. Cette porte-ci n'en avait pas ; elle prend désormais un mot de passe ;
2. **compte inconnu** — même refus, même message qu'un mot de passe faux ;
3. **mot de passe** — une panne de lecture de la base n'est PAS comptée comme un
   échec, sinon une base indisponible freinerait tout le parc ;
4. **kill switch** — APRÈS la vérification, pour ne pas révéler l'état d'un
   compte à qui n'en détient pas les identifiants ;
5. **droit sur le domaine**, puis **droit sur la machine** ;
6. clés publiques et statut administrateur.

Tous les refus rendent `03_03` avec le même libellé : distinguer les motifs
transformerait cette trame en oracle.

---

# Détail du transport GPO (catégorie 05)

> **Statut : proposition v2, en attente de validation.** Réordonnée pour que chaque
> demande soit immédiatement suivie de ses réponses (succès, puis cas « rien à
> faire », puis erreur). Aucune implémentation avant accord.

## Règle de numérotation appliquée

Une demande et ses réponses possibles sont contiguës. Le **numéro de trame porte
donc le scope** pour tout ce qui est spécifique à un scope, ce qui évite de
répéter l'information dans le contenu — une information dupliquée finit toujours
par diverger.

```
05_01  demande machine
  05_02  réponse : manifeste
  05_03  réponse : rien à faire
  05_04  réponse : erreur

05_05  demande user
  05_06  réponse : manifeste
  05_07  réponse : rien à faire
  05_08  réponse : erreur

05_09  demande de fragment            (partagée entre les deux scopes)
  05_10  réponse : fragment
  05_11  réponse : erreur

05_12  rapport d'application           (partagé entre les deux scopes)
  05_13  réponse : accusé
  05_14  réponse : erreur

05_15  rapport de conformité          (partagé entre les deux scopes)
  05_16  réponse : accusé
  05_17  réponse : erreur
```

Les blocs 05_09, 05_12 et 05_15 sont **partagés** entre les deux scopes : la logique de
transfert de fragment et de rapport est rigoureusement identique, la dédoubler
donnerait deux fois le même code à maintenir et à tester. Pour ces trames
uniquement, le scope voyage donc dans le contenu (première ligne).

Slots libres pour la suite : **05_18 et au-delà**.

## Principe

Modèle **pull**, comme Puppet : c'est toujours le client qui initie. Le serveur ne
pousse jamais une politique de lui-même. Deux moments de sollicitation :

| Moment | Scope demandé | Portée |
|--------|---------------|--------|
| Démarrage du service client, une fois la session mère `vaultaire` établie, puis rafraîchissement périodique | machine | toutes les GPO machine de **tous** les groupes de la machine |
| Authentification réussie d'un utilisateur via PAM | user | les GPO user des groupes **partagés** entre la machine et l'utilisateur |

Le comportement est identique pour un client serveur et un client poste : seule la
liste des groupes diffère.

**Intersection en scope user.** Une GPO user ne s'applique que si son groupe
contient à la fois l'utilisateur et la machine. Sans cette intersection, un
utilisateur emporterait la configuration d'un groupe sur une machine qui n'en fait
pas partie — ce qui reviendrait à laisser l'utilisateur choisir la configuration de
la machine.

## Contrainte de taille : pourquoi un découpage

La couche de transport annonce la taille du message sur **2 octets**
(`CompileMessageSize` → `uint16`), et la charge est chiffrée en AES-GCM puis encodée
en base64. Le plafond réel par trame est donc :

```
65535 octets sur le fil
  → base64  : 65535 / 4 * 3          = 49151 octets chiffrés
  → AES-GCM : - nonce(12) - tag(16)  = 49123 octets de texte clair
```

Or un seul module `file_deploy` accepte jusqu'à 256 Kio de contenu. Une politique
réaliste dépasse donc une trame. Le découpage n'est pas une optimisation : sans
lui, la fonctionnalité casse dès le premier fichier volumineux, et de façon
silencieuse — l'écriture de la taille tronque sur `uint16`.

Marge retenue : **fragments de 32 Kio de texte clair**, pour laisser de la place à
l'en-tête de trame et ne pas frôler la limite.

## Séquence — scope machine

```
client                                              serveur
  |                                                    |
  |-- 05_01  ask_gpo_machine ---------------------->    |  empreinte appliquée localement
  |                                                    |  résout les GPO, calcule l'empreinte
  |                                                    |
  |   cas A : empreinte identique                      |
  |<-------------------- 05_03  gpo_machine_unchanged --|  rien à appliquer, fin
  |                                                    |
  |   cas B : empreinte différente                     |
  |<-------------------- 05_02  gpo_machine_manifest --|  version, empreinte, nb de fragments
  |-- 05_09  ask_gpo_chunk (machine, index 0) ----->    |
  |<------------------------------- 05_10  gpo_chunk --|
  |-- 05_09  ask_gpo_chunk (machine, index 1) ----->    |
  |<------------------------------- 05_10  gpo_chunk --|
  |   réassemblage, vérification de l'empreinte        |
  |   application des seuls modules modifiés           |
  |-- 05_12  gpo_apply_report (machine) ----------->    |
  |<--------------------- 05_13  gpo_apply_report_ack --|
  |                                                    |
  |   cas C : erreur serveur                           |
  |<--------------------- 05_04  gpo_machine_error ----|
```

Le manifeste ne transporte **jamais** de fragment, même quand il n'y en a qu'un.
Un format conditionnel économiserait deux trames sur le cas courant mais
doublerait les chemins de code à écrire et à tester, pour un échange qui a lieu au
démarrage et à la connexion — pas dans une boucle chaude.

La séquence du scope **user** est identique, avec `05_05` → `05_06` / `05_07` /
`05_08` à la place de `05_01` → `05_02` / `05_03` / `05_04`.

## Format des trames

Rappel : client → serveur = 5 lignes d'en-tête (`action`, `destination`,
`session_key`, `username`, `client_software_id`), serveur → client = 3 lignes
(`action`, `destination`, `session_key`). Ce qui suit décrit le **contenu**, ligne
par ligne.

### 05_01 — ask_gpo_machine (client → serveur)

```
<empreinte_appliquée>
```

Empreinte SHA-256 (hex) de la politique machine actuellement appliquée, lue dans
l'état local. `none` au premier démarrage ou après remise à zéro de l'état.

### 05_02 — gpo_machine_manifest (serveur → client)

```
<version>            somme des versions des GPO contributrices
<empreinte>          SHA-256 hex de la politique effective
<nb_fragments>
<taille_totale>      octets de texte clair
<nb_modules>
<somme_de_controle>  SHA-256 hex de la charge transmise
```

> **Ajout par rapport à la v2 validée : la ligne `<somme_de_controle>`.**
> Deux empreintes distinctes cohabitent, et les confondre serait une source de
> bugs difficiles à diagnostiquer :
>
> - `<empreinte>` identifie la **configuration voulue**. C'est elle qui décide
>   s'il y a quelque chose à appliquer, et elle ne dépend pas du format de
>   livraison — ajouter un champ de transport ne provoque donc pas une
>   réapplication sur tout le parc ;
> - `<somme_de_controle>` porte sur les **octets réellement transmis** et ne sert
>   qu'à valider le réassemblage des fragments. Chaque trame est déjà
>   authentifiée par AES-GCM en transit : ce qui est vérifié ici, c'est
>   l'assemblage côté agent, pas l'intégrité réseau.
>
> Sans elle, un défaut de réassemblage produirait un JSON syntaxiquement valide
> mais amputé, appliqué sans que rien ne le signale.

### 05_03 — gpo_machine_unchanged (serveur → client)

```
<empreinte>
```

### 05_04 — gpo_machine_error (serveur → client)

```
<code>
<message lisible>
```

Codes : `no_groups`, `resolve_conflict`, `restrictions_unavailable`,
`unknown_client`, `internal`.

`resolve_conflict` correspond à deux GPO du même scope réglant la même clé : le
serveur refuse de livrer plutôt que d'en choisir une arbitrairement.
`restrictions_unavailable` correspond au mode fail-closed des restrictions.

### 05_05 — ask_gpo_user (client → serveur)

```
<username_cible>
<empreinte_appliquée>
```

Le `username` de l'en-tête reste `vaultaire` (identité du client sur le tunnel) ;
`<username_cible>` est l'utilisateur qui vient de s'authentifier. Les séparer évite
de faire dépendre l'authentification du tunnel de l'utilisateur du moment.

### 05_06 — gpo_user_manifest (serveur → client)

```
<username_cible>
<version>
<empreinte>
<nb_fragments>
<taille_totale>
<nb_modules>
<somme_de_controle>
```

`<username_cible>` est repris dans la réponse : plusieurs connexions peuvent être
en cours sur la même machine, le client doit savoir à qui rattacher le manifeste.

### 05_07 — gpo_user_unchanged (serveur → client)

```
<username_cible>
<empreinte>
```

### 05_08 — gpo_user_error (serveur → client)

```
<username_cible>
<code>
<message lisible>
```

Codes : ceux de 05_04, plus `unknown_user` et `no_shared_group` (aucun groupe
commun entre la machine et l'utilisateur).

### 05_09 — ask_gpo_chunk (client → serveur)

```
<scope>            machine | user
<username_cible>   vide pour le scope machine
<empreinte>        celle du manifeste — sert de jeton de cohérence
<index_fragment>   0-based
```

L'empreinte est renvoyée à chaque fragment : si la politique change côté serveur
pendant le transfert, le serveur détecte l'écart et répond `05_11` plutôt que de
livrer un assemblage de deux politiques différentes.

### 05_10 — gpo_chunk (serveur → client)

```
<scope>
<username_cible>   vide pour le scope machine
<empreinte>
<index_fragment>
<nb_fragments>
<données...>       tout le reste de la trame, y compris les \n
```

### 05_11 — gpo_chunk_error (serveur → client)

```
<scope>
<username_cible>
<code>             stale_fingerprint | bad_index | unknown_transfer | internal
<message lisible>
```

Sur `stale_fingerprint`, le client abandonne le transfert en cours et repart d'une
demande `05_01` ou `05_05` : c'est plus simple et plus sûr que de tenter de
raccorder deux versions.

### 05_12 — gpo_apply_report (client → serveur)

```
<scope>
<username_cible>   vide pour le scope machine
<empreinte>
<statut_global>    applied | partial | failed
<module_type>|<identité>|<résultat>|<détail>     une ligne par module
```

`<résultat>` : `applied`, `unchanged`, `skipped` ou `failed`. Sans ce rapport, le
serveur n'a aucun moyen de savoir si une politique a réellement atterri sur le
parc — l'interface afficherait la configuration voulue en la faisant passer pour
la configuration réelle.

### 05_13 — gpo_apply_report_ack (serveur → client)

```
<scope>
<username_cible>
<empreinte>
```

### 05_14 — gpo_apply_report_error (serveur → client)

```
<scope>
<username_cible>
<code>             malformed_report | unknown_fingerprint | internal
<message lisible>
```

Le rapport n'est pas rejoué en cas d'erreur : il est journalisé côté client et
l'application reste valide. Un rapport perdu est un défaut d'observabilité, pas un
défaut de configuration.

### 05_15 — gpo_drift_report (client → serveur)

```
<scope>
<username_cible>   vide pour le scope machine
<nb_fichiers_vérifiés>
<nb_écarts>
<identité_module>|<type_écart>|<chemin>|<détail>     une ligne par écart
```

`<type_écart>` : `modified`, `missing`, `unreadable` ou `permissions`.

**Pourquoi une trame distincte de 05_12.** 05_12 rapporte une *application* : ce
que l'agent vient de faire. 05_15 rapporte une *vérification* : ce qu'il
constate sans rien changer. Une machine peut avoir appliqué parfaitement il y a
trois semaines et avoir été modifiée à la main depuis — sans 05_15, elle reste
verte au tableau de bord. Confondre les deux rendrait impossible de distinguer
« appliqué avec succès » de « toujours conforme aujourd'hui ».

**Le nombre de fichiers vérifiés est envoyé même quand il n'y a aucun écart.**
Zéro écart sur zéro fichier vérifié ne veut pas dire « conforme », il veut dire
« rien n'était inventorié ». Sans ce compte, une machine dont l'inventaire est
vide s'afficherait comme parfaitement conforme.

**Le contenu des fichiers ne voyage jamais**, ni l'ancien ni le nouveau. Un
fichier géré par une GPO peut porter des clés ou des jetons ; un rapport de
conformité n'est pas un canal d'exfiltration. Seuls le chemin, le type d'écart
et un détail court sont transmis.

**Séparateur `|`.** Chemin et détail sont assainis côté agent avant l'envoi. Le
serveur découpe en quatre champs au maximum : le détail est le dernier et peut
donc contenir des séparateurs résiduels sans rendre la ligne ambiguë.

### 05_16 — gpo_drift_report_ack (serveur → client)

```
<scope>
<username_cible>
<nb_écarts_enregistrés>
```

### 05_17 — gpo_drift_report_error (serveur → client)

```
<scope>
<username_cible>
<code>             malformed_report | storage | internal
<message lisible>
```

À la différence de 05_12, un échec d'enregistrement **est** signalé ici (`storage`).
L'application, elle, est faite : la rejouer n'apporterait rien. Un scan, au
contraire, est bon marché et sera refait au cycle suivant — dire à l'agent que
le constat n'a pas été conservé lui évite de croire le serveur informé.

**La correction est locale et n'attend pas l'accusé.** L'agent efface les
empreintes des modules concernés dès le scan terminé, et les réapplique au cycle
suivant, que le rapport soit parti ou non. Une panne du serveur ne doit pas
laisser une machine en dérive.

## Charge utile de la politique

Les fragments réassemblés forment un document JSON canonique, celui déjà produit
par `gpo.CanonicalJSON` :

```json
{
  "name": "effective_machine",
  "scope": "machine",
  "version": 7,
  "fingerprint": "752bf78712f8…",
  "modules": [
    { "type": "sysctl", "scope": "machine", "apply_order": 11,
      "params": { "key": "net.ipv4.ip_forward", "value": "0" },
      "state_key": "sysctl:net.ipv4.ip_forward",
      "fingerprint": "f3dad3533bb3…" },

    { "type": "sudoers_rule", "scope": "machine", "apply_order": 12,
      "params": { "group": "ops", "command_set": "nginx_restart", "nopasswd": "false" },
      "state_key": "sudoers_rule:ops",
      "fingerprint": "a91c0e4471bd…",
      "definitions": {
        "command_set": {
          "name": "nginx_restart",
          "kind": "command_list",
          "payload": "/usr/bin/systemctl restart nginx\n/usr/bin/systemctl status nginx"
        }
      } }
  ]
}
```

Trois champs méritent d'être détaillés, parce qu'ils portent des garanties :

- **`state_key`** et **`fingerprint`** par module sont calculés par le serveur et
  transmis, jamais recalculés par l'agent. Le client est un module Go séparé :
  deux implémentations du même hachage finiraient par diverger, et une machine se
  croirait à jour sans l'être.

- **`definitions`** porte le CONTENU des valeurs nommées référencées par les
  paramètres. Un module `sudoers_rule` ne transmet pas seulement le nom du jeu de
  commandes mais sa liste réelle : sans cela, créer un jeu custom depuis
  l'interface n'aurait aucun effet sur le parc, puisque l'agent ne saurait pas ce
  que ce nom recouvre.

  Conséquence sur les empreintes : le contenu des définitions **entre dans le
  calcul** de l'empreinte du module et de celle de la politique. Modifier la liste
  de commandes d'un jeu ne change aucun paramètre de module, mais change bel et
  bien ce qui sera appliqué — sans cela le serveur répondrait « rien à faire » et
  le parc conserverait indéfiniment l'ancienne règle.

Les modules sont triés par ordre d'application et les clés de paramètres sont
ordonnées : le document est reproductible, et son empreinte stable d'un envoi à
l'autre. C'est ce qui rend la comparaison d'empreintes fiable.

**Signature.** Le document n'est pas encore signé. Le tunnel Ducky est déjà
authentifié et chiffré, ce qui couvre l'écoute et la modification en transit, mais
pas un serveur central compromis. La signature fera l'objet d'une entrée de TO-DO
séparée ; le champ est prévu dans le format pour ne pas avoir à changer les trames.

## État local du client

Fichier `/var/lib/vaultaire/applied_policies.json`, en `0600 root:root` — chemin
déjà refusé à toutes les GPO par les règles de restriction, précisément pour qu'une
GPO ne puisse pas réécrire l'état qui décide de son application.

```json
{
  "machine": {
    "fingerprint": "a1b2…",
    "version": 7,
    "applied_at": "2026-07-30T14:22:03Z",
    "modules": { "sysctl:net.ipv4.ip_forward": "e3f4…" }
  },
  "users": {
    "alice": { "fingerprint": "c5d6…", "version": 3, "applied_at": "…", "modules": {} }
  }
}
```

L'empreinte **par module** est ce qui permet de ne réappliquer que ce qui a changé :
à empreinte globale différente, le client compare module par module et laisse
tranquille ceux dont les paramètres sont identiques. Réappliquer l'ensemble à chaque
changement serait plus simple, mais relancerait des services et réinstallerait des
paquets sans raison.

## Moment d'application en scope user

L'ordre demandé est : utilisateur local créé et validé → **GPO user appliquées** →
droit de connexion accordé. Le point d'insertion est donc le traitement de `03_02`
côté client, après `ProvisionVaultaireUser` et avant la remise du résultat au
module PAM.

Ce choix rend la connexion dépendante de l'application des GPO. C'est acceptable
ici parce qu'aucun module de scope user n'est lent : environnement, timers
utilisateur et fichiers sous le home. Les modules lents (installation de paquets,
redémarrage de services) sont tous machine-only, donc appliqués au démarrage.

**À l'expiration du délai ou en cas d'échec d'un module, la connexion est
accordée** et l'incident part en `WARNING` + `SECURITY`, avec un rapport `05_12` de
statut `partial` ou `failed`. Aucun module de scope user ne touche aux privilèges :
une variable d'environnement non posée ne crée pas de faille, alors qu'un annuaire
qui bloque les connexions sur incident GPO est un incident d'exploitation majeur.

---

# Détail de la révocation — kill switch (catégorie 06)

> **Statut : validé et implémenté.** Numérotation, bascule de `delete -u` en mode
> hard et confirmation par saisie du nom pour le mode destructeur : les trois ont
> été validés. Le point ouvert n° 4 (lecture des groupes par domaine) était un
> défaut et a été corrigé — voir `migrations/rbac_groupes_stricts.md`.

## Pourquoi une catégorie séparée des GPO

Le transport est très proche de celui des GPO — ordre déclaratif, jamais de
commande shell — mais trois différences justifient de ne pas le loger dans 05 :

| | GPO (05) | Révocation (06) |
|---|---|---|
| Initiative | Le client tire, quand il veut | Le serveur pousse, tout de suite |
| Délai acceptable | Le prochain cycle (1 h) | Immédiat |
| Cible | La machine ou l'utilisateur connecté | Un compte nommé, sur des machines où il n'est pas connecté |
| Cumul | La politique remplace la précédente | Chaque ordre est un événement distinct, à tracer |

Mélanger les deux ferait dépendre une révocation d'urgence du cycle de
rafraîchissement des GPO. C'est précisément ce qu'un kill switch doit éviter.

## Les trois ordres

| Mode | Annuaire | Machines | Réversible |
|------|----------|----------|------------|
| `soft` | Compte marqué révoqué : plus aucune authentification, plus aucune permission | `usermod -L` + `chage -E 1` — compte verrouillé, home intact | Oui, via `unlock` |
| `unlock` | Marque levée | `usermod -U` + `chage -E -1` | — |
| `hard` | Compte **supprimé** de l'annuaire | `userdel -r` — compte et répertoire personnel supprimés | **Non** |

**Pourquoi le verrouillage local est indispensable, y compris en `soft`.** Le
module PAM écrit le mot de passe dans le `/etc/shadow` de chaque machine où
l'utilisateur se connecte (`pam_common.c`, `ensure_local_user_with_password`).
Une révocation limitée au serveur laisserait donc le compte utilisable en local
sur toutes ces machines. Un kill switch qui ne coupe pas l'accès n'est pas un
kill switch.

**Le mode `hard` détruit le répertoire personnel** (`userdel -r`), conformément
au choix retenu. À garder en tête : sur un compte compromis, cela détruit aussi
les traces de la compromission. Si un jour l'analyse post-incident devient un
besoin, c'est ici qu'il faudra revenir.

## Quelles machines reçoivent l'ordre

Celles qui partagent au moins un groupe avec l'utilisateur — la même règle que
les GPO utilisateur, et la fonction existe déjà (`HasSharedGroup`). C'est
exactement l'ensemble des machines où l'utilisateur a pu se connecter, donc
l'ensemble où un compte local a pu être créé.

En `hard`, la liste est **figée au moment du déclenchement**, avant la
suppression du compte en base : après la suppression, l'appartenance aux groupes
n'existe plus et la liste serait vide.

## Machines hors ligne

Un ordre est **durable**, pas un message éphémère. Il est écrit en base avec la
liste de ses cibles, poussé immédiatement aux machines connectées, et rejoué
tant qu'il n'est pas acquitté. Une machine éteinte au moment de la révocation
reçoit l'ordre à sa prochaine connexion, via 06_04.

Sans cette persistance, éteindre son poste suffirait à échapper à une
révocation — le seul cas où la précaution compte vraiment.

## Séquence

```
 Déclenchement (CLI, web ou API)
        │
        ├─ écriture en base : ordre + liste des machines cibles
        ├─ marquage du compte / suppression selon le mode
        ├─ fermeture immédiate des sessions Ducky de l'utilisateur
        │
        └─ pour chaque machine EN LIGNE :
                serveur ──── 06_01 revoke_order ────► client
                serveur ◄─── 06_02 revoke_ack ─────── client      cible passée à « acquittée »
                        ◄─── 06_03 revoke_error ─────            cible passée à « en échec », réessai au cycle suivant

 Machine qui se (re)connecte
                serveur ◄─── 06_04 ask_revocations ── client      après authentification
                serveur ──── 06_05 revocations_list ► client
                serveur ◄─── 06_02 revoke_ack ─────── client      un acquittement par ordre
```

## Format des trames

### 06_01 — revoke_order (serveur → client)

```
06_01
serveur_central
<session_integrity_key>
<order_id>            identifiant unique de l'ordre
<mode>                soft | unlock | hard
<username>            forme complète, domaine compris (admin@vaultaire.fr)
<reason_code>         compromised | offboarding | admin_request
```

`reason_code` est un code fermé, jamais du texte libre : le motif détaillé reste
côté serveur. Une raison saisie par un administrateur n'a pas à voyager jusqu'à
une machine potentiellement compromise, et du texte libre sur le fil est une
surface d'injection dans les journaux de l'agent.

### 06_02 — revoke_ack (client → serveur)

```
06_02
serveur_central
<session_integrity_key>
<username_de_session>
<client_software_id>
<order_id>
<result>              applied | already_absent | not_applicable
```

`already_absent` (compte local inexistant) et `not_applicable` sont des succès,
pas des erreurs : une machine où l'utilisateur ne s'est jamais connecté n'a rien
à faire, et le signaler comme un échec provoquerait des réessais sans fin.

### 06_03 — revoke_error (client → serveur)

```
06_03
...
<order_id>
<code>                unknown_mode | command_failed | permission_denied | internal
<message>
```

### 06_04 — ask_revocations (client → serveur)

```
06_04
serveur_central
<session_integrity_key>
<username_de_session>
<client_software_id>
```

Aucun contenu : le serveur connaît déjà la machine, puisque le
`ClientSoftwareID` est figé à la poignée de main et vérifié à chaque trame.

### 06_05 — revocations_list (serveur → client)

```
06_05
serveur_central
<session_integrity_key>
<nombre_d_ordres>
<order_id>|<mode>|<username>|<reason_code>
<order_id>|<mode>|<username>|<reason_code>
...
```

Plafonné à 200 ordres par trame ; au-delà, le client rappelle 06_04. Un ordre
pèse une centaine d'octets, la limite utile d'une trame est d'environ 48 Kio.

### 06_06 — revocations_error (serveur → client)

```
06_06
serveur_central
<session_integrity_key>
<code>
<message>
```

## Idempotence

Un ordre peut arriver deux fois : poussé puis rejoué après une reconnexion, ou
réémis après un acquittement perdu. Les trois modes sont naturellement
idempotents (`usermod -L` deux fois de suite, `userdel` sur un compte absent),
et l'agent tient la liste des `order_id` déjà appliqués dans son état local, à
côté de `applied_policies.json`. Un ordre déjà appliqué est ré-acquitté sans
être rejoué.

## Intégration RBAC côté serveur

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

# Enrôlement d'un client service (01_05 à 01_09)

L'enrôlement précède l'existence du client : il n'y a ni session, ni identifiant
machine, ni type. Il ne peut donc pas être soumis au contrôle par type de client
— c'est la **clé d'enrôlement** qui autorise la trame, et c'est **son type à
elle** qui décide de ce que le client pourra émettre ensuite.

## Ce que la clé porte, et ce que le client ne choisit pas

La clé d'enrôlement est émise par le core avec un **type**, une **expiration** et
un **quota d'utilisations**. Le client ne déclare donc pas son type : il le
reçoit.

C'est le point de sécurité central de ce flux. Si le client annonçait son type,
n'importe quel service enrôlé pourrait se déclarer `vaultaire_web` et obtenir
`AssertsUser`, c'est-à-dire le droit d'agir au nom de n'importe quel utilisateur.
Le type vient de la clé, la clé vient d'un administrateur : le service n'a aucune
prise sur ses propres privilèges.

## Pourquoi une clé de session temporaire

Une clé publique RSA-4096 pèse environ **800 octets** en PEM, **1116** une fois
en base64 dans une trame. Une charge RSA-OAEP sur clé 4096 en accepte **446**.

Elle ne peut donc pas voyager dans une enveloppe asymétrique, et **aucun encodage
n'y change rien** : même `base64(DER)` d'une clé 2048, la forme la plus compacte
possible, fait 499 octets. Le problème est que la charge utile d'une enveloppe
RSA est plus petite que la clé qu'on veut y mettre.

La clé temporaire tient sans peine en RSA — 32 octets — et ouvre un canal
symétrique qui n'a plus de limite de taille. C'est le mécanisme de `01_02`,
avancé d'un cran pour servir avant même que le client existe.

## Séquence

```
service                                          core
  |-- askkey (non authentifié) ----------------->  |
  |<-- clé publique du core ----------------------  |
  |
  |-- 01_05 clé d'enrôlement + clé TMP --------->  |  valide la clé, crée le client
  |                                                |  (sans clé publique pour l'instant)
  |<-- 01_06 identifiant + type -----------------  |  AES-GCM, clé TMP
  |
  |   écrit client_software.yaml                  |
  |   génère sa paire RSA-4096 localement         |
  |
  |-- 01_07 sa clé publique -------------------->  |  AES-GCM, clé TMP
  |<-- 01_08 ok ---------------------------------  |  RSA, clé publique du service
  |
  |   la connexion se ferme                       |
  |   ... puis 01_01 / 01_02 sur une connexion neuve ...
```

**La preuve de possession est gratuite.** `01_08` est chiffrée avec la clé
publique enregistrée en `01_07` : seul le détenteur de la privée correspondante
peut la lire. Un service qui aurait soumis une clé qu'il ne possède pas le
découvre immédiatement, au lieu d'échouer à la première poignée de main d'une
session ultérieure.

**La connexion est jetable.** Elle a servi à l'enrôlement et n'est pas une
session : ni machine liée, ni type. La laisser ouverte donnerait un canal chiffré
dans l'état que le fail-closed du Spliter existe précisément pour ne pas laisser
traîner.

## Format des trames

### 01_05 — enroll_request (client → serveur)

Chiffrée avec la clé publique du serveur, comme `01_01`.

```
01_05
serveur_central
-
-
-
<clé_enrôlement>
<clé_session_temporaire_base64>    32 octets, AES-256
<libellé>
```

Les trois champs d'en-tête sont vides : il n'y a ni session, ni utilisateur, ni
identifiant machine à ce stade. Le `libellé` est une chaîne libre destinée aux
journaux et à l'affichage (« proxy-preprod-01 ») ; il n'a aucune valeur de
sécurité et n'entre dans aucune décision.

La clé temporaire est **validée avant** que la clé d'enrôlement ne soit
consommée : une clé mal formée ne doit pas coûter un jeton à l'administrateur qui
l'a émis.

### 01_06 — enroll_ok (serveur → client)

Chiffrée en **AES-GCM avec la clé temporaire**. La bascule se fait des deux côtés
dès l'envoi de `01_05` : le core répond déjà sous ce régime.

```
01_06
<destination>
-
<computeur_id_attribué>
<type_de_client>
```

Le client existe alors en base **sans clé publique** — elle vient en `01_07`.
Cet état est inerte : un client sans clé publique ne peut rien faire, puisque la
poignée de main `01_02` lui répondrait un chiffré que personne ne sait lire.

### 01_07 — enroll_pubkey (client → serveur)

Chiffrée en **AES-GCM avec la clé temporaire**.

```
01_07
serveur_central
-
-
<computeur_id>
<clé_publique_pem_base64>
```

L'identifiant est repris de la **session**, jamais de la trame, côté serveur. Le
lire dans la trame laisserait quiconque a passé un enrôlement écraser la clé
publique d'un autre client, donc prendre sa place.

### 01_08 — enroll_confirmed (serveur → client)

Chiffrée avec la **clé publique qui vient d'être enregistrée**.

```
01_08
<destination>
-
ok
```

Le serveur ferme la connexion juste après.

### 01_09 — enroll_denied (serveur → client)

En clair, puis fermeture. Le serveur n'a rien pour chiffrer : pas de clé publique
du client, et pas de clé temporaire utilisable si c'est justement elle qui était
malformée. Le refus ne contient aucun secret.

| Code journalisé | Sens |
|---|---|
| `unknown_key` | clé inconnue |
| `expired_key` | date d'expiration dépassée |
| `exhausted_key` | quota d'utilisations atteint |
| `revoked_key` | clé révoquée |
| `unknown_type` | le type porté par la clé n'est plus au catalogue |
| `bad_public_key` | clé publique illisible ou trop faible |
| `invalid_request` | trame malformée, ou clé temporaire de taille inattendue |

**Les cinq premiers sont distincts dans les journaux mais indistincts pour le
client**, qui reçoit `invalid_key` dans les cinq cas. Une réponse détaillée
transformerait le point d'enrôlement en oracle : un attaquant apprendrait qu'une
clé existe mais est expirée, donc qu'elle a existé, donc que le format est le
bon. Le journal serveur, lui, porte la vraie raison.

**Numérotation : 01_01, 01_02, puis 01_05 à 01_09. Libre à partir de 01_10.**

## Traçabilité

Chaque consommation écrit une ligne dans `service_enrollment_use` :
identifiant de clé, `computeur_id` créé, adresse source, horodatage.

Sans cette table, on ne peut pas répondre à « quels services sont entrés par cette
clé ? » le jour où l'on découvre qu'elle a fuité — et c'est précisément le jour où
la question se pose.

---

# Cluster : enregistrement d'un service (04_09 à 04_14)

> **Statut : proposition, en attente de validation.**

La catégorie 04 porte déjà l'enregistrement d'un **hôte** (`04_01`), le service
discovery (`04_03`), les métriques proxy (`04_05`) et le battement de cœur
(`04_07`). La plage réservée va jusqu'à `04_19`.

## Pourquoi ne pas réutiliser 04_01

`register_host` déclare une **machine** : hostname, fqdn, ip, role, domain. Un
service déclare une **fonction** : son type, sa version, ce qu'il sait faire.
Ce ne sont pas les mêmes données.

Les séparer a une seconde conséquence, plus importante : la restriction par
sous-trame reste utile. Un `vaultaire_proxy` peut émettre `04_01` et pas `04_09` ;
un `vaultaire_web` l'inverse. Un enregistrement unique pour les deux effacerait
cette distinction.

### 04_09 — register_service (client → serveur)

```
04_09
serveur_central
<session_integrity_key>
<username_du_programme>
<client_software_id>
<version>
<endpoint>
<capabilities>
```

`capabilities` est une liste séparée par des virgules, à visée d'inventaire et
d'affichage. **Elle n'accorde aucun droit** : ce que le service peut émettre est
décidé par son type au catalogue, jamais par ce qu'il déclare savoir faire. Un
champ déclaratif qui accorderait des droits serait une élévation de privilèges
offerte au client.

### 04_10 — register_service_ok (serveur → client)

### 04_11 — register_service_error (serveur → client)

Codes : `unknown_service`, `version_refused`, `duplicate_endpoint`.

### 04_12 — service_heartbeat (client → serveur)

Même rôle que `04_07` pour les hôtes : maintenir le service en ligne dans
`cluster_nodes`. Un service qui cesse de battre est marqué hors ligne, et
l'interface d'administration peut le signaler au lieu de laisser un
administrateur découvrir la panne par un timeout.

### 04_13 — service_heartbeat_ack (serveur → client)

### 04_14 — service_deregister (client → serveur)

Sortie propre à l'arrêt du service. Sans elle, un arrêt planifié serait
indistinguable d'une panne pendant toute la fenêtre de battement de cœur.

**Numérotation : 04_09 à 04_14. Libre à partir de 04_15, la plage réservée allant
jusqu'à 04_19.**

---

# Détail du transport de commandes (catégorie 07)

> **Statut : proposition, en attente de validation. Aucune implémentation avant
> accord.** Contexte et découpage des programmes dans
> `Architecture_Services.md`.

## Pourquoi une catégorie séparée

Les catégories 02 à 06 transportent des opérations **fixées à l'avance** :
authentifier, tirer une politique, acquitter une révocation. Le serveur sait ce
qui va arriver et n'a qu'à le traiter.

La catégorie 07 transporte une **commande VLT arbitraire**, c'est-à-dire tout ce
que le routeur `core/command` sait faire, présent et à venir. C'est une
différence de nature, pas de sujet : ajouter une commande au CLI l'expose
automatiquement ici, sans toucher au protocole.

C'est aussi ce qui justifie de ne pas la mélanger aux autres. Une trame 07 peut
avoir des effets de bord irréversibles — `delete -u` déclenche une révocation
`hard` — là où une trame 05 est une lecture idempotente. Les contrôles ne peuvent
donc pas être les mêmes.

## Séquence

```
web                                        serveur central
 |                                              |
 |-- 07_01 command_request ------------------->  |  vérifie type client, identité
 |                                              |  déclarée, fraîcheur, rejeu
 |                                              |  puis core/command.ExecuteCommand
 |                                              |
 |<-- 07_02 command_result --------------------  |  résultat complet, OU manifeste
 |                                              |     si la sortie dépasse une trame
 |                                              |
 |-- 07_04 ask_result_chunk (n) -------------->  |  (seulement si fragmenté)
 |<-- 07_05 result_chunk (n) ------------------  |
 |            ... jusqu'au dernier fragment      |
```

Le client **tire** les fragments, comme pour les GPO. Le serveur ne pousse rien :
un résultat volumineux dont le destinataire a disparu ne doit pas occuper une
goroutine à écrire dans le vide.

## Contrainte de taille

Identique à celle des GPO — `uint16` sur le fil, base64 sur AES-GCM, soit environ
49 Kio utiles. `get -u` sur un annuaire fourni dépasse largement. **Fragments de
32 Kio**, même marge et même raison qu'en catégorie 05.

Le seuil de fragmentation est donc : au-delà de 32 Kio de résultat, 07_02 porte un
manifeste au lieu du corps.

## Format des trames

### 07_01 — command_request (client → serveur)

```
07_01
serveur_central
<session_integrity_key>
<username_du_programme>
<client_software_id>
<request_id>
<timestamp>
<asserted_user>
<output_format>
<commande>
```

| Champ | Rôle |
|---|---|
| `request_id` | entier, **strictement croissant** dans la session |
| `timestamp` | RFC 3339 UTC, fenêtre d'acceptation de 2 minutes |
| `asserted_user` | utilisateur au nom duquel la commande s'exécute |
| `output_format` | `json` ou `text` |
| `commande` | la ligne VLT telle qu'on la taperait : `get -u alice` |

La commande est sur **une seule ligne** et passe par
`command.SplitArgsPreserveBlocks`, exactement comme la saisie d'un terminal. Un
seul analyseur d'arguments pour les deux chemins : deux analyseurs finiraient par
diverger sur les guillemets, et l'écart serait exploitable.

### 07_02 — command_result (serveur → client)

```
07_02
<destination>
<session_integrity_key>
<request_id>
<fragments>
<taille_totale>
<empreinte>
<corps ou vide si fragments > 1>
```

`fragments = 1` : le corps suit directement. Sinon il est vide et le client
demande ses fragments en 07_04.

L'empreinte SHA-256 porte sur le corps **complet reconstitué**. Elle n'est pas
décorative : sans elle, un fragment perdu ou dupliqué produirait un JSON tronqué
que le web afficherait comme une réponse valide.

### 07_03 — command_error (serveur → client)

```
07_03
<destination>
<session_integrity_key>
<request_id>
<code>
<message>
```

| Code | Sens |
|---|---|
| `forbidden_category` | le type de client n'a pas le droit d'émettre 07 |
| `assert_not_allowed` | le type de client n'a pas le droit de déclarer une identité |
| `stale_request` | horodatage hors fenêtre |
| `replayed_request` | `request_id` déjà vu ou non croissant |
| `unknown_user` | l'utilisateur déclaré n'existe pas ou est révoqué |
| `permission_denied` | RBAC : refus, avec le motif dans `message` |
| `command_failed` | la commande a échoué ; `message` porte son texte |

**`permission_denied` et `command_failed` sont distincts à dessein.** Le premier
est une décision de sécurité, journalisée en SECURITY ; le second est une erreur
d'exploitation ordinaire. Les confondre rendrait les journaux inexploitables pour
détecter des tentatives.

### 07_04 — ask_result_chunk (client → serveur)

```
07_04
serveur_central
<session_integrity_key>
<username_du_programme>
<client_software_id>
<request_id>
<index_du_fragment>
```

### 07_05 — result_chunk (serveur → client)

```
07_05
<destination>
<session_integrity_key>
<request_id>
<index>
<total>
<corps du fragment>
```

### 07_06 — result_chunk_error (serveur → client)

Codes : `unknown_request` (résultat expiré ou jamais produit),
`bad_index`.

Un résultat en attente de retrait est **conservé au plus 60 secondes** et lié à
la session qui l'a demandé. Le garder plus longtemps ferait du serveur un cache
de sorties d'administration ; le lier à la session empêche une autre connexion de
venir lire un résultat qui ne lui était pas destiné.

**Numérotation : 07_01 à 07_06. Libre à partir de 07_07.**

## Contrôles, dans l'ordre

1. **Type de client** — `vaultaire_web` peut émettre 07 ; un agent de poste, non.
   Contrôle posé dans `Split_Action`, avant le routage. Voir
   `Architecture_Services.md` §4.
2. **Droit de déclarer une identité** — seul un type portant `AssertsUser` peut
   renseigner `asserted_user`. Pour les autres, le champ doit être vide et la
   commande s'exécute sous l'identité du programme lui-même.
3. **Fraîcheur et rejeu** — horodatage dans la fenêtre, `request_id` strictement
   croissant pour la session.
4. **Existence et état du compte déclaré** — un compte révoqué est refusé ici,
   avant même l'évaluation RBAC, pour que le journal porte la vraie raison.
5. **RBAC** — évalué sur les groupes de l'**utilisateur déclaré**, jamais sur ceux
   du programme. C'est ce qui fait qu'un web compromis ne peut rien faire qu'aucun
   utilisateur ne pourrait faire.

### Pourquoi un anti-rejeu alors que le tunnel est chiffré

Le tunnel protège contre l'écoute et l'altération, pas contre la réémission d'une
trame valide déjà observée. Les catégories 05 et 06 s'en passent parce qu'elles
sont idempotentes : rejouer une demande de GPO redonne la même politique.

La catégorie 07 ne l'est pas. Rejouer `delete -u alice` la supprime une seconde
fois — sans effet — mais rejouer `add -u bob -g admins` après un retrait légitime
le remet dans le groupe. Le compteur croissant coûte un entier par session et
ferme la question.

## Ce que ce transport ne résout pas : les GPO

Le catalogue de commandes VLT **ne couvre pas l'administration des GPO**. Le CLI
sait créer, supprimer, lister une GPO et la lier à un groupe. Il ne sait rien
faire de ses **modules** ni de ses **restrictions** — 22 fonctions de `dbgpo`
sont appelées par l'interface web et n'ont aucun équivalent en commande :

```
modules       AddModule, UpdateModuleParams, DeleteModule, GetModuleByID
restrictions  AddAllowedValue, AddPathRule, AddEnvDeny, SetFieldRule,
              SaveDefinition, DeleteDefinition, DeleteRestriction,
              ResetRestrictionsToDefaults, ListRestrictionsByKind,
              ListAllowedValuesForField, ListDefinitionsForField, GetFieldRule
métadonnées   UpdatePolicyMeta
```

Les pages GPO ne peuvent donc **pas** basculer sur la catégorie 07 en l'état.
Deux options, à trancher au moment de l'étape 6 :

- **Étendre le CLI** avec `vlt gpo module ...` et `vlt gpo restriction ...`. Le
  paramétrage d'un module est un dictionnaire de champs variables ; le passer en
  arguments de ligne de commande est possible mais verbeux, et le CLI y gagne une
  capacité qui lui manque aujourd'hui de toute façon.
- **Garder les pages GPO en accès base direct** jusqu'à ce que le besoin CLI se
  manifeste par ailleurs. Contredit la frontière du §2 et laisse un deuxième
  chemin d'écriture vers l'annuaire depuis le web.

La première est plus longue, la seconde laisse une exception qui aura tendance à
s'installer. Aucune n'est à décider maintenant : c'est l'étape 6, elle vient après
la bascule des vues en lecture.
