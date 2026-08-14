# Protocole Ducky Network

> **Public : développeurs.** Référence des trames `MM_SS` : format, ordre, contrôles.

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
| client                      |             | 08            | server respond ok                | le serveur chiffre ok via la clé public du client pour validé l'enregistrement            |
| client                      |             | 09            | enroll denied                    | refus, EN CLAIR : le serveur n'a ni clé publique du client ni clé tmp utilisable          |
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
| SSH / identités du poste    | 03          |               | (plage utilisée : 03_01 à 03_10) | voir « Authentification SSH / PAM » et « Synchronisation des groupes de la machine »      |
| server                      |             | 01            | client ask if user can login     | le client envoie un username/password et attend  d'auth avec les clé public du user       |
| client                      |             | 02            | server awnser   succes           | succès : is_admin, la ligne `groups:` des groupes du user, puis ses clés publiques        |
| client                      |             | 03            | server anwser failed             | le server renvoie un failed avec la raison de l'echec                                     |
| ~~server~~                  |             | ~~04~~        | **OBSOLÈTE**                     | demandait le sel d'un user — le défi HMAC a disparu, refusée par « obsolete client »      |
| ~~client~~                  |             | ~~05~~        | **OBSOLÈTE**                     | rendait sel + nonce — l'agent la journalise en WARNING si un vieux core l'envoie          |
| server                      |             | 06            | fetch_pubkey                     | le client demande les clés publiques seules, sans authentifier personne                   |
| client                      |             | 07            | fetch_pubkey_response            | réponse à 03_06 : les clés publiques du user                                              |
| server                      |             | 08            | group_sync_request               | le client demande la liste des groupes de ses domaines — contenu VIDE, l'ID est en en-tête |
| client                      |             | 09            | group_sync_list                  | réponse succès à 03_08 : `sync:<minutes>` puis une ligne `<nom>:<id_group>` par groupe    |
| client                      |             | 10            | group_sync_denied                | réponse erreur à 03_08 : l'agent ne touche à rien et garde ses groupes                    |
|                             |             |               |                                  |                                                                                           |
| Cluster / Service discovery | 04          |               | (plage réservée : 04_01 à 04_19) | voir « Découverte de service et proxies » en fin de document                               |
| serveur                     |             | 01            | register_host                    | un nœud se déclare : hostname, fqdn, ip, rôle, domaine, port, empreinte                   |
| client                      |             | 02            | register_host_ack                | accusé d'enregistrement                                                                   |
| serveur                     |             | 03            | list_cores                       | demande les nœuds joignables — contenu VIDE, l'ID est lu dans l'en-tête                   |
| client                      |             | 04            | list_cores_response              | `<nombre>` puis `<host>\|<ip>\|<port>\|<rôle>\|<priorité>\|<empreinte>`, ORDONNÉE par le core |
| serveur                     |             | 05            | proxy_metrics                    | envoi des métriques du proxy vers le Core (pour table proxy_metrics)                      |
| client                      |             | 06            | proxy_metrics_ack                | accusé de réception                                                                       |
| serveur                     |             | 07            | host_heartbeat                   | heartbeat du host pour rester dans cluster_nodes (online)                                 |
| client                      |             | 08            | host_heartbeat_ack               | accusé heartbeat                                                                          |
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
  03_02  <utilisateur@domaine>\n<is_admin>\ngroups:<g1>,<g2>\n<clé pub 1>\n<clé pub 2>…
  03_03  <utilisateur@domaine>\n<raison>

03_06  <utilisateur@domaine>              demande des clés publiques seules
  03_07  vaultaire\n\n<utilisateur@domaine>\n<clés>

03_08  (vide)                            synchronisation des groupes du domaine
  03_09  sync:<minutes>\n<nom>:<id_group>…
  03_10  <raison>

03_04  OBSOLÈTE — refusée par « obsolete client, update required »
03_05  OBSOLÈTE — l'agent la journalise en WARNING
```

`03_08` à `03_10` ont leur propre section, plus bas : « Synchronisation des
groupes de la machine ».

## La ligne des groupes dans `03_02`

Les clés publiques occupent « tout le reste » du contenu : il n'existait donc
aucune position libre APRÈS elles. La liste des groupes se place avant, et se
reconnaît à son **préfixe** `groups:` plutôt qu'à son rang.

Compter les lignes aurait lié l'agent à une version précise du serveur : face à
un serveur qui n'envoie pas encore la ligne, tout serait décalé et la première
clé serait lue comme une liste de groupes. Avec le préfixe, son absence est
simplement un contenu sans groupes.

**La compatibilité ne va que dans un sens, et c'est assumé.** Un agent à jour
fonctionne avec un serveur ancien : il n'applique aucune appartenance, soit
l'ancien comportement. L'inverse ne tient pas — un agent ancien prend la ligne
pour une clé et l'écrit dans `authorized_keys`, où sshd l'ignore comme entrée
malformée. Le fichier étant réécrit à chaque connexion, l'artefact disparaît dès
la mise à jour. Ce chemin porte déjà une contrainte de version du même ordre :
voir `03_04`.

Le préfixe est déclaré **des deux côtés** — l'agent et le serveur sont des
modules Go distincts, et aucune compilation ne peut les tenir liés. Deux tests
jumeaux figent la chaîne (`sshauth/groupes_trame_test.go` et
`ssh_client_test.go`) : sans eux, un changement d'un seul côté échouerait en
silence, puisque sshd ne signale pas les lignes qu'il ignore.

### Ce que l'agent en fait

Il **ne retire que ce qu'il a lui-même posé**. `/etc/group` porte aussi les
appartenances de l'administrateur local, d'un paquet, d'un installeur : aligner
naïvement sur la liste du serveur les effacerait toutes, silencieusement, à la
première connexion et sur tout le parc à la fois.

La mémoire de ce qu'il a posé est `/etc/vaultaire/user_groups.map`, sur le modèle
de `uid.map`. État illisible ⇒ **aucun retrait** : retirer sans savoir ce qu'on a
posé reviendrait exactement à ce que le fichier existe pour éviter.

Il ne **crée** aucun groupe : un groupe du domaine absent de la machine est
ignoré, et le journal le dit. C'est l'objet de la spécification ci-dessous.

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

un service n'a pas besoin de se reenregistré tous cela est fait via la clé d'enrollement utiliser lors de la premiere connection d'un service dans la base de donné il y a son client ID et son profil
la seul chose que le service peut mettre a jour de son coté dans cette base c'est sa version le premiere trames doivent servir a se signalé comme up pour etre enregistré dans le cluster comme disponible 
 cette section doit etre reserve au client type service

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

# Découverte de service et proxies (catégorie 04)

Un agent ne connaissait que les serveurs de son fichier de configuration.
Ajouter un core au cluster demandait de repasser sur chaque machine du parc ; en
retirer un laissait les agents s'y acharner. Un proxy déployé, lui, n'apparaissait
dans aucune configuration — donc aucun agent n'y passait, donc il ne servait à
rien.

```
04_01  s'enregistrer dans le cluster   (nœud → core)
  04_02  accusé
04_03  demander les nœuds joignables   (client → core)   contenu vide
  04_04  la liste, ORDONNÉE            (core → client)
04_05  remonter une métrique           (nœud → core)
  04_06  accusé
04_07  battre                          (nœud → core)
  04_08  accusé
```

> **Ce qui est en place** : les lots 0 à 3 — un agent apprend ses nœuds
> joignables, un proxy existe dans le cluster et bat. **Le relais TCP et le
> relais LDAP/S ne sont pas écrits** ; ils restent spécifiés plus bas.

## Ce qui bloquait

La catégorie `04` était écrite **côté serveur** presque en entier. Ce qui
manquait n'était pas le code du core : c'est que le **catalogue de types ne
l'accordait à personne**, et que rien ne l'émettait.

| Trame | Code serveur | Émetteur, avant | Émetteur, maintenant |
|---|---|---|---|
| `04_01` | oui | personne | proxy |
| `04_03` | oui | personne | agent, proxy |
| `04_05` | oui | personne | proxy |
| `04_07` | oui | personne | proxy |

## Arbitrage 1 — la découverte vit en `04`, et nulle part ailleurs

Le tableau en tête de document a longtemps porté deux entrées de la catégorie
`02` pour « demander la liste des proxies/cores » et « rendre la liste ». Aucune
ligne de code ne les a jamais implémentées, et elles faisaient doublon avec
`04_03`/`04_04`. Elles ont été retirées du protocole.

La catégorie `02` est « User auth » : y ranger la découverte de service se
paierait à chaque lecture. Qui a le droit de demander reste décidé par le
catalogue de types, pas par le numéro de trame.

*(Détail du retrait : DO/2.1/2.1.md, entrée 9+10.)*

## Arbitrage 2 — le proxy est un RELAIS, il ne déchiffre rien

Deux modèles étaient possibles : transporter les octets sans les lire, ou
terminer la session Ducky et en ouvrir une autre vers le core.

C'est le **point 29 qui a tranché**. Avant lui, le chemin PAM ne faisait passer
qu'une preuve HMAC : un proxy qui terminait la session ne voyait rien
d'utilisable. Depuis, le mot de passe transite dans le tunnel — un proxy qui
déchiffrerait deviendrait un point de collecte des mots de passe du parc.

*Non implémenté.* C'est ce qui reste du sujet.

## Arbitrage 3 — les empreintes s'apprennent depuis une confiance existante

Sans cela, distribuer une liste de cores ne servirait à rien : l'agent
refuserait tous ceux qu'il ne connaît pas — c'est-à-dire tous sauf un.

`core_key_fingerprint` est donc devenu une **liste**. N'importe laquelle de ses
entrées suffit à accepter une clé. La première ligne reste celle déposée par
`vlt create -join`, la seule dont on sache par quel canal elle est arrivée ;
l'ordre du fichier le dit.

Une empreinte s'apprend en recevant `04_04`, qui la porte pour chaque nœud
annoncé. Le message ne s'atteste pas lui-même : il arrive sur une session dont la
clé du core a **déjà** été vérifiée. Ce n'est pas un nœud qui se déclare, c'est
un core de confiance qui atteste ses pairs.

**On n'apprend jamais depuis rien.** Une machine sans aucune empreinte est en
confiance au premier usage ; y ajouter une valeur venue du réseau serait la même
chose sous un autre nom. `ApprendreEmpreinte` refuse ce cas.

La liste est **bornée** à 16 entrées. Un fichier de confiance qui grossit tout
seul finit par ne plus rien attester — personne ne relit trente empreintes pour
savoir laquelle n'a rien à y faire. L'atteindre est un signal, d'où le refus
explicite plutôt qu'une éviction de la plus ancienne, qui retirerait justement
celle de l'installation.

> **Limite assumée.** Tout core de confiance peut ajouter de la confiance. Un
> core compromis fait apprendre au parc l'empreinte de son choix. Ce qui borne le
> risque est ailleurs : un core compromis détient déjà les clés du domaine, et
> l'empreinte n'est pas ce qui le retient.

## Arbitrage 4 — un nœud est joignable par défaut

`expose_aux_agents`, **VRAI par défaut**, y compris pour les nœuds déjà
enregistrés. Le défaut compte : à faux, la migration aurait retiré d'un coup tous
les cores existants de la liste, et le parc n'aurait plus eu aucune adresse — sur
une mise à jour censée n'ajouter qu'une fonctionnalité.

**Ce n'est pas un contrôle d'accès.** Le drapeau retire une adresse d'une liste,
il n'empêche personne de se connecter. Le pare-feu reste ce qui protège un core.
Il sert à sortir un nœud de la rotation sans le désenregistrer, ce qui le ferait
disparaître des vues de supervision au moment précis où on le surveille.

## Le tri est fait par le SERVEUR

L'agent parcourt la liste de haut en bas, sans rien décider.

Trier côté agent supposerait de lui envoyer de quoi le faire — métriques,
affinités, état de chaque nœud — c'est-à-dire de distribuer à toutes les machines
du parc une carte de l'infrastructure. Et chaque agent trierait avec SA version
du code : changer la règle demanderait de mettre le parc à jour avant qu'elle
prenne effet.

L'ordre, en trois critères :

1. les **proxies** avant les cores — c'est leur raison d'être ;
2. à rôle égal, la **priorité la plus basse** d'abord ;
3. à priorité égale, le **nom**, pour que l'ordre soit reproductible.

Les cores restent **toujours** dans la liste, en queue : un client dont tous les
proxies échouent doit pouvoir en joindre un, sans quoi la panne d'un relais
deviendrait une panne d'authentification.

**Zéro se range APRÈS.** Une priorité nulle vaut « sans préférence ». Si elle se
rangeait avant, donner une priorité à un seul nœud le reléguerait derrière tous
les autres — l'exact inverse de l'intention. C'est le piège classique d'un défaut
à zéro sur un champ d'ordre, et il se paie une fois en production.

Le troisième critère n'est pas décoratif : sans lui, deux nœuds équivalents
s'ordonneraient selon le plan d'exécution, et tout le parc basculerait ensemble
sur un nœud que rien n'a désigné.

## Ce qu'un nœud doit déclarer pour être annoncé

Trois choses, et leur absence l'écarte de la liste plutôt que de l'y faire
figurer à moitié :

| | Sans quoi |
|---|---|
| un **port** | l'agent composerait l'adresse avec un port deviné — une tentative qui échoue, un délai, un basculement retardé |
| une **empreinte** | l'agent devrait accepter la clé de ce nœud en aveugle à sa première connexion |
| l'état **en ligne** | l'adresse serait servie alors que personne n'écoute |

Le core se déclare lui-même au démarrage, avec le port de sa configuration
d'écoute — la même source, pour que les deux ne puissent pas diverger. Sur une
installation mono-core, un défaut ici reviendrait à n'annoncer personne, et rien
ne relierait « les agents ne trouvent plus de serveur » à une colonne ajoutée au
schéma. D'où le message d'erreur explicite.

## Un nœud n'écrit que SA ligne

C'est la règle dont dépend toute la chaîne de confiance de la découverte. Elle
n'existait pas : `04_01` lisait le hostname, l'IP et le **rôle** dans le contenu
de la trame, sans aucun lien avec la session authentifiée.

Un proxy enrôlé pouvait donc envoyer le hostname d'un core. L'écriture écrasait
sa ligne — adresse, port et **empreinte** comprises. La `04_04` annonçait ensuite
l'empreinte de l'attaquant sous le nom du core ; les agents l'apprenaient, la
plaçaient devant leurs serveurs statiques, et s'y connectaient pour
s'authentifier. Élévation de « service qui relaie » à « serveur qui
authentifie ».

### Deux barrières indépendantes

**La ligne appartient à quelqu'un.** `cluster_nodes.owner_client_id` porte
l'identifiant machine figé à la poignée de main `01_01`. Un nœud met à jour la
ligne dont il est propriétaire, ou la crée — et se voit refuser un hostname déjà
pris par un autre propriétaire, ce qui est précisément le geste de l'usurpation.

Deux formes de propriétaire :

| Forme | Qui |
|---|---|
| `<client_software_id>` | un nœud enregistré par le réseau — proxy, service |
| `@core:<hostname>` | un core, qui écrit sa ligne depuis son propre processus |

Le préfixe `@` est **réservé** : un propriétaire venu d'une session ne peut pas
commencer par lui. Et le nom du core porte son **hostname**, parce qu'une valeur
commune à tous les cores laisserait chacun écrire la ligne des autres — le même
défaut, sous une autre forme.

**Le rôle se déduit, il ne se déclare pas.** `clienttype.RoleCluster` le rend à
partir du type figé à la poignée de main. `vaultaire_proxy` → `proxy`, et rien
d'autre ne prend de rôle de nœud. **Aucun type ne peut produire `core`** : un
core n'est pas au catalogue — il ne peut pas se juger lui-même — et n'entre dans
la table que par son propre processus. Le rôle annoncé dans la trame n'est plus
lu que pour journaliser un écart.

### La même règle sur les trois autres trames

| Trame | Désignait la ligne par | Désormais |
|---|---|---|
| `04_01` | hostname et IP du contenu | propriétaire |
| `04_07` | hostname du contenu | propriétaire |
| `04_05` | hostname du contenu | hostname de la ligne du propriétaire |
| `04_12`, `04_14` | hostname de l'en-tête | propriétaire |

Un battement dit « **je** suis là », pas « celui-là est là ». Sans quoi n'importe
quel nœud maintenait en ligne la ligne d'un core éteint, qui restait annoncé aux
agents et absorbait leurs tentatives. Et les métriques alimentent le **tri** de
la liste : les écrire au nom d'un pair revenait à décider vers qui le parc se
dirige.

`04_12` et `04_14` prenaient l'identifiant dans l'**en-tête** — que
`Split_Action` vérifie déjà contre la session. Ce n'était donc pas exploitable,
mais c'était juste *par dépendance* : le jour où ce contrôle bouge, ce code
devient faux sans avoir été touché.

### Le piège de `RowsAffected`

`RegisterNode` fait un `SELECT` puis un `UPDATE` par identifiant, et non un
`UPDATE` dont on lirait le nombre de lignes touchées. MySQL rend `0` quand
l'`UPDATE` ne **change** rien — le cas ordinaire d'un nœud qui se réenregistre
sans avoir bougé. S'en servir pour conclure « la ligne n'existe pas » ferait
échouer chaque réenregistrement sur un conflit de hostname : un défaut qui
n'apparaît qu'au **deuxième** démarrage d'un nœud stable.

## Ce que l'agent fait de la liste

Il la **fusionne** : les nœuds appris devant, les serveurs du fichier de
configuration derrière.

**Les statiques ne sont jamais écrasés.** Ils sont le dernier recours. Un agent
qui les remplacerait par les nœuds reçus n'aurait plus rien à joindre le jour où
la liste distribuée est vide, fausse, ou pointe sur des nœuds tous éteints — et
il faudrait repasser à la main sur les machines, c'est-à-dire exactement ce que
la découverte existe pour éviter.

**Une liste vide n'en écrase pas une pleine.** Un core qui répond « aucun nœud » a
peut-être une base indisponible. Effacer sur cette foi couperait l'agent de tout
ce qu'il avait appris, au moment précis où le core va mal.

Cadence : 30 minutes, constante côté agent. La liste ne change qu'à l'ajout ou au
retrait d'un nœud. Une machine qui a besoin de la liste *tout de suite* — parce
que son serveur habituel ne répond plus — ne l'attend pas : elle bascule sur
l'adresse suivante, qu'elle a déjà.

## Ce que le proxy émet

`04_01` au démarrage, `04_07` toutes les 20 secondes, `04_03` pour trouver ses
cores. La cadence de battement est **locale et volontairement courte** : un
`reglages` lit la base, qu'un proxy n'a pas, et un battement trop espacé ferait
déclarer hors ligne un nœud parfaitement vivant.

`-listen-port` est **obligatoire et sans défaut**. Une valeur devinée serait
annoncée à tout le parc, et les agents s'y connecteraient sans que rien n'écoute.

Un échec de raccordement **n'arrête pas le proxy** : il reste connecté et
authentifié, il perd sa visibilité. Traiter cela comme fatal ferait qu'un nom
d'hôte introuvable coupe un service qui fonctionne par ailleurs.

---

# Ce qui reste du sujet 04

## Arbitrage 5 — l'affinité core ↔ groupe *(non implémenté)*

Table `(nœud, groupe, priorité)`, la MÊME que celle des proxies. Priorité et non
exclusivité : ordre servi — proxies affins, autres proxies, cores affins exposés,
autres cores exposés.

## Arbitrage 6 — une clé d'enrôlement porte une affinité, pas un droit *(non implémenté)*

Le rattachement est appliqué **une fois**, à l'enrôlement. Le relire à chaque
connexion ferait qu'une clé modifiée changerait les groupes d'un service déjà en
production, et le lien entre la cause et l'effet serait introuvable des mois plus
tard.

Ce que les groupes portent est décidé ailleurs, et reste modifiable après coup.
Une clé qui accorderait des droits deviendrait un second système de permissions,
à tenir d'accord avec le premier.

## Le relais *(non implémenté)*

Relais TCP Ducky, puis relais LDAP/S avec le SAN du core couvrant les proxies.

**Que fait un proxy dont tous les cores sont injoignables ?** Tranché : il
**refuse franchement**. Un client qui reçoit un refus essaie le suivant de sa
liste — un core, puisqu'ils y figurent toujours. Un client en attente ne fait
rien pendant tout le délai, et le proxy en panne devient un trou noir au lieu
d'un nœud qu'on contourne.

## Découpage restant

| Lot | Contenu | Dépend de |
|---|---|---|
| 4 | Relais TCP Ducky | fait (3) |
| 5 | Relais LDAP/S, SAN du core couvrant les proxies | 4 |
| 6 | Table d'affinité `(nœud, groupe, priorité)` et tri côté serveur | fait (1, 3) |
| 7 | Groupes portés par une clé d'enrôlement | 6 |

Le lot 7 vient **après** le 6 et non avant : rattacher un service à des groupes
n'a aucun effet observable tant que l'affinité ne trie rien. L'écrire d'abord
donnerait une fonctionnalité qu'on ne peut pas éprouver.


# Synchronisation des groupes de la machine (catégorie 03)

Les appartenances arrivent avec `03_02`, à chaque connexion. Encore faut-il que
les groupes existent sur la machine : sans eux, une appartenance annoncée n'est
posée nulle part. C'est ce que cet échange apporte.

```
03_08  demande            (agent → core)   contenu vide
  03_09  liste            (core → agent)   sync:<minutes> puis <nom>:<id_group>
  03_10  refus            (core → agent)   <raison>
```

L'agent émet au démarrage du service, puis à la cadence que le core lui annonce,
et une fois de plus quand une ouverture de session révèle un groupe annoncé mais
absent localement — le seul moment où l'écart est visible et où il a une
conséquence immédiate.

## Le GID vient du core

`GID = 100000 + id_group`.

Un GID choisi localement serait différent sur chaque machine. Sur un partage NFS,
où seuls des nombres circulent, deux postes du même domaine liraient alors des
droits différents sur les mêmes fichiers. C'est le problème que `uid.map` résout
pour les utilisateurs, et il ne se résout pas machine par machine : le seul point
qui voit tout le domaine est le core.

La formule est **sans état**. Une machine réinstallée retrouve les mêmes numéros
sans rien recopier, et deux machines qui découvrent les groupes dans un ordre
différent obtiennent le même résultat. Une table d'allocation aurait ajouté un
état à sauvegarder, à migrer, et à réparer le jour où il diverge de `groups`.

### Pourquoi 100000

`ProvisionVaultaireUser` donne à chaque compte un groupe primaire dont le GID
vaut l'UID : **5000–60000 est déjà consommé en entier**. Y placer les groupes du
domaine garantirait la collision — deux groupes portant le même numéro, donc des
droits qui s'appliquent au mauvais.

60001–65533 est libre mais étroit et bute sur `nogroup`. Les GID sont des entiers
32 bits ; 100000 laisse la place et reste lisible dans un `ls -n`.

Borne haute : `id_group ≤ 60000`. La table `groups` en est très loin — la borne
existe pour que l'hypothèse soit **vérifiée** plutôt que supposée.

### La règle est écrite des deux côtés

`db_groups.GIDDeGroupe` et `localusermanagement.GIDDeGroupe`, dans deux modules
Go qu'aucune compilation ne relie.

C'est le prix d'un choix : `03_09` porte les `id_group`, **pas les GID**. Envoyer
le numéro déjà calculé laisserait un core en imposer un arbitraire — dont `0`,
qui est `root`. Le core est authentifié, il n'est pas infaillible : une injection
SQL, une base restaurée de travers, un bogue suffisent.

Des tests jumeaux figent les constantes aux deux bouts, plus un test côté agent
qui refuse que la plage des groupes descende sur celle des UID. Sans eux, une
divergence n'apparaîtrait qu'au premier partage NFS, sous forme de droits qui ne
s'appliquent pas, sans message d'erreur nulle part.

## Ce que la machine reçoit

Les groupes des **domaines** auxquels elle appartient — pas ceux dont elle est
membre, pas ceux du reste de l'organisation.

Le filtre porte sur le domaine parce qu'un utilisateur qui s'y connecte peut
appartenir à un groupe que la machine ne partage pas. Il ne va pas plus loin
parce que la liste complète des groupes de l'organisation est une information de
structure, et que `/etc/group` est lisible par tous les comptes locaux du poste.

L'identifiant de la machine est lu dans **l'en-tête** de `03_08`, où la couche de
session l'a posé — donc authentifié. Le lire dans le contenu laisserait n'importe
quel agent réclamer les groupes d'un autre.

## La cadence voyage avec la liste

`group_sync_minutes` est un réglage du core (défaut 60 min), mais la boucle qu'il
pilote tourne sur l'agent. Sa valeur part donc dans `03_09`, sur une ligne
préfixée `sync:`.

L'alternative — une constante côté agent — aurait reproduit un défaut déjà nommé
ici : `IntervalleRapportAgent` duplique `gpo.MachineRefreshInterval`, et allonger
l'un sans l'autre fait apparaître tout le parc en retard du jour au lendemain.
Surtout, **un réglage qui s'affiche sans agir est plus trompeur que pas de
réglage du tout**.

La boucle de l'agent reconstruit son `time.After` à chaque tour : un `Ticker`
lirait sa période une seule fois, et la nouvelle valeur n'aurait d'effet qu'au
redémarrage du service. C'est la raison d'être de `reglages.Boucle` côté core, et
la même ici.

Une machine hors ligne applique la nouvelle cadence à son retour, pas avant.

## La suppression vide le groupe, elle n'efface pas la ligne

Quand un groupe disparaît du domaine, l'agent **retire ses membres** et
**conserve la ligne**.

Effacer la ligne rendrait orphelins tous les fichiers dont c'est le groupe
propriétaire : `ls -l` n'afficherait plus qu'un nombre, sur des données que
personne n'a demandé à toucher, et sans qu'aucune trace n'explique le numéro. Un
agent ne peut pas savoir ce qui en porte la marque sans parcourir tous les
systèmes de fichiers montés — partages réseau compris, où le parcours dure des
heures et où les fichiers appartiennent à d'autres machines.

Vider suffit à couper les droits, immédiatement et partout. Le nom subsiste pour
que l'administrateur puisse lire ce qu'il regarde.

L'effacement définitif est une décision humaine : `vaultaire_client
--purge-groups` affiche ce qui serait effacé, et n'agit qu'avec `--confirm`.

> **Écart avec la spécification initiale.** Elle proposait `vlt purge groups
> --machine <id>`, une commande du core. Cela aurait supposé une trame de plus,
> autorisant une écriture dans `/etc/group` à distance : une frontière de
> privilège neuve, donc une clé RBAC, une action et une entrée de catalogue —
> pour un geste dont le seul bénéfice est de la propreté, le vidage ayant déjà
> coupé les droits. La commande est donc locale, sur la machine concernée.

## Ce que l'agent ne touche jamais

Les groupes qu'il n'a pas créés. La limite est tenue par `/etc/vaultaire/groups.map`,
au format `<nom>:<gid>`, écrit atomiquement — même modèle que `user_groups.map`
pour les appartenances, et que `uid.map` pour les identifiants.

Un groupe local **homonyme** d'un groupe du domaine n'est jamais repris : il est
signalé en WARNING et laissé intact, GID compris. Le renuméroter changerait le
propriétaire de tous les fichiers qui en portent la marque.

**État illisible ⇒ aucun vidage.** Vider sans savoir ce qu'on a créé reviendrait
à toucher aux groupes de l'administrateur local — ce que le fichier existe pour
empêcher. Les créations, elles, se font quand même : elles n'enlèvent rien.

**Trois fichiers d'état sont deux de trop.** Les fusionner est possible, mais
`uid.map` est lu par le module NSS, en C, dans des processus non privilégiés :
en changer le format engage bien plus que la synchronisation des groupes. La
séparation est le choix prudent, pas le choix élégant.

## Les refus, et la liste vide

`03_10` et « aucun groupe » ne se confondent pas, et la distinction compte : un
domaine peut légitimement n'avoir aucun groupe, auquel cas il faut vider ceux qui
restent — mais vider le parc parce que la base du core est indisponible serait
exactement le mauvais réflexe.

Devant un refus, l'agent ne touche à rien. Devant une réponse dont **toutes** les
lignes ont été rejetées, non plus : elle ressemble à une liste vide sans en être
une.

Le motif du refus est volontairement grossier — « indisponible », jamais le
détail de l'erreur SQL. La trame part vers une machine du parc, dont le journal
est lisible par qui a un accès local.

## Ordre des opérations

Créations **avant** vidages — l'inverse de ce que fait `03_02` pour les
appartenances, et pour la même raison de fond.

Pour les appartenances, retirer d'abord garantit qu'un incident au milieu laisse
l'utilisateur avec moins de droits qu'attendu, jamais plus. Ici, vider d'abord
ouvrirait une fenêtre pendant laquelle un groupe renommé — disparu sous un nom,
réapparu sous un autre — n'existerait sous aucun des deux. Créer d'abord ne
retire jamais de droit par accident : le vidage qui suit s'en charge, sur une
liste déjà à jour.

## Ce qui reste ouvert

**Le groupe primaire de l'utilisateur** porte le nom du compte et le GID de son
UID. Le remplacer par un groupe du domaine toucherait `/etc/passwd` et la
propriété des fichiers déjà créés. Choix retenu : ne pas y toucher, ne gérer que
les groupes secondaires.

**Les machines hors ligne longtemps.** Une machine absente six mois retrouve des
groupes supprimés depuis. Le vidage les traite au premier contact, mais entre son
démarrage et cette synchronisation, les droits sont ceux d'il y a six mois.
Refuser les sessions en attendant transformerait une panne de réseau en
verrouillage de la machine : ce n'est pas fait.
