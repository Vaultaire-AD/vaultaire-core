dans la colone 1 serveur ou client c'est le partie qui recoit la tramme pas qui l'envoie

| Name_trames                 | Main Number | Second Number | desciption                       | Example                                                                             |
| --------------------------- | ----------- | ------------- | -------------------------------- | ----------------------------------------------------------------------------------- |
| Server auth                 | 01          |               |                                  |                                                                                     |
| serveur                     |             | 01            | client ask server auth           |                                                                                     |
| client                      |             | 02            | serveur proof of work            |                                                                                     |
|                             |             |               |                                  |                                                                                     |
|                             |             |               |                                  |                                                                                     |
|                             |             |               |                                  |                                                                                     |
|                             |             |               |                                  |                                                                                     |
|                             |             |               |                                  |                                                                                     |
| User auth                   | 02          |               |                                  |                                                                                     |
| serveur                     |             | 01            | ask auth                         | le client demande une auth pour le user qui tente de se co                          |
| client                      |             | 02            | proof of work                    | 02_03\nserveur_central\nvisiteur\nIJVSEMNJA\nfeisfjsefijsmefjsmefj                  |
| serveur                     |             | 03            | check auth                       | verifie les informations envoyépar le user pour valider l'auth                      |
| client                      |             | 04            | auth_succes                      | quand l'auht a reussit                                                              |
| serveur                     |             | 05            | close session                    | ferme la session pour que le user se logout                                         |
|                             |             |               |                                  |                                                                                     |
| client                      |             | 07            | failed                           | trame que recoit le client si echec de l'auth                                       |
|                             |             |               |                                  |                                                                                     |
| client                      |             | 11            | ask_information                  | le serveur va demander des information au pc hostname etc                           |
| serveur                     |             | 12            | serveur_information              | la trame d'information envoyé par les softwares serveur                             |
| serveur                     |             | 13            | client_information               | la trame d'information envoyé par les softwares client                              |
|                             |             |               |                                  |                                                                                     |
| server                      |             | 17            | ask list proxy/core              | le client Demande la liste des serveurs a joindre pour se connecter au réseau       |
| client                      |             | 18            | respond list                     | le serveur repond la liste des serveur joignable                                    |
|                             |             |               |                                  |                                                                                     |
| SSH                         | 03          |               |                                  |                                                                                     |
| server                      |             | 01            | client ask if user can login     | le client envoie un username/password et attend  d'auth avec les clé public du user |
| client                      |             | 02            | server awnser   succes           | le server renvoie un succes  avec les clé public du user et le boolean admin        |
| client                      |             | 03            | server anwser failed             | le server renvoie un failed avec la raison de l'echec                               |
| server                      |             | 04            | client ask for salt              | le client demande le salt d'un user                                                 |
| client                      |             | 05            | server respond with key          | le serveur repond simplement le salt du user                                        |
|                             |             |               |                                  |                                                                                     |
| Cluster / Service discovery | 04          |               | (plage réservée : 04_01 à 04_19) |                                                                                     |
| client (host/proxy)         |             | 01            | register_host                    | enregistrement d’un hôte (proxy, etc.) : hostname, fqdn, ip, role, domain           |
| serveur                     |             | 02            | register_host_ok                 | confirmation + session considérée établie pour le host                              |
| client                      |             | 03            | list_cores                       | demande la liste des Cores en ligne (service discovery)                             |
| serveur                     |             | 04            | list_cores_response              | liste des Cores (id, hostname, ip, port, stress, capabilities)                      |
| client                      |             | 05            | proxy_metrics                    | envoi des métriques du proxy vers le Core (pour table proxy_metrics)                |
| serveur                     |             | 06            | proxy_metrics_ack                | accusé de réception                                                                 |
| client                      |             | 07            | host_heartbeat                   | heartbeat du host pour rester dans cluster_nodes (online)                           |
| serveur                     |             | 08            | host_heartbeat_ack               | accusé heartbeat                                                                    |
|                             |             |               |                                  |                                                                                     |
| GPO                         | 05          |               | (plage utilisée : 05_01 à 05_14) | voir « Détail du transport GPO » en fin de document                                  |
| serveur                     |             | 01            | ask_gpo_machine                  | le client demande ses GPO machine, en annonçant l'empreinte qu'il applique déjà     |
| client                      |             | 02            | gpo_machine_manifest             | réponse succès à 05_01 : version, empreinte, découpage                              |
| client                      |             | 03            | gpo_machine_unchanged            | réponse à 05_01 : l'empreinte du client est à jour, rien à appliquer                |
| client                      |             | 04            | gpo_machine_error                | réponse erreur à 05_01                                                              |
| serveur                     |             | 05            | ask_gpo_user                     | le client demande les GPO user après authentification, avec son empreinte courante  |
|                             |             |               |                                  | attention ne seront appliquées que les GPO user des groupes auxquels appartiennent   |
|                             |             |               |                                  | a la fois la machine et a la fois l'utilisateur                                     |
|                             |             |               |                                  | et non l'ensemble des GPO user liées a l'utilisateur                                |
| client                      |             | 06            | gpo_user_manifest                | réponse succès à 05_05 : version, empreinte, découpage                              |
| client                      |             | 07            | gpo_user_unchanged               | réponse à 05_05 : l'empreinte du client est à jour, rien à appliquer                |
| client                      |             | 08            | gpo_user_error                   | réponse erreur à 05_05                                                              |
| serveur                     |             | 09            | ask_gpo_chunk                    | le client réclame un fragment de la politique annoncée (les deux scopes)            |
| client                      |             | 10            | gpo_chunk                        | réponse succès à 05_09 : un fragment de politique                                   |
| client                      |             | 11            | gpo_chunk_error                  | réponse erreur à 05_09 : empreinte périmée, index invalide, transfert inconnu        |
| serveur                     |             | 12            | gpo_apply_report                 | le client rapporte le résultat de l'application, module par module (les deux scopes) |
| client                      |             | 13            | gpo_apply_report_ack             | réponse succès à 05_12                                                              |
| client                      |             | 14            | gpo_apply_report_error           | réponse erreur à 05_12 : rapport malformé ou empreinte inconnue                     |


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
msg := "03_04\nserveur_central\n" + SessionKey + "\nvaultaire\n" + Computeur_ID + "\n" + req.User
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
return "03_05\nserveur_central\n" + SessionIntegritykey + "\nvaultaire\n" + sshUser + "\n" + salt + "\n" + nonce
```
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
```

Les blocs 05_09 et 05_12 sont **partagés** entre les deux scopes : la logique de
transfert de fragment et de rapport est rigoureusement identique, la dédoubler
donnerait deux fois le même code à maintenir et à tester. Pour ces trames
uniquement, le scope voyage donc dans le contenu (première ligne).

Slots libres pour la suite : **05_15 et au-delà**.

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

## Charge utile de la politique

Les fragments réassemblés forment un document JSON canonique, celui déjà produit
par `gpo.CanonicalJSON` :

```json
{
  "name": "effective_machine",
  "scope": "machine",
  "version": 7,
  "enabled": true,
  "modules": [
    { "type": "sysctl", "scope": "machine", "apply_order": 11,
      "params": { "key": "net.ipv4.ip_forward", "value": "0" } }
  ]
}
```

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
