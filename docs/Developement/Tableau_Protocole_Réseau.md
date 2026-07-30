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
| GPO                         | 05          |               |                                  |                                                                                     |
| serveur                     |             | 01            | client ask for GPO Machine       | le client demande au serveur de lui envoyé l'ensemble de ses GPO machines           |
| client                      |             | 02            | Server send GPO Machine          | le client recoit les GPO qu'il doit appliquer par le serveur central                |
|                             |             | 03            |                                  |                                                                                     |
|                             |             | 04            |                                  |                                                                                     |
| server                      |             | 05            | client ask for GPO User          | le client demande a la suite d'une connection d'un utilisateur les GPO user         |
|                             |             |               |                                  | attention ne seront appliquer les GPO user via les groupes auquelle appartient      |
|                             |             |               |                                  | a la fois la machine et a la fois le client                                         |
|                             |             |               |                                  | et non l'ensemble des GPO user liées a l'utilisateurs                               |
| client                      |             | 06            | server send gpo user             | le client recoit les GPO user a applqiuer suite a une connection user               |
|                             |             | 07            |                                  |                                                                                     |
|                             |             | 08            |                                  |                                                                                     |
|                             |             | 09            |                                  |                                                                                     |
|                             |             | 10            |                                  |                                                                                     |


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