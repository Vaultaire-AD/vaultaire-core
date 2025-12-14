dans la colone 1 serveur ou client c'est le partie qui recoit la tramme pas qui l'envoie

| Name_trames | Main Number | Second Number | desciption                   | Example                                                                                |
| ----------- | ----------- | ------------- | ---------------------------- | -------------------------------------------------------------------------------------- |
| Server auth | 01          |               |                              |                                                                                        |
| serveur     |             | 01            | client ask server auth       |                                                                                        |
| client      |             | 02            | serveur proof of work        |                                                                                        |
|             |             |               |                              |                                                                                        |
|             |             |               |                              |                                                                                        |
|             |             |               |                              |                                                                                        |
|             |             |               |                              |                                                                                        |
|             |             |               |                              |                                                                                        |
| User auth   | 02          |               |                              |                                                                                        |
| serveur     |             | 01            | ask auth                     | le client demande une auth pour le user qui tente de se co                             |
| client      |             | 02            | proof of work                | 02_03\nserveur_central\nvisiteur\nIJVSEMNJA\nfeisfjsefijsmefjsmefj                     |
| serveur     |             | 03            | check auth                   | verifie les informations envoyépar le user pour valider l'auth                         |
| client      |             | 04            | auth_succes                  | quand l'auht a reussit                                                                 |
| serveur     |             | 05            | close session                | ferme la session pour que le user se logout                                            |
|             |             |               |                              |                                                                                        |
| client      |             | 07            | failed                       | trame que recoit le client si echec de l'auth                                          |
|             |             |               |                              |                                                                                        |
| client      |             | 11            | ask_information              | le serveur va demander des information au pc hostname etc                              |
| serveur     |             | 12            | serveur_information          | la trame d'information envoyé par les softwares serveur                                |
| serveur     |             | 13            | client_information           | la trame d'information envoyé par les softwares client                                 |
|             |             |               |                              |                                                                                        |
| serveur     |             | 15            | ask GPO                      | le client demande au serveur de lui envoyé les GPO de l'utilisateur                    |
| client      |             | 16            | send GPO                     | Envoie au client toutes ses GPOs                                                       |
|             |             |               |                              |                                                                                        |
|             |             |               |                              |                                                                                        |
| SSH         | 03          |               |                              |                                                                                        |
| server      |             | 01            | client ask if user can login | le client envoie un username et attend un reponse d'auth avec les clé public du client |
| client      |             | 02            | server awnser   succes       | le server renvoie une reponse succes  avec les clé public du user                      |
| client      |             | 03            | server anwser failed         | le server renvoie une reponse failed avec la raison de l'echec                         |
|             |             |               |                              |                                                                                        |
