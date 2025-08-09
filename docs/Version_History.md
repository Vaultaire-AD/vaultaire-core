# 🕰️ Historique des Versions & Changements

-   ## 🔰 Alpha

    - ### 🚀 **Alpha 1.0** - *06/03/2025*  
        **Première version Alpha de Vaultaire_AD**  

        📌 **Fonctionnalités incluses :**  
            - Implémentation des **commandes principales** du serveur. - Lorens Viguie
            - **Gestion des Admin Locaux** fonctionnelle via les permissions. - Lorens Viguie
            - **Compatibilité Linux uniquement**. - Lorens Viguie  
            - Fichiers de configuration **minimaux** : - Lorens Viguie  
                - `server.conf` : Port d’écoute & base de données.  
                - `client.conf` : IP du serveur.  

        ⚠️ **Limitations connues :**  
            - **Permissions et gestion des groupes** non encore fonctionnelles. - Lorens Viguie  
            - **Compatibilité Windows & macOS** non supportée. - Lorens Viguie  
            - ☠️ **Intégrité Du DuckyNetwork Compromise**. - Lorens Viguie

        📅 **À venir dans les prochaines versions :**  
            - Implémentation des **règles de permissions Client et groupes**.    
            - Amélioration de la **sécurité patch de la faille connue**.  
            - Implementation Du **Super Administrateur**

        - #### 🛠️ Patch**Alpha 1.0.1** - *08/03/2025*
            - Correction des verification des droit administrateur via les permission client et non plus user - Lorens Viguie
            - Correction du bug de logout qui faisait crash les clients - Lorens Viguie
            - Correction du bug sur les commandes delete via le cli - Lorens Viguie
            - Correction du bug du never failed sur la connection tjrs timeout - Lorens Viguie
            - ajout de la commande get -p pour voire toutes les permissions - Lorens Viguie
            - ajout du check des entrée utilisateur lors de relation avec la database - Lorens Viguie
            - Ajout du check des connection via la presence dans le meme groupe ou permission pour les user et les clients - Lorens Viguie
        - #### 🛠️ Patch**Alpha 1.0.2** - *15/03/2025*
            - Correction du bug d'affichage lors de la création d'un client - Lorens Viguie
            - Correction du bug qui empecher de crée des groupes -> **UPDATE** dans la man sur la commande create -g - Lorens Viguie
            - Correction du bug qui faisait crash le serveur avec vlt get -g groupequiexsitepas - Lorens Viguie
            - Correction des bug qui empeche de delete des user client et group - Lorens Viguie
            - Correction du bug qui empeche de retiré une perm client a un group - Lorens Viguie
            - Ajout a la commande get -p d'une colone IsAdmin pour voir si une perm est admin - Lorens Viguie 
            - Ajout de la verification de l'integrité Du DuckyNetwork Patch Faille de sécu sur le DuckyNetwork - Lorens Viguie
        - #### 🛠️ Patch**Alpha 1.1.0** - *16/04/2025*
            - Modification de la creation des users - Lorens Viguie
            - Ajout du tracking automatique des client serveur au demarage des serveurs - Lorens Viguie
            - Ajout de la version Alpha des GPO linux - Lorens Viguie
            - Gestion des commandes sudo via l'auth local et non plus via des requetesr au serveur central - Lorens Viguie
            - Suppresion automatique des comptes vaultaire sur les client apres 4 jour sans connection - Lorens Viguie
        - #### 🛠️ Patch**Alpha 1.1.1** - *11/05/2025*
            - Ajout automatique de nouveau client sous rocky linux - Lorens Viguie
            - Bug for status of serveur session for see if they are online - Lorens Viguie
        - #### 🛠️ Patch**Alpha 1.1.2** - *09/06/2025*
            - correction bug de surchage de logs - Lorens Viguie
            - ajout de la gestion de la perte de connection pour les serveur distant - Lorens Viguie
            - implementation de la premiere version du plugin ldap - Lorens Viguie
            - Correction d'un bug sur la comparaison des password avec les salts - Lorens Viguie
            - implementation de la premiere version de ldap fonctionnelle - Lorens Viguie
            - update de la structure des user dans la base de donnée - Lorens Viguie
         
        - #### 🛠️ Patch**Alpha 1.1.3** - *11/07/2025* 
            - Ajout de la feature LDAPS - Lorens Viguie
            - Optimisation mineur de certain de la sanitize fonction - Lorens Viguie
            - Ajout du site internet pour que les utilisateurs puissent mettre a jour leur information personnel - Lorens Viguie


---



