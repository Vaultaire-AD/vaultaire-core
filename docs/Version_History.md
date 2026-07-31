# 🕰️ Historique des Versions & Changements

-   ## 🔰 Alpha

    - ### 🚀 **Alpha 1.0** *(nom de code : ROCKET)* - *06/03/2025*  
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
        - ### 🛠️ Patch**Alpha 1.1.4** - *20/07/2026* 
            - Changement sur la table user_permission ("api_write_permission, api_read_permission) - Lorens Viguie
            - Debut de l'api REST pour vaultaire - Lorens Viguie
            - Changement sur la gestion des clé pour les differents services cle unique mtn - Lorens Viguie
            - Ajout des clé public pour les users via WebUI ou vaultaire_cli/vaultaire_ctl - Lorens Viguie
            - Ajout de la logique des permission pour l'api et ldap par encore implémenter - Lorens Viguie
            - Intégration des permissions dans les commandes toutes a faire sauf - Lorens Viguie
            - Intégration des permissions dans ldap toutes a faire / en cour search
    - ### 🐷 **Alpha 2.0.0** *(nom de code : PIG)* - *a Venir Fin Aout*
        📌 **Changements depuis Alpha 1.1.4 :**

        - 🔐 **Sécurité**
            - Correction d'un bug **critique** sur la vérification du mot de passe lors de l'authentification - Lorens Viguie
            - Le droit super-admin `*` (tous domaines) donnait accès à des domaines inexistants ou mal tapés (ex `vault.fr` au lieu de `vaultaire.fr`) ; vérification de l'existence réelle du domaine avant d'accorder l'accès - Lorens Viguie
            - Immuabilité de l'identité d'amorçage : user `vaultaire`, groupe `vaultaire` et permissions `vaultaire_all`/`vaultaire_admin` non supprimables et non renommables, sur CLI, web, LDAP et API - Lorens Viguie
            - Le mot de passe ne transite plus en clair dans le Ducky-Network lors de l'authentification SSH - Lorens Viguie
            - Vérification du domaine du client déplacée du module PAM vers le serveur central (plus fiable, plus difficile à contourner) - Lorens Viguie

        - 🩹 **Session management (Ducky-Network, client & serveur)**
            - Refonte complète de la gestion des sessions avec un système map + mutex propre (remplace plusieurs variables globales non synchronisées : liste d'auth partagée, statut serveur en ligne, ancien package `sync`) - Lorens Viguie
            - Le SessionID devient la source de vérité pour identifier une session (plusieurs sessions peuvent partager le même username) - Lorens Viguie
            - Suivi du statut de connexion (authentifié / en attente / fermé) par session, côté client comme serveur - Lorens Viguie
            - Nombreux correctifs sur le flux d'authentification SSH (challenge / salt / nonce, transmission de l'ID client dans les trames, réponses 03_02/03_05, timeouts de fetch de clé) - Lorens Viguie

        - 🧹 **Logs & lisibilité**
            - Nettoyage complet du système de logs : plus aucun log en fonctionnement normal, WARNING pour ce qui est inhabituel, ERROR/WARNING pour les vrais problèmes (permissions, web, base de données) - Lorens Viguie
            - Correction des logs de la base de données systématiquement marqués `[ERROR]` même pour des messages informationnels - Lorens Viguie
            - Le module PAM crée maintenant son dossier de logs s'il est manquant (auparavant les logs disparaissaient silencieusement, donnant l'impression que le module n'était pas chargé) - Lorens Viguie
            - Correction d'un bug récurrent de parsing de date dans le nettoyage des sessions expirées - Lorens Viguie

        - ⚙️ **GPO**
            - Les restrictions GPO ne sont plus stockées en JSON en dur mais en base de données (tables `gpo_restriction`, `gpo_field_rule`, `gpo_value_definition`), éditables via une page d'administration `/admin/gpo/restrictions` réservée au groupe `vaultaire` - Lorens Viguie
            - Modes par champ (liste / motif regex / libre) avec motif d'exclusion prioritaire, socle par défaut réinitialisable - Lorens Viguie
            - Lecture fail-closed : plus aucun repli sur des valeurs internes si la base ne répond pas - Lorens Viguie
            - Peuplement initial via `gpo_seed.sql` (embarqué, exécuté uniquement au premier démarrage) - Lorens Viguie
            - Correction des jeux de commandes sudo par défaut absents du menu déroulant, et de l'aperçu qui affichait toutes les valeurs custom au lieu de la sélection - Lorens Viguie
            - Systeme de Scope User machines avec des actions prédefinis et des regles de restrictions - Lorens Viguie

        - 📖 **Documentation**
            - Mise à jour du `MAN.md` (modèle déclaratif GPO, restrictions, définitions, lecture fail-closed) et de `DataBase_Struct.md` (nouvelles tables GPO) - Lorens Viguie

---



