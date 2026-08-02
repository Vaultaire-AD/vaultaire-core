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
    - ### 🐷 **Alpha 2.0.0** *(nom de code : PIG)* - *02/08/2026*
        📌 **Changements depuis Alpha 1.1.4 :**

        - 🔐 **Sécurité**
            - Correction d'un bug **critique** sur la vérification du mot de passe lors de l'authentification - Lorens Viguie
            - Le droit super-admin `*` (tous domaines) donnait accès à des domaines inexistants ou mal tapés (ex `vault.fr` au lieu de `vaultaire.fr`) ; vérification de l'existence réelle du domaine avant d'accorder l'accès - Lorens Viguie
            - Immuabilité de l'identité d'amorçage : user `vaultaire`, groupe `vaultaire` et permissions `vaultaire_all`/`vaultaire_admin` non supprimables et non renommables, sur CLI, web, LDAP et API - Lorens Viguie
            - Le mot de passe ne transite plus en clair dans le Ducky-Network lors de l'authentification SSH - Lorens Viguie
            - Vérification du domaine du client déplacée du module PAM vers le serveur central (plus fiable, plus difficile à contourner) - Lorens Viguie
            - **Audit complet du système de permissions sur les 4 points d'entrée** (client Ducky, LDAP, CLI local/distant, interface web) — 14 constats, rapport dans `docs/Developement/Audit_Permissions.md` - Lorens Viguie
            - **Élévation de privilèges corrigée** : `GetGroupIDsForUser` retournait tous les groupes des *domaines* de l'utilisateur au lieu des groupes dont il est *membre*. Un compte du seul groupe « stagiaires » héritait des permissions de tous les groupes de son domaine, « admins » compris — l'appartenance à un groupe ne servait plus à rien pour le RBAC. Procédure de bascule et requêtes de diagnostic dans `docs/Developement/migrations/rbac_groupes_stricts.md` - Lorens Viguie
            - **Le `ClientSoftwareID` est désormais figé à la poignée de main et vérifié à chaque trame.** Un client authentifié pouvait réclamer les GPO d'une autre machine — donc ses règles sudo, sa configuration SSH et le contenu de ses fichiers déployés — ou le sel d'un utilisateur via 03_04 - Lorens Viguie
            - **Contrôle multi-domaines strict sur toutes les écritures** (`CheckPermissionsAllDomains`). Un droit sur un seul domaine suffisait pour agir sur une entité qui en couvre plusieurs : `add -u X -k <clé>` laissait un délégué poser sa propre clé SSH sur un compte ayant des droits ailleurs, puis s'authentifier à l'API sous cette identité. La lecture reste tolérante - Lorens Viguie
            - **Anti-rejeu sur l'API signée** : horodatage dans le corps signé et registre de nonces sur fenêtre glissante de 2 minutes. La signature dit qui, jamais quand — une requête capturée restait rejouable indéfiniment. ⚠️ Changement de protocole : `api_client_package` et `vaultaire_ctl` mis à jour, tout consommateur externe de `/api/command` doit ajouter `timestamp` au corps signé - Lorens Viguie
            - Socket UNIX d'administration passé en 0600 explicite. Toute commande y est exécutée en tant que `vaultaire` sans authentification : sa seule protection était le umask du processus, fixé nulle part - Lorens Viguie
            - `vaultaire_all` n'est plus modifiable de l'intérieur : les gardes couvraient la suppression et le renommage, mais `update -pu vaultaire_all web_admin nil` verrouillait tout le monde dehors sans rien supprimer - Lorens Viguie
            - Suppression d'un certificat réservée aux membres du groupe `vaultaire` (supprimer le certificat TLS de l'API ou de LDAPS interrompt le service, et un certificat ne porte aucun domaine sur lequel déléguer) - Lorens Viguie
            - Filtrage des entrées séparé en deux niveaux : `SanitizeIdentifier` en liste blanche pour ce qui **nomme** une entité, `SanitizeInput` en liste noire pour le texte libre. Un durcissement global aurait cassé les mots de passe, les infos matérielles (« Intel(R) Core(TM) i7 ») et les motifs regex des restrictions GPO - Lorens Viguie
            - `AuthID` généré en hexadécimal : `string(rune(bigint))` tronquait vers `U+FFFD`, faisant s'écraser deux authentifications simultanées dans le store — échecs de login aléatoires en charge - Lorens Viguie
            - Refus explicite d'une trame `02_03` vide : `bytes.Equal(nil, []byte(""))` vaut `true` en Go, la comparaison du challenge était franchie avec un username vide. La requête était arrêtée juste après, mais par accident - Lorens Viguie
            - **Second audit, ciblé base de données et interface web** — 10 constats, 7 corrigés. Rapport dans `docs/Developement/Audit_Serveur.md` - Lorens Viguie
            - **Les vues liste ne filtraient par aucun domaine.** Régression du correctif précédent : en ouvrant les pages aux administrateurs délégués, le contrôle par entité n'avait été ajouté que sur les écritures. Un délégué d'un domaine voyait tout l'annuaire. Nouveau `permission.DomainsWhereAllowed` et filtrage des quatre listes plus la recherche globale - Lorens Viguie
            - **Changement de mot de passe** : l'ancien est désormais exigé, et toutes les autres sessions sont fermées. Un jeton volé permettait de changer le mot de passe sans le connaître, et la victime ne pouvait pas reprendre la main — changer son mot de passe n'évinçait pas l'intrus - Lorens Viguie
            - **Aucune déconnexion n'existait** : route `/logout`, invalidation par jeton et par utilisateur, purge des sessions expirées (la map ne rétrécissait jamais). Le kill switch ferme maintenant aussi les sessions web, il ne fermait que les sessions Ducky - Lorens Viguie
            - `generateToken` journalisait l'échec de `rand.Read` puis retournait la valeur quand même — un tableau de zéros, donc un jeton de session parfaitement prévisible. L'erreur est remontée et la connexion refusée - Lorens Viguie
            - `SameSite=Strict` déclaré explicitement sur le cookie de session : la protection CSRF dépendait jusqu'ici du défaut du navigateur - Lorens Viguie
            - `rows.Err()` ajouté sur 12 lectures. Deux alimentent `CheckPermissionsAllDomains`, où le sens de l'erreur était le mauvais : une liste de domaines tronquée est **plus facile** à satisfaire, donc une coupure passagère élargissait l'accès - Lorens Viguie
            - Délais d'attente sur les serveurs HTTP web et API : `http.Serve` n'en pose aucun, une connexion lente immobilisait une goroutine sans limite - Lorens Viguie
            - **Nouvelle permission `read:log`** : les journaux étaient adossés à `read:get:user`, si bien qu'administrer un seul domaine donnait l'activité de tout le parc. Le droit est maintenant séparé dans les deux sens — auditer sans administrer, administrer sans lire les journaux des autres - Lorens Viguie
            - Suppression de `UpdateUserPermissionBooleanField`, sans appelant et sans garde sur `vaultaire_all` - Lorens Viguie

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

        - 🛑 **Kill switch — désactivation d'urgence d'un compte** *(TO-DO tâche 5)*
            - Nouvelle catégorie de trames **06** (06_01 à 06_06), documentée et validée dans `Tableau_Protocole_Reseau.md`. Catégorie séparée des GPO : celles-ci sont *tirées* par le client à son rythme, une révocation est *poussée* et ne peut pas attendre le cycle horaire - Lorens Viguie
            - Trois modes : `soft` (verrouille partout, réversible), `unlock`, `hard` (supprime le compte de l'annuaire **et** des machines, répertoire personnel compris) - Lorens Viguie
            - **Le verrouillage local est indispensable, y compris en `soft`** : le module PAM écrit le mot de passe dans le `/etc/shadow` de chaque machine visitée, donc une révocation limitée au serveur laisserait le compte compromis utilisable en local partout. Côté agent : `usermod -L` **et** `chage -E 1` — le premier seul laisse entrer par clé SSH - Lorens Viguie
            - **Les ordres sont durables**, pas des messages : écrits en base avec leur liste de machines cibles, poussés aux machines en ligne, rejoués à la reconnexion des autres. Sans cela, éteindre son poste suffisait à échapper à une révocation - Lorens Viguie
            - Point de coupure unique côté RBAC (`GetGroupIDsForUser`) : un compte révoqué n'a aucun groupe, donc aucune permission, sur tous les chemins d'un coup. Refus explicites ajoutés aux points d'authentification Ducky, SSH, LDAP, web et API — l'API compte, un compte révoqué garde ses clés SSH et sa signature resterait valide - Lorens Viguie
            - Nouvelle action RBAC `write:killswitch` (action spéciale, aucune colonne ajoutée à la matrice), vérifiée sur **tous** les domaines de la cible. Séparée de `write:delete:user` pour pouvoir confier l'urgence à une équipe d'astreinte sans lui donner la suppression au quotidien ; le mode `hard` exige les deux - Lorens Viguie
            - `delete -u` et le bouton de suppression web passent désormais par ce flux en mode `hard`. Auparavant la suppression retirait le compte de l'annuaire et laissait le compte local vivant sur chaque machine : **le compte survivait à sa propre suppression** - Lorens Viguie
            - Le compte `vaultaire` n'est pas révocable ; il reste le filet de secours pour lever une révocation déclenchée par erreur - Lorens Viguie
            - Interface : pas de confirmation pour `soft` (réversible, c'est un bouton d'urgence), saisie du nom du compte exigée pour `hard`. CLI : `vlt kill -u <user> [--unlock|--hard] [--reason ...]`, mode par défaut `soft` — une commande tapée dans l'urgence ne doit jamais détruire - Lorens Viguie

        - ⚙️ **GPO**
            - Les restrictions GPO ne sont plus stockées en JSON en dur mais en base de données (tables `gpo_restriction`, `gpo_field_rule`, `gpo_value_definition`), éditables via une page d'administration `/admin/gpo/restrictions` réservée au groupe `vaultaire` - Lorens Viguie
            - Modes par champ (liste / motif regex / libre) avec motif d'exclusion prioritaire, socle par défaut réinitialisable - Lorens Viguie
            - Lecture fail-closed : plus aucun repli sur des valeurs internes si la base ne répond pas - Lorens Viguie
            - Peuplement initial via `gpo_seed.sql` (embarqué, exécuté uniquement au premier démarrage) - Lorens Viguie
            - Correction des jeux de commandes sudo par défaut absents du menu déroulant, et de l'aperçu qui affichait toutes les valeurs custom au lieu de la sélection - Lorens Viguie
            - Systeme de Scope User machines avec des actions prédefinis et des regles de restrictions - Lorens Viguie
            - **Ordre d'application repensé en phases** *(TO-DO tâche 2)*. L'ancien ordre était faux : fichiers en 30, **après** les paquets (20) et les services (21). Un service démarrait donc sur la configuration par défaut de son paquet, puis la GPO déposait la vraie configuration sans rien relancer — la machine tournait avec une conf que personne n'avait choisie, jusqu'au prochain redémarrage - Lorens Viguie
            - Nouvelles phases : `10-19` fichiers, `20-29` sources (DNS, dépôts), `30-39` paquets, `40-59` configuration, `60-69` services, `70-79` ménage, `80+` utilisateur. Bornes constantes, donc un ajout ne demande jamais de renumérotation - Lorens Viguie
            - Conséquence traitée : déposer une configuration avant d'installer son paquet crée un conflit de *conffile*. `--force-confold` ajouté côté apt, sans quoi le comportement dépendrait de la distribution et de son mode interactif - Lorens Viguie
            - **Catalogue porté de 8 à 34 modules.** Nouveaux : `directory_manage`, `templated_file_deploy` (marqueurs `{{hostname}}` `{{fqdn}}` `{{username}}` `{{domain}}`), `file_acl`, `trusted_ca`, `dns_resolver`, `package_repository`, `boot_params`, `kernel_module_policy`, `ssh_known_hosts`, `pam_policy`, `local_account_policy`, `auditd_rule`, `selinux_mode`, `firewall_rule`, `ntp_config`, `log_policy`, `update_policy`, `system_env`, `resource_limits`, `file_retention`, `user_group_membership`, `user_shell`, `user_password_policy`, `user_ssh_client_config`, `user_git_config`, `user_resource_limits` - Lorens Viguie
            - **Garde-fous sur les modules capables de rendre une machine injoignable** : `pam_policy` n'écrit jamais dans `/etc/pam.d/` (uniquement des fichiers de *paramètres*) et refuse un verrouillage sans déverrouillage automatique ; `boot_params` valide la génération GRUB avant installation et restaure sinon ; `selinux_mode` refuse `enforcing` sur un système jamais réétiqueté ; `local_account_policy` exclut root et uid < 1000, et son mode par défaut liste sans modifier - Lorens Viguie
            - `file_retention` est le seul module qui détruit des données : motif sans séparateur de chemin, âge minimal d'un jour vérifié des deux côtés, liens symboliques jamais suivis, un seul niveau de récursion - Lorens Viguie
            - Trois nouveaux champs dynamiques éditables en base : modules noyau interdictibles, shells attribuables, groupes locaux attribuables. ⚠️ Cette dernière liste ne contient volontairement que des groupes de périphériques — `docker`, `lxd`, `disk`, `sudo` en sont absents, appartenir à `docker` revenant à être root - Lorens Viguie
            - `user_git_config` n'accepte qu'une liste fermée de clés : git permet de définir des commandes exécutées automatiquement (`core.pager`, alias, filtres), un champ libre donnerait une exécution de code arbitraire à chaque commande git - Lorens Viguie

        - 🖥️ **Interface web**
            - **Page GPO repensée** *(TO-DO tâche 3)* : quatre onglets (Modules / Ajouter / Groupes / Réglages), tableau compact avec édition dépliable, catalogue filtrable dont un seul formulaire est monté à la fois. Motivation : rendre 34 formulaires dans une même page la rendait impraticable - Lorens Viguie
            - Colonne « Cible » dérivée de `ModuleStateKey` et non recalculée : deux modules partageant la même clé d'état se voient donc immédiatement - Lorens Viguie
            - **Page permissions repensée** : les 30+ clés RBAC sont présentées en **matrice objet × verbe** au lieu d'une liste de 37 lignes. Un éditeur unique, alimenté par la case cliquée, remplace les deux formulaires par ligne - Lorens Viguie
            - Retrait d'un domaine par bouton, avec vérification serveur que le domaine est réellement accordé. Auparavant il fallait ressaisir le nom à la main : une faute de frappe affichait « domaine retiré » sans que rien ne change - Lorens Viguie
            - `web_admin` redevient une simple porte d'entrée : les droits RBAC sont ensuite vérifiés **sur les domaines de l'entité visée**, comme en CLI. L'interface exigeait jusqu'ici un droit global pour toute action, si bien qu'un administrateur délégué pouvait tout faire en ligne de commande et rien en web - Lorens Viguie
            - Le découpage en onglets et les filtres sont du JavaScript d'agrément : sans lui, toutes les sections s'affichent à la suite. Aucun contrôle de sécurité n'en dépend - Lorens Viguie
            - Message clair au rejet d'une clé publique déjà enregistrée : l'erreur MySQL brute remontait telle quelle et taisait le nom du compte qui la détient. Code HTTP 409 au lieu de 500 - Lorens Viguie

        - 📖 **Documentation**
            - Mise à jour du `MAN.md` (modèle déclaratif GPO, restrictions, définitions, lecture fail-closed) et de `DataBase_Struct.md` (nouvelles tables GPO) - Lorens Viguie
            - Nouveau `GPO.md` : fonctionnement complet, catalogue des 34 modules avec leur ordre, et procédure pour ajouter un module, un champ ou un type de contenu - Lorens Viguie
            - Nouveau `Permissions.md` : modèle RBAC, actions à portée globale, et ce qu'il faut toucher pour ajouter un objet - Lorens Viguie
            - Nouveau `Audit_Permissions.md` : constats restant ouverts, avec la décision associée à chacun - Lorens Viguie
            - Nouveau `migrations/rbac_groupes_stricts.md` : requêtes de diagnostic à lancer **avant** la bascule du RBAC en appartenance stricte - Lorens Viguie
            - `Tableau_Protocole_Reseau.md` complété : transport GPO (catégorie 05) et révocation (catégorie 06) - Lorens Viguie
        - - ### 🐷 **Alpha 2.1.0** *refactorisation* - *...*
---



