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
    - ### 🐷 **Alpha 2.1.0** *refactorisation* - *...*

        - 🧱 **Nettoyage du paquet `core/database`** *(TO-DO_Database §2.1 à §2.4)*
            - **79 fichiers → 30**, dont la racine qui passe de 52 fichiers à 12. Le paquet tenait 75 lignes par fichier en moyenne, une fonction par fichier : les fonctions liées vivaient chacune dans son coin, et 26 noms de fichiers sur 57 ne correspondaient plus à leur contenu - Lorens Viguie
            - Regroupement par sujet : `users.go`, `groups.go`, `clients.go`, `sessions.go`, `domains.go`, `permissions.go`, `ldap_reads.go`, `schema.go`, `sanitize.go`, `db.go`, `resolve.go`, `protected.go`. `db_permission` passe de 13 fichiers à 4 - Lorens Viguie
            - **Aucun appelant touché** : le regroupement ne change pas de paquet, et l'empreinte de la surface exportée (331 entrées : nom, signature, types, variables) a été comparée avant/après à chaque étape — identique - Lorens Viguie
            - Noms de paquets alignés sur la convention Go : `db_permission` → `dbpermission`, `db_revocation` → `dbrevocation`, `db_authpolicy` → `dbauthpolicy`. Les alias divergents pour un même paquet (`dbperm` et `db_permission`, `dbcert` et `dbcertificates`) sont unifiés - Lorens Viguie
            - **Requêtes de résolution d'identifiant dédupliquées** : les mêmes `SELECT id_group FROM groups WHERE group_name = ?` et consorts étaient recopiés dans une vingtaine de fonctions, et ne se comportaient pas tous pareil — certains assainissaient leur entrée, d'autres non. Nouveau `resolve.go` avec cinq résolveurs `Lookup*` - Lorens Viguie
            - Les résolveurs rendent `found bool` plutôt que de formuler l'absence : chaque appelant conserve **au caractère près** le message que voit l'administrateur. Ils prennent une interface `RowQuerier` que `*sql.DB` et `*sql.Tx` satisfont tous deux, pour qu'une résolution à l'intérieur d'une transaction ne lise jamais en dehors - Lorens Viguie
            - L'assainissement est fait dans le résolveur, au plus près de la base : `Command_GET_UserPermissionID` et `EnsureSuperadminActions` y gagnent une vérification qu'elles n'avaient pas - Lorens Viguie

        - 🧩 **Clients service : catalogue, enrôlement autonome et restriction des trames**
            - **Deux familles de clients sont désormais distinguées.** Un client BASIC est un agent : il représente une machine, il est créé d'abord sur le core qui génère sa paire de clés, puis installé. Un client SERVICE est une extension qui ajoute une fonction au cluster : il s'enrôle seul et génère sa propre paire - Lorens Viguie
            - Nouveau paquet `core/clienttype` : le catalogue des types de programmes vit dans le CODE et non en base. Un type détermine quelles trames un programme peut émettre — c'est une frontière de privilège, elle ne doit pas être éditable depuis une interface d'administration - Lorens Viguie
            - **Le core ne figure pas au catalogue et ne peut pas y figurer** : c'est lui qui juge la légitimité des trames qu'il reçoit en fonction du type de leur émetteur, il ne peut pas se juger lui-même. Il n'est d'ailleurs jamais enregistré comme client - Lorens Viguie
            - **Un seul type d'agent.** Le drapeau `isServeur` ne crée pas un second type : c'est le même binaire, qui émet les mêmes trames et ouvre seulement un tunnel machine en plus. Ce n'est pas une frontière de privilège - Lorens Viguie
            - Les listes de trames sont relevées sur ce que les programmes émettent **réellement**, pas sur la table du protocole qui décrit aussi des trames restées à l'état d'intention : l'agent émet `02_12` et jamais `02_13`, le proxy n'émet pas encore `04_05` - Lorens Viguie
            - **`create -c` ne demande plus de type** : ce chemin ne peut produire qu'un client basic. Le type était une chaîne libre saisie à la main, que rien ne validait et dont rien ne dépendait — le formulaire web proposait « client » en simple exemple. Champ retiré de la commande, du handler web et du gabarit - Lorens Viguie
            - **Les droits portent sur la SOUS-TRAME, pas sur la catégorie.** L'interface web utilise 02 pour s'authentifier mais n'a rien à faire de `02_11`, `02_12` et `02_13`, qui sont l'inventaire matériel d'une machine — elle n'a ni processeur ni mémoire à déclarer. Un contrôle par catégorie lui ouvrirait les trois - Lorens Viguie
            - La liste des trames est exhaustive et **fail-closed** : une sous-trame ajoutée au protocole n'est émissible par personne tant qu'elle n'est pas déclarée. Un oubli produit un refus visible, jamais une ouverture silencieuse - Lorens Viguie
            - Contrôle posé dans `Split_Action`, immédiatement après la vérification d'identité machine qui existait déjà : un point unique couvre toutes les catégories, présentes et futures - Lorens Viguie
            - `BoundClientType` est figé à la poignée de main comme `BoundClientSoftwareID`, et hérite de sa preuve : la réponse `01_02` est chiffrée avec la clé publique de cet identifiant, donc qui ment sur son identifiant ne déchiffre rien - Lorens Viguie
            - ⚠️ **Migration requise avant bascule.** `logiciel_type` était un `VARCHAR(255)` libre, sans validation. Toute valeur sans équivalent au catalogue empêchera la machine de se connecter : `SELECT logiciel_type, COUNT(*) FROM id_logiciels GROUP BY logiciel_type` avant la mise en service - Lorens Viguie

        - 🔑 **Enrôlement autonome des clients service (trames 01_03 à 01_06)**
            - Le service génère sa paire RSA localement et présente une clé d'enrôlement pour faire enregistrer sa clé PUBLIQUE. **Sa clé privée ne quitte jamais son hôte**, contrairement à celle d'un agent que le core génère et livre avec sa configuration - Lorens Viguie
            - Les clés portent **un type, une expiration et un quota**. `vlt enroll create --type vaultaire_web --uses 1 --expires 30m`. Par défaut : une utilisation, trente minutes - Lorens Viguie
            - **LE TYPE VIENT DE LA CLÉ, jamais du client.** S'il l'annonçait, il suffirait de s'enrôler pour se déclarer `vaultaire_web` et obtenir avec lui le droit d'agir au nom de n'importe quel utilisateur de l'annuaire - Lorens Viguie
            - Émettre une clé pour un type portant l'assertion d'identité est réservé au groupe `vaultaire` : ce pouvoir ne se délègue pas par une clé RBAC ordinaire - Lorens Viguie
            - **Seul le condensat de la clé est stocké**, comme un mot de passe. Le secret est affiché une fois et n'est jamais réécrit : une fuite de la base ne rend aucune clé utilisable - Lorens Viguie
            - Les cinq motifs de refus (inconnue, expirée, épuisée, révoquée, type retiré) sont **distincts dans les journaux et indistincts pour le client**. Les détailler ferait du point d'enrôlement un oracle confirmant qu'une clé a existé - Lorens Viguie
            - La réponse `01_04` est chiffrée avec la clé publique qui vient d'être soumise : **la preuve de possession est acquise sans défi explicite**, exactement comme en `01_02` - Lorens Viguie
            - Le décompte précède la création du client : une panne entre les deux perd un jeton, elle ne crée jamais de client non autorisé. `Release` rattrape l'échec de création - Lorens Viguie
            - Table `service_enrollment_use` : sans elle, impossible de répondre à « quels services sont entrés par cette clé ? » le jour où l'on découvre qu'elle a fuité - Lorens Viguie
            - `create -c` refuse désormais un type service : il s'enrôle, il ne se crée pas sur le core - Lorens Viguie

        - 🌐 **Cluster : enregistrement des services (trames 04_09 à 04_14)**
            - Enregistrement, battement de cœur et sortie propre d'un service dans `cluster_nodes`. Distinct de `04_01`, qui déclare une machine : un service déclare une fonction — type, version, point d'accès - Lorens Viguie
            - Les séparer garde la restriction par sous-trame utile : un proxy émet `04_01` et pas `04_09`, l'interface web l'inverse - Lorens Viguie
            - Le type vient de la SESSION, jamais du contenu de la trame. Les capacités déclarées sont de l'INVENTAIRE et n'accordent aucun droit : ce qu'un service peut émettre est décidé par son type au catalogue - Lorens Viguie
            - Le passage hors ligne est écrit par un balayage serveur plutôt que déduit à la lecture — une vue calculée à la volée ne garderait aucune trace du moment où le service a cessé de répondre - Lorens Viguie
            - La sortie propre `04_14` évite qu'un arrêt planifié soit indistinguable d'une panne pendant toute la fenêtre de battement - Lorens Viguie

        - 📁 **Découpage de `core/database` en sous-paquets, une déclaration par fichier**
            - Le regroupement thématique précédent produisait des fichiers de 500 lignes, aussi peu praticables que les 52 fichiers d'une fonction qu'ils remplaçaient : on troquait « où est cette fonction ? » contre « où est-elle dans ce fichier ? » - Lorens Viguie
            - **266 fichiers, 34 lignes en moyenne.** Le nom de chaque fichier est dérivé mécaniquement du nom de sa déclaration (CamelCase → minuscules soulignées, préfixe `Command_` retiré) : un nom de fichier ne peut donc plus mentir sur son contenu, ce qui était le défaut principal de l'organisation d'origine - Lorens Viguie
            - **En Go un dossier est un paquet** : des dossiers signifiaient de vrais sous-paquets. 637 références qualifiées réécrites dans 155 fichiers, `database.Command_ADD_UserToGroup` devenant `dbgroups.Command_ADD_UserToGroup`. Cohérent avec `db_gpo`, `db_permission` et `db_revocation`, qui étaient déjà des sous-paquets - Lorens Viguie
            - Douze sous-paquets : `dbusers`, `dbgroups`, `dbclients`, `dbsessions`, `dbdomains`, `dbldap`, `dbschema`, `dbpermission`, `dbgpo`, `dbauthpolicy`, `dbrevocation`, `dbcertificates` - Lorens Viguie
            - **Le socle `core/database` ne contient plus une seule requête métier** : connexion, filtrage des entrées, résolveurs d'identifiants, gardes d'immuabilité. Il n'importe aucun sous-paquet, ce qui garantit l'absence de cycle - Lorens Viguie
            - Exception assumée : `IsUserInGroup` reste dans le socle bien que ce soit une lecture d'appartenance, parce que `IsSuperadmin` en a besoin et que `dbgroups` importe déjà les gardes. La déplacer aurait obligé à dupliquer la requête - Lorens Viguie
            - `permissions.go` rejoint `dbpermission` (deux paquets pour le même sujet n'avaient pas de sens), `db-user` disparaît dans `dbusers` (une clé SSH est un attribut de compte), `db-certificates` devient `db_certificates` - Lorens Viguie
            - **Piège du découpage : les commentaires d'en-tête de fichier**, ceux qui précèdent la première déclaration sans lui être attachés, sont perdus — et ce sont justement ceux qui portent le raisonnement d'ensemble. Vérifié par comptage (1 173 lignes avant) et restaurés en `doc.go` par paquet, ce qui est leur place correcte en Go - Lorens Viguie
            - ⚠️ Les 155 fichiers appelants ne sont pas prouvés par le compilateur : vérification au parseur (547 fichiers, 0 échec) et contrôle statique confirmant que les 637 références désignent un symbole réellement exporté. **Recompiler avant de pousser** - Lorens Viguie

        - 🐛 **Correction : retirer une permission utilisateur d'un groupe n'a jamais fonctionné**
            - `Command_Remove_UserPermissionFromGroup` résolvait le nom de la permission dans `client_permission`, la table des permissions **client**, alors qu'elle retire une permission **utilisateur** — deux familles numérotées séparément - Lorens Viguie
            - Elle interrogeait ensuite puis supprimait dans `group_permission_user`, **table qui n'existe pas** : le schéma déclare `group_user_permission`. MySQL rendait « table inconnue » dès le `COUNT` - Lorens Viguie
            - Les deux chemins offerts échouaient : `vlt remove -g <groupe> -pu <permission>` et le bouton de la page groupe. En web l'appelant ne teste que `== nil`, donc le clic ne produisait **aucun message** et la permission restait affichée sans explication - Lorens Viguie
            - **Portée réelle** : un droit accordé à un groupe ne pouvait plus lui être repris. Le seul contournement était de supprimer la permission entière, donc de la retirer à *tous* les groupes. Une réduction de privilèges était impossible sans en casser d'autres - Lorens Viguie
            - Trouvé en redirigeant les requêtes recopiées. Même famille que `DeleteGroup`, morte et cassée pour la même raison : du code visant des tables inexistantes, donc jamais exécuté sur une vraie base - Lorens Viguie

---



