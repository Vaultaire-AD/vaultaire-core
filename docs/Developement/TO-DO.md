CONVENTION — une tâche traitée QUITTE ce fichier. On ne la marque pas, on la supprime.

Un fichier de reste-à-faire ne doit contenir que ce qui reste à faire. Des entrées
« [FAIT] » qui s'accumulent le transforment en second historique, moins complet que le
vrai, et on finit par ne plus savoir ce qui est ouvert d'un coup d'œil.

Les trois gestes, dans le même passage que le code :

  1. l'entrée est SUPPRIMÉE d'ici et écrite dans DO/<version en cours>/<version>.md, avec
     le détail de ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité ;
  2. si une partie n'a pas été traitée, elle revient ici sous un numéro NEUF et sa propre
     description — jamais en gardant l'ancien numéro, qui se lirait comme une tâche
     entière non commencée ;
  3. les changements sont consignés dans docs/Version/<majeure>/<mineure>.md, en haut.

Le fichier DO est l'archive, l'historique de version est le compte rendu, celui-ci est
la liste de courses.

2.[DEPLACE] [GPO] Ajout de nouveaux Module -> voir DO/2.0/2.1.md
            Reste ouvert : mount_hardening (ecarte volontairement) et le volet user de
            ssh_known_hosts (~/.ssh/known_hosts), implemente en scope machine seul.
.3[DUCKY] [SERVICE] il faut crée le systeme qui permet au client service de push leur clé public au server tous en garantissant la confidentialité du token
      
4.[PATCH] [GPO] - Détection de dérive (drift detection) -> voir DO/2.1/2.1.md
            Rien dans le catalogue ne vérifie qu'un module resté "appliqué avec succès" (version à jour dans applied_policies.json) correspond encore à l'état réel du système — un admin qui modifie manuellement sshd_config.d/99-vaultaire-gpo.conf en SSH direct fausserait l'état sans que rien ne le détecte. Il faut un scan périodique de conformité, pas seulement une application ponctuelle.
7.[PATCH] [GPO] - Reporting de conformité centralisé -> voir DO/2.1/2.1.md
            Vue d'ensemble côté serveur : quelle version de policy chaque machine a effectivement appliquée avec succès, quelles machines sont en échec/en retard — sans ça, tu n'as aucune visibilité sur l'état réel du parc.

8.[LDAP] - un mode synchro sur un anuaire existant qui permet de beneficier des fonctionalite de vaultaire mais en le lians a un AD deja existant 

9.[SSH] - il y a un bug sur la gestion des clé ssh authorizek sur les compte de domain il faut mettre en place une logique comme pour le mot de passe les clé sont overwrite a chaque nouvelle connection avec les nouvelles pour eviter que des vielle clé ne reste 

13.[COMMAND] - « aucune réponse du serveur » apres un create : NON REPRODUIT
            Reste de l'ancien point 12, dont tout le reste est traite (voir DO/2.1/2.1.md).
            Trois causes voisines ont ete corrigees — troncature a 1024 octets dans
            l'invite interactive, reponse vide affichee comme une ligne blanche, message
            de create -p muet sur la suite a donner — mais AUCUNE ne reproduit exactement
            « la creation aboutit, le serveur ne repond pas ».

            Le client signale desormais explicitement une reponse vide au lieu d'afficher
            une ligne blanche : si le symptome persiste, le message le dira.

            Pour trancher il faut : la commande EXACTE tapee, le mode (argument ou invite
            interactive), et les lignes du journal serveur au meme instant.

15.[DOC] - dans le package action ecrire une doc sur comment cela marche et comment rajouter une action proprement 

22.[EN COURS] [SELINUX] Politique pour les clients -> voir docs/exploitation/selinux.md
            Le module NSS ne faisait aucun appel systeme ; il lit desormais un fichier
            et ouvre un socket. Sous sshd_t, SELinux refuse — d'ou « Invalid user »
            sans aucun journal Vaultaire, alors que getent lance a la main REUSSIT.
            deployments/selinux/ : collect.sh, vaultaire.te, vaultaire.fc, install.sh
            Reste a faire : un domaine dedie pour l'agent (aujourd'hui unconfined_service_t).

30.[TEST] [ACTION] - Des tests de core/action exigent une base vivante
            Ils appellent une action directement pour verifier son MESSAGE, et l'action
            ecrit en base. Sans base, database.GetDatabase() rend nil et l'appel PANIQUE —
            or un panic ne fait pas echouer ce seul test, il fait tomber le BINAIRE de test
            du paquet : les dizaines d'autres controles, matrice RBAC comprise, ne rendent
            plus rien.

            Quatre acces ont ete isoles derriere des variables substituables (suppression
            de machine, creation et mise a jour des permissions). Restent ceux qui evaluent
            une PORTEE : elle resout les domaines d'une permission en base, et cette
            resolution n'est pas encore substituable —
            TestPorteeDesPermissionsNestPasGlobalePourLaSuppression en particulier.

            A faire : rendre le resolveur de portee injectable, comme l'ont ete les autres
            acces, pour que le paquet soit testable sans conteneur.
