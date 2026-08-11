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
10.[LOG] - sur l'ajout d'une clé public sur un user il  manque le username qui subit l'ajout / lors de la suppresion d'un certificat il manque le nom du certificat 
11.[MAN] - il manque des commandes vlt dans le man deja les commandes pour les certificats
22.[EN COURS] [SELINUX] Politique pour les clients -> voir docs/exploitation/selinux.md
            Le module NSS ne faisait aucun appel systeme ; il lit desormais un fichier
            et ouvre un socket. Sous sshd_t, SELinux refuse — d'ou « Invalid user »
            sans aucun journal Vaultaire, alors que getent lance a la main REUSSIT.
            deployments/selinux/ : collect.sh, vaultaire.te, vaultaire.fc, install.sh
            Reste a faire : un domaine dedie pour l'agent (aujourd'hui unconfined_service_t).

29.[SECU] [AUTH] - Les mots de passe sont haches en SHA-256 SIMPLE
            core/global/security/password.go : un seul tour de sha256.Sum256 sur sel+mot de
            passe. Ni bcrypt, ni scrypt, ni argon2.

            Une limitation de debit (point 23) ne protege que l'attaque EN LIGNE. Sur une
            base volee, un GPU essaie des milliards de candidats par seconde : un mot de
            passe faible tombe en secondes, et aucune limite cote serveur n'y change quoi
            que ce soit. C'est le risque DOMINANT des deux.

            La comparaison finale « newHashHex == hashHex » n'est pas non plus a temps
            constant — marginal sur un hachage compare a travers le reseau, mais gratuit a
            corriger avec subtle.ConstantTimeCompare.

            A faire : argon2id (ou bcrypt), avec reencodage TRANSPARENT a la prochaine
            connexion reussie — la seule migration possible, puisqu'on ne peut pas
            recalculer une empreinte forte a partir d'une faible. Prevoir une colonne qui
            porte l'algorithme, sans quoi on ne saura pas distinguer les deux formats.

            Touche les quatre chemins d'authentification : web, LDAP, Ducky, et la creation
            comme le changement de mot de passe.
