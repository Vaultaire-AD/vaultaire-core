Une fois une action faite est validé definitevement c'est a un humain de déplacer la taches dans le dossier DO et ranger le changement dans la bonne version et d'ajouter les changemnt dans Version_History.md


1.[FAIT-H] [DOC]mettre a jour la Documentation pour séparé entierement les GPO voir trames struct (si il a des changement a faire dans le protcole dabord mettre ajour la documentation et demander ensuite validation)

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

22.[EN COURS] [SELINUX] Politique pour les clients -> voir docs/exploitation/selinux.md
            Le module NSS ne faisait aucun appel systeme ; il lit desormais un fichier
            et ouvre un socket. Sous sshd_t, SELinux refuse — d'ou « Invalid user »
            sans aucun journal Vaultaire, alors que getent lance a la main REUSSIT.
            deployments/selinux/ : collect.sh, vaultaire.te, vaultaire.fc, install.sh
            Reste a faire : un domaine dedie pour l'agent (aujourd'hui unconfined_service_t).

