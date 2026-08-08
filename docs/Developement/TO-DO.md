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

12.[DEPLACE] [LDAP] Remplacer les encodeurs BER ecrits a la main par go-asn1-ber
            -> voir DO/2.1/2.1.md

21.[EN COURS] [PAM/NSS/AGENT/SDK] Audit complet -> voir Audit_Client_SDK_PAM.md
            Points 1, 2 et 3 CORRIGES (socket PAM, UID partage, useradd).
            Deploiement sequence obligatoire : docs/migrations/pam_socket_et_uid.md
            20 points releves, 2 critiques : socket d'authentification en /tmp mode 0666
            (elevation locale vers root), et UID 5001 partage par TOUS les utilisateurs
            du domaine (aucune separation entre comptes sur une machine geree).
            Les points 1, 2 et 3 sont lies : corriger l'un sans les autres degrade.
