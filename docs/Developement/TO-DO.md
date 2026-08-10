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

23.[SECU] [AUTH] - Aucune limitation de debit sur l'authentification
            Ni le portail web, ni LDAP, ni l'API n'imposent de delai ou de blocage apres
            des echecs repetes. Le bruteforce en ligne n'a rien en face : un mot de passe
            faible tombe en quelques heures, et rien dans les journaux ne distingue une
            campagne d'essais d'un utilisateur maladroit.
            A prevoir : compteur par compte ET par adresse source (un seul des deux se
            contourne), delai croissant plutot que blocage sec — un blocage sec permet a
            un tiers de verrouiller un compte a volonte.

24.[TEST] [CI] - La CI ne lance aucun `go test`, et quatre modules n'ont aucun test
            Le workflow dev.yaml enchaine gofmt, go vet, golangci-lint, gosec, semgrep,
            govulncheck, trivy et hadolint — mais pas un seul test. Les 287 fonctions de
            test du depot ne sont donc jamais executees automatiquement : une regression
            passe la CI au vert.
            Sans aucun test : api_client_package, vaultaire_cli, vaultaire_ctl,
            vaultaire_proxy. Les deux premiers portent la signature des requetes API.
            A faire : job `go test ./...` par module, avec -race sur le serveur.

25.[BUILD] - auto-compil.sh porte un chemin absolu en dur
            ROOT_DIR="/mnt/c/Users/loren/Documents/git/vaultaire-core". Personne d'autre
            ne peut compiler sans editer le script, et une CI ne le peut pas du tout.
            A faire : deduire la racine du script lui-meme
            (ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"), en laissant une variable
            d'environnement la surcharger.

26.[FAIT-IA] [DUCKY] - Le protocole existe en double et les deux copies ont diverge
            src/vaultaire_client/duckynetworkClient/ et
            src/ducky-network-sdk-service/duckynetwork/ portent les memes sept
            repertoires — ducky_tool, key_encode_decode, keymanagement, sendmessage,
            serveurauth, trames_manager, userauth — et leur contenu differe.
            Un correctif de protocole doit donc etre ecrit deux fois, et le sera un jour
            une seule. A faire : un module partage dont les deux dependent.


