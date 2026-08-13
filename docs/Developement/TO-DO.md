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

      
4.[PATCH] [GPO] - La derive ne voit que les fichiers
            Le scan de conformite existe et fonctionne : ScanScope compare chaque fichier
            depose a son SHA-256 et a son mode, toutes les heures, avant le cycle. Un seul
            entonnoir d'ecriture dans le paquet, donc tout module qui ecrit un fichier est
            couvert automatiquement. Voir DO/2.1/2.1.md.

            Deux angles morts subsistent.

            a) Les fichiers qui doivent etre ABSENTS. 25 os.Remove dans les appliqueurs :
               des modules dont l'effet est « ce fichier ne doit pas exister ». Rien ne
               l'inventorie, donc le recreer ne produit aucun ecart.
               A faire : recordAbsent a cote de recordWrite, et le scan signale la
               reapparition. Mecanique, petit.

            b) Les effets NON-fichier. 55 appels de commandes dans les appliqueurs :
               systemctl x25, nft x7, chage x6, usermod/sysctl x3, gpasswd, setsebool.
               Un service reactive, une table nftables videe, un compte remis dans sudo :
               invisible, et la machine est declaree conforme.
               A faire : chaque module declare une fonction de VERIFICATION a cote de sa
               fonction d'application. Module par module, en commencant par ceux qui
               portent un privilege — sshd et firewalld sous systemctl, appartenance a
               sudo/wheel, regles nftables. On ne devine pas l'etat d'un service depuis
               un fichier.
5.[WEB-COMMAND] - BUG sur l'execution des commandse via la CLI web aucun logs present lord de l'execution des commandes il y a un pb
8.[LDAP] - un mode synchro sur un anuaire existant qui permet de beneficier des fonctionalite de vaultaire mais en le lians a un AD deja existant 

9.[Ducky] [PROXY] - Decouverte de service et proxies
            Les points 9 et 10 d'origine sont UN SEUL sujet : un client ne peut pas se voir
            offrir une liste de serveurs tant qu'il ne sait pas leur faire confiance, et un
            proxy ne sert a rien tant que personne ne sait qu'il existe.

            SPECIFICATION COMPLETE dans « how it work/Protocole_Ducky.md », section
            « Decouverte de service et proxies (categorie 04) ». Trois arbitrages y sont
            rendus :

              - 02_17/02_18 SUPPRIMEES : doublon jamais implemente de 04_03/04_04.
                La decouverte reste en 04, qui porte deja ce nom ;
              - le proxy est un RELAIS TCP, il ne dechiffre rien. C'est le point 29 qui
                tranche : le mot de passe transite desormais dans le tunnel, un proxy qui
                terminerait la session serait un point de collecte des mots de passe du parc ;
              - les empreintes de core s'APPRENNENT par une session deja de confiance.
                core_key_fingerprint devient une liste. Limite assumee et ecrite : tout core
                de confiance peut ajouter de la confiance.

            Etat reel du code, qui surprend : 04_01, 04_03, 04_05 et 04_07 sont DEJA
            implementees cote serveur. Personne ne les emet, et le catalogue de types ne les
            accorde a personne — pas meme 04 au proxy. La table proxy_metrics n'a jamais recu
            une ligne.

            Trois manques concrets : cluster_nodes n'a pas de colonne PORT ; rien ne persiste
            une liste apprise ; le SDK lit « servers » en YAML quand vaultaire_client le lit
            en JSON, pour la meme structure.

            Decoupage en 7 lots dans la spec. Les lots 1 (schema + trame enrichie + catalogue)
            et 3 (le proxy s'enregistre) sont independants et peuvent demarrer les premiers.
            Le lot 0 (liste d'empreintes) conditionne le lot 2.

            Reste ouvert, a trancher : que fait un proxy dont tous les cores sont
            injoignables ? La spec propose de refuser franchement plutot que de mettre en
            attente.
10.[DUCKY-Client] - Comment gère la liste des serveur joignable pour les clients basics (client qui ne sont pas des services) : aujourd'jui un client n'a que un seul serveur core joingable dans son fichier de conf l'idée c'est que a chaque connection apres avoir été authentifié pour tous les client et pour les serveur tous les X temps parametrables le client demande via sa session actuelle la liste des serveur qu'il peut joindre (priorité sur les proxys qui sont dans son groupe - puis les proxy - puis les core ou alors reflechir a un autre moyen de crée cette liste on imagnine un contexte d'entreprise ou des employé d'un bureau ne peuvent pas joindre tous les proxy et n'ont acces a aucun core - peut etre pouvoir choisr si un core est exposé ou non au client basic et peut etre aussi pouvoir liées des cores a des groupes - dans ce cas peut etre aussi pouvoir liée des clé d'enrollement a des groupes et donc pouvoir faire des regles d'afinité)
11.[AUTH-DUCKY-SSH] - Comment son stocké transmit les mots de passe via l'auth ssh ducky 03
12.[LEXIQUE] - faire un lexique des definition de vulaitare client service basic etc etc

22.[EN COURS] [SELINUX] Politique pour les clients -> voir docs/exploitation/selinux.md
            Le module NSS ne faisait aucun appel systeme ; il lit desormais un fichier
            et ouvre un socket. Sous sshd_t, SELinux refuse — d'ou « Invalid user »
            sans aucun journal Vaultaire, alors que getent lance a la main REUSSIT.
            deployments/selinux/ : collect.sh, vaultaire.te, vaultaire.fc, install.sh
            Reste a faire : un domaine dedie pour l'agent (aujourd'hui unconfined_service_t).

31.[TEST] [ACTION] - Les tests d'ACTION restent tributaires de la base
            Suite du point 30, dont les PORTEES ont ete traitees (voir DO/2.1/2.1.md).

            Restent les quelques tests qui appellent une action en attendant un SUCCES et
            dont l'ecriture n'est pas encore substituee — hors permissions, machines et
            certificats, qui le sont. Aucun n'est connu comme cassant aujourd'hui : le
            balayage n'a trouve que des tests de REFUS, qui s'arretent a la validation.

            A faire : etendre baseSimulee au coup par coup, quand un nouveau test de
            message en aura besoin. Ne PAS poser une variable sur les 76 points d'entree
            du paquet — le critere reste ce qu'un test traverse reellement.

32.[GPO] [WEB] - La conformite du parc n'existe qu'en ligne de commande
            Suite du point 7, dont la VUE a ete traitee (voir DO/2.1/2.1.md).

            L'action gpo.list_compliance est au registre avec sa cle RBAC read:get:gpo et
            son filtre de perimetre ; gpo.get_compliance porte le detail d'une machine.
            Il n'y a donc aucun metier a ecrire — seulement un gabarit et un handler.

            A faire : une page qui montre le resume du parc, le tableau trie comme en CLI,
            et le detail d'une machine au clic. Le tri et les etats viennent de
            db_gpo.TrierConformite et ComplianceRow.Fraicheur : ne pas les recopier dans
            le gabarit, sans quoi la CLI et le web finiront par ne plus dire la meme chose.

33.[GPO] - Le scope UTILISATEUR n'est jamais scanne
            scanMachineDrift n'existe que pour le scope machine. RunUserCycle applique les
            GPO user a l'ouverture de session mais ne verifie jamais l'etat laisse par la
            session precedente.

            Or les fichiers de scope user vivent dans le HOME de l'utilisateur — le seul
            endroit ou le proprietaire edite librement sans etre root. Le scope ou la
            derive est la plus probable est celui qui n'est pas surveille.

            A faire : scanUserDrift dans RunUserCycle, symetrique de l'existant, a
            l'ouverture de session. La correction reste DIFFEREE au cycle suivant, comme
            cote machine : reappliquer dans le home pendant que l'utilisateur travaille
            ecraserait ce qu'il vient d'editer.

34.[GPO] - Le mode enforce/audit est code en dur dans le binaire
            gpo.CurrentDriftMode porte le commentaire « destinee a etre relue depuis la
            configuration de l'agent ». Personne ne le fait : le mode audit est
            inatteignable en production, c'est du code mort.

            Et c'est une variable du BINAIRE, alors que la decision devrait venir du core :
            un parc peut vouloir un groupe « laboratoire » en audit et le reste en enforce,
            sans deux binaires.

            A faire : porter le mode dans le manifeste GPO, comme un parametre de
            politique. Le lire depuis client_software.yaml serait moins cher mais remettrait
            la decision sur la machine — celle qui derive.
