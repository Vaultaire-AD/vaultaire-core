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

      
41.[GPO] - Verification des effets non-fichier : les 27 modules restants
            Suite des points 4 et 37. Neuf modules declarent maintenant une
            attente (voir DO/2.1/2.1.md) : cinq dont la derive donne un DROIT,
            quatre dont la derive coute de la COHERENCE.

            Le socle n'a pas bouge et n'a pas besoin de bouger : recordCheck a
            cote de l'appliqueur, registre de verificateurs, deux types d'ecart
            (system_state, unverifiable), et le scan les parcourt. Les garde-fous
            lisent desormais les constantes DANS les sources, donc ils resteront
            justes a trente-six verificateurs.

            A faire, module par module : un recordCheck dans l'appliqueur, un
            verificateur enregistre, un test de son ANALYSE (pas de la commande —
            la sortie depend de la machine).

            Candidats restants, par ordre d'interet :
              - ntp_config : « timedatectl show -p NTPSynchronized » dit si
                l'horloge est reellement synchronisee, ce que le fichier ne dit
                pas ;
              - user_env / system_env : une variable exportee ailleurs masque
                celle de la GPO sans toucher au fichier ;
              - resource_limits / user_resource_limits : « ulimit -a » dans un
                shell de connexion, mais la valeur depend de la session, donc le
                constat ne vaut pas pour l'utilisateur connecte ;
              - auditd_rule : « auditctl -l » — les regles chargees, pas le
                fichier.

            NE PAS les ecrire toutes d'affilee. Une verification approximative est
            PIRE qu'aucune : elle declare conforme ce qui ne l'est pas, et personne
            ne va plus regarder.

            Trois refus a NE PAS defaire sans traiter leur cause :
              - la VERSION d'un paquet n'est pas verifiee (formats rpm/dpkg
                incomparables de facon fiable) ;
              - une ACL RECURSIVE ne declare aucune attente (getfacl ne constate
                que le chemin de tete) ;
              - boot_params et kernel_module_policy ne sont pas verifiables tant
                que l'etat ne sait pas porter « en attente de redemarrage » : les
                constater signalerait une derive permanente sur toute machine qui
                n'a pas encore redemarre.

            Reste ouvert aussi : « expire » de local_account_policy n'est pas
            verifie. chage -E 1 fixe une date passee, et la relire supposerait de
            comparer des dates dans une sortie localisee. Mieux vaut ne rien
            affirmer sur cette facette que de l'affirmer de travers.


43.[DUCKY] [CLUSTER] - Aucune limite de debit sur 04_05 (metriques)
            Un proxy peut emettre autant de trames 04_05 qu'il veut, et chacune
            insere une ligne dans proxy_metrics. Ce n'est plus une usurpation
            depuis le correctif de propriete — les lignes portent son nom — mais
            c'est une saturation de table par un client authentifie.

            La table n'a aucune purge non plus : elle croit indefiniment meme en
            fonctionnement normal.

            A faire, dans cet ordre d'importance :
              - une purge periodique, sur le modele de PurgeDepartedServices
                (une retention en jours, en base, pas en dur) ;
              - un debit maximal par noeud, cote core. Attention : le refus doit
                etre SILENCIEUX pour le noeud — fermer sa connexion parce qu'il
                remonte trop de metriques couperait aussi son enregistrement et
                son battement, donc le retirerait de la liste servie aux agents.
                La sanction serait pire que le probleme.

            Le paquet core/auth/ratelimit existe deja (point 16) mais il compte
            des tentatives d'authentification, pas des ecritures. Verifier s'il
            se generalise avant d'en ecrire un second.

8.[LDAP] - un mode synchro sur un anuaire existant qui permet de beneficier des fonctionalite de vaultaire mais en le lians a un AD deja existant 

38.[DUCKY] [PROXY] - Le relais, et l'affinite noeud <-> groupe
            Ce qui reste des points 9 et 10, dont les lots 0 a 3 sont traites : un
            agent apprend ses noeuds joignables, un proxy existe dans le cluster et
            bat. Voir DO/2.1/2.1.md.

            Le proxy est VISIBLE et connait ses cores. Il ne transporte aucun octet.

            SPECIFICATION dans « how it work/Protocole_Ducky.md », section « Ce qui
            reste du sujet 04 ». Les arbitrages 2, 5 et 6 y sont rendus et VALIDES ;
            la question ouverte est tranchee.

            Lot 4 — RELAIS TCP DUCKY.
              Le proxy transporte les octets sans les lire. Arbitrage 2 : il ne
              termine PAS la session. Depuis le point 29, le mot de passe transite
              dans le tunnel — un proxy qui dechiffrerait deviendrait un point de
              collecte des mots de passe du parc.

              Tranche : un proxy dont tous les cores sont injoignables REFUSE
              franchement. Le client essaie le suivant de sa liste — un core,
              puisqu'ils y figurent toujours. Un client en attente ne fait rien
              pendant tout le delai, et le proxy en panne devient un trou noir.

              C'est du code reseau neuf sur le chemin qui porte les mots de passe :
              a ecrire avec le meme soin que le reste de la categorie 02.

            Lot 5 — RELAIS LDAP/S. Depend du lot 4. Demande que le SAN du
              certificat du core couvre les proxies, sinon le client TLS refuse.

            Lot 6 — AFFINITE noeud <-> groupe. Table (noeud, groupe, priorite), la
              MEME que celle des proxies. Priorite et non exclusivite. Ordre servi :
              proxies affins, autres proxies, cores affins exposes, autres cores
              exposes. Le tri existe deja (TrierNoeudsPourAgents) : c'est un
              quatrieme critere a y inserer, pas un tri neuf.

            Lot 7 — GROUPES DE NAISSANCE d'une cle d'enrolement. APRES le lot 6, et
              non avant : rattacher un service a des groupes n'a aucun effet
              observable tant que l'affinite ne trie rien. Applique une fois, a
              l'enrolement — le relire a chaque connexion ferait qu'une cle modifiee
              change les groupes d'un service deja en production, et le lien entre
              la cause et l'effet serait introuvable des mois plus tard.

            Reste ouvert : rien. Les six arbitrages sont rendus.

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

40.[AGENT-UPDATE] - comment mettre a jour le parc de client (download from repo ordonée par le core ou download directement via le ducky network ou alors via un module vaultaire special vlt-upm [vaultaire-updateManager] qui est un nouveau service vauiltaire qui sert a mettre a jour les client sans acces a internet apres comment il marche je sais pas trop encore si on prend cette solution je pense que le mode repo nexus et le plsu simple sans auth pas un service sensible que de le consulter par l'administration passera par l'interface web admin)