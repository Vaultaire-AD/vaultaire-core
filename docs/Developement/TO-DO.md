

1.[FAIT-IA] [GPO] -> Faire en sorte que toutes les restrictions ne soit pas stocké en JSON mais dans le DB et puisse etre editable (uniquement par les membres du groupe vaultaire)
       Tables gpo_restriction + gpo_field_rule, page /admin/gpo/restrictions réservée au groupe vaultaire.
       Modes par champ : liste / motif (regex) / libre, avec motif d'exclusion prioritaire — c'est ce qui
       permet à un client de déclarer un service de monitoring maison sans toucher au code.
       Socle par défaut = anciennes listes en dur, réécrivable via « Réinitialiser ».
    Point a revoir : 
    -1 pas de valeur par default present pour sysctl pareil pour jeux de commande sudo (les jeux de commandes sudo par default present dans le menu deroulant ne sont pas present dans la partie administration des jeux de commandes GPO) autres bug quand je veux ajouter un droit sudo le bouton des valeur propose affiche toutes les valeurs custom au lieux d'afficher les valeur que de celle qui est selectioner plus les valeur presente par default ne sont pas jamais affiché je ne vois que les droit sudo crée 
       [CORRIGE] Cause : la base avait ete peuplee avant l'arrivee de gpo_value_definition. Le marqueur
       kind='meta' faisait sortir le peuplement en avance, donc les jeux sudo restaient de simples noms
       dans gpo_restriction (visibles dans le menu deroulant) sans definition correspondante (absents de
       la page Restrictions). Le peuplement est desormais conditionne PAR TABLE, pruneOrphanAllowValues
       nettoie les noms orphelins, et ensureFieldRules cree la regle du nouveau champ sysctl/value sur
       les bases existantes.
       [CORRIGE] L'apercu ne montre plus que le contenu de la valeur selectionnee (pre-rendu serveur +
       suivi de la selection en JS ; correct sans JavaScript).
    -2 je ne veux aucune valeur stocké dans un json pour les valeur des module tous doit etre injecter dans la base (uniquement au premier demarage (si les tables GPO existe pas en gros)) en gros tous les variable dans defaults.go ne doivent pas etre stocké en dur mais dans la DB sinon trop de pb si les valeur sont delete coté webui et que le serveur et restart cela va crée des pb
       [CORRIGE] defaults.go supprime. Les valeurs sont dans core/database/db_gpo/seed/gpo_seed.sql,
       embarque via go:embed et execute uniquement pour les tables qui viennent d'etre creees.
       core/gpo/dynamicfields.go ne garde que la STRUCTURE (quels champs sont dynamiques, libelle, type
       de contenu) : ca fait partie du catalogue de modules, pas de la donnee.
       Lecture fail-closed : plus aucun repli sur un socle interne. Si la base ne repond pas, aucune
       valeur n'est autorisee et un bandeau l'explique dans l'interface.
    -3 profite en pour mettre a jour la documentation des commandes le ficheir MAN
       [FAIT] MAN.md : §5.6 (modele declaratif, restrictions, definitions, ou vivent les valeurs,
       fail-closed), §8.5 (sortie de get -gpo et empreinte), §4 et §15 (reference rapide GPO),
       table des matieres. DataBase_Struct.md : les trois tables de restrictions et leurs regles.
2.[FAIT-H] [DOC]mettre a jour la Documentation pour séparé entierement les GPO voir trames struct (si il a des changement a faire dans le protcole dabord mettre ajour la documentation et demander ensuite validation)
3.[FAIT-IA] [SECURITY]Immuabilité de l'identité d'amorçage : user vaultaire, groupe vaultaire, permissions vaultaire_all
       et vaultaire_admin non supprimables / non renommables (core/database/protected.go, refus posés dans
       la couche base pour couvrir CLI, web, LDAP et API par construction).
4.[PAM] -> Verification du module login (pb pour la création des users si il existe pas)
4.[PAM] -> Ajout d'une mecanique pour mettre a jour le mot de passe de l'utilisateur en local
4.[PAM] -> Verification de l'expiration des comptes sur les clients
4.[GPO] -> Gère la transmission des GPO au client (quand un user se co on applique les GPO user liées a son groupe) (quand un client se connecte on applique toutes les GPO machine via ses differenet groupe ATTNETION bonne pratique il faudrai dans l'ideal pour les GPO machine quelle soit toutes regroupe dans un groupe sans user qui sert juste a appliquer les GPO machine pour l'organistion)