Une fois une action faite est validé definitevement c'est a un humain de déplacer la taches dans le dossier DO et ranger le changement dans la bonne version et d'ajouter les changemnt dans Version_History.md


1.[FAIT-H] [DOC]mettre a jour la Documentation pour séparé entierement les GPO voir trames struct (si il a des changement a faire dans le protcole dabord mettre ajour la documentation et demander ensuite validation)
2.[PAM] -> Verification du module login (pb pour la création des users si il existe pas)
3.[PAM] -> Ajout d'une mecanique pour mettre a jour le mot de passe de l'utilisateur en local
4.[PAM] -> Verification de l'expiration des comptes sur les clients
6.[FAIT-IA] [WEB-GPO] -> sur l'interface web il faut que les GPO soit visible et clickable depuis le page details d'un groupe
       Section GPO dans /admin/groups?group=X : liste cliquable vers /admin/gpo?gpo=X, liaison et
       deliaison depuis la page groupe (RBAC write:add:gpo / write:delete:gpo).
       Seules les GPO pas encore liees sont proposees a l'ajout.
7.[FAIT-IA] [WEB] -> sur l'interface graphique pouvoir gere les permissions clients (aussi cote page group)
       Cause : GroupInfo.ClientPerms et GroupInfo.GPOs etaient deja lus par Command_GET_GroupInfo et
       exposes dans l'API de l'arborescence, mais aucun template ne les affichait. Les permissions
       client n'etaient donc gerables qu'en CLI.
       - /admin/permissions : section dediee (liste, creation avec drapeau admin, suppression).
         La creation d'une permission client ADMIN est journalisee en SECURITY.
       - /admin/groups?group=X : section permissions client (liste, ajout, retrait).
       - La page distingue explicitement permissions UTILISATEUR et permissions CLIENT, qui etaient
         confondues faute d'affichage.
       Au passage : les clients de la page groupe sont devenus cliquables vers leur fiche.