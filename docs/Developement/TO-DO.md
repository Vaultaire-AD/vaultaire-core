Une fois une action faite est validé definitevement c'est a un humain de déplacer la taches dans le dossier DO et ranger le changement dans la bonne version et d'ajouter les changemnt dans Version_History.md


1.[FAIT-H] [DOC]mettre a jour la Documentation pour séparé entierement les GPO voir trames struct (si il a des changement a faire dans le protcole dabord mettre ajour la documentation et demander ensuite validation)
2.[PAM] -> Verification du module login (pb pour la création des users si il existe pas)
    [CORRIGE-IA] Connexion graphique : aucune requete n'arrivait au daemon.
       Cause : GDM n'utilise pas /etc/pam.d/login mais /etc/pam.d/gdm-password, que rocky.sh
       n'ecrivait pas. Le module n'etait donc jamais appele depuis l'interface graphique.
       rocky.sh ecrit maintenant la pile gdm-password (si GDM est present) et pose
       disable-user-list, sans quoi un compte Vaultaire jamais connecte sur la machine
       n'apparait dans aucune liste et l'utilisateur croit que son compte n'existe pas.
    [CORRIGE-IA] Risque de verrouillage sur /etc/pam.d/login.
       La pile utilisait « auth required pam_login_custom_module.so » avec system-auth commente :
       un compte local, root compris, ne pouvait plus se connecter en console, puisque le seul
       module rendait PAM_IGNORE sans que personne prenne le relais.
       Remplace par [success=done ignore=ignore default=die] + substack system-auth, le meme
       schema que la pile sshd qui, elle, etait correcte.
    Reste a traiter : la creation des users quand ils n'existent pas encore localement.
3.[FAIT-IA] [PAM] -> Ajout d'une mecanique pour mettre a jour le mot de passe de l'utilisateur en local
       ensure_local_user_with_password lancait chpasswd a CHAQUE connexion reussie, sans rien
       comparer. Ajout de local_password_matches() : le hash deja present dans /etc/shadow sert de
       reglage a crypt_r (il porte l'algorithme, le cout et le sel), on rechiffre le mot de passe
       fourni avec ce reglage et on compare. chpasswd n'est lance que si le resultat differe.
       Pourquoi ca comptait : reecrire /etc/shadow a chaque connexion remettait a zero la date de
       dernier changement (sp_lstchg), ce qui fausse toute politique de peremption de mot de passe.
       Cas traites : compte verrouille ("!", "!!", "*"), champ vide, hash tronque, entree shadow
       illisible -> on reecrit, comportement sur en cas de doute.
       struct crypt_data fait 32 Ko avec libxcrypt : allouee sur le tas, pas sur la pile d'un module
       PAM, et effacee (explicit_bzero) avant liberation car elle contient un derive du mot de passe.
       ATTENTION build : -lcrypt ajoute dans auto-compil.sh et pam_module/auto_compil.sh. Sans lui le
       .so se construit quand meme (les objets partages tolerent les symboles non resolus) mais PAM
       echoue a le charger a l'execution — meme symptome que le module absent de la pile.
4.[FAIT-H][PAM] -> Verification de l'expiration des comptes sur les clients :
      les comptes sont supprimé au bout de 6 d'inactivité uniquement si il y a plus de 3 comptes vaultaires sur le client
