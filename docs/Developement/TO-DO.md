Une fois une action faite est validé definitevement c'est a un humain de déplacer la taches dans le dossier DO et ranger le changement dans la bonne version et d'ajouter les changemnt dans Version_History.md


1.[FAIT-H] [DOC]mettre a jour la Documentation pour séparé entierement les GPO voir trames struct (si il a des changement a faire dans le protcole dabord mettre ajour la documentation et demander ensuite validation)
2.[PAM] -> Verification du module login (pb pour la création des users si il existe pas)
3.[PAM] -> Ajout d'une mecanique pour mettre a jour le mot de passe de l'utilisateur en local
4.[PAM] -> Verification de l'expiration des comptes sur les clients
5.[GPO] -> Gère la transmission des GPO au client (quand un user se co on applique les GPO user liées a son groupe) (quand un client se connecte on applique toutes les GPO machine via ses differenet groupe ATTNETION bonne pratique il faudrai dans l'ideal pour les GPO machine quelle soit toutes regroupe dans un groupe sans user qui sert juste a appliquer les GPO machine pour l'organistion)
    [EN ATTENTE DE VALIDATION - PROTOCOLE v2] Proposition redigee dans Tableau_Protocole_Reseau.md,
    section « Detail du transport GPO ». Aucune implementation avant accord.
      - v2 : renumerotation pour coller chaque demande a ses reponses (succes / rien a faire / erreur).
        Plage 05_01 a 05_14. Libre a partir de 05_15.
      - Modele pull : le client initie (demarrage + rafraichissement pour machine, apres auth PAM pour user).
      - Manifeste + fragments de 32 Kio : la taille de trame est bornee a uint16 et la charge est
        base64(AES-GCM), soit ~48 Kio utiles, alors qu'un seul file_deploy accepte 256 Kio.
      - Comparaison d'empreintes SHA-256 (globale puis par module) pour ne reappliquer que ce qui a change.
      - Etat local /var/lib/vaultaire/applied_policies.json, chemin deja refuse a toutes les GPO.
      - Rapport d'application 05_09 vers le serveur, sinon l'interface presenterait la configuration
        voulue comme si c'etait la configuration reelle.
      - Les 10 slots 05_01..05_10 sont utilises.
    Decisions actees avec l'humain :
      - decoupage en fragments plutot que plafonnement de la taille des politiques ;
      - si les GPO user echouent ou expirent, la connexion est accordee et l'incident est journalise
        (aucun module de scope user ne touche aux privileges) ;
      - scope user : intersection stricte des groupes machine et utilisateur.
    A corriger au passage : resolveUserPolicy prend actuellement tous les groupes de l'utilisateur
    au lieu de l'intersection avec ceux de la machine (ecart avec la doc du protocole).
    A prevoir ensuite, TO-DO separee : signature de la politique par le serveur central. Le tunnel
    Ducky couvre l'ecoute et la modification en transit, pas un serveur central compromis.
6.[GPO] -> sur l'interface web il faut que les GPO soit visible et clickable depuis le page details d'un groupe