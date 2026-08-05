Une fois une action faite est validé definitevement c'est a un humain de déplacer la taches dans le dossier DO et ranger le changement dans la bonne version et d'ajouter les changemnt dans Version_History.md


1.[FAIT-H] [DOC]mettre a jour la Documentation pour séparé entierement les GPO voir trames struct (si il a des changement a faire dans le protcole dabord mettre ajour la documentation et demander ensuite validation)

2.[DEPLACE] [GPO] Ajout de nouveaux Module -> voir DO/2.0/2.1.md
            Reste ouvert : mount_hardening (ecarte volontairement) et le volet user de
            ssh_known_hosts (~/.ssh/known_hosts), implemente en scope machine seul.

4.[GPO] - Détection de dérive (drift detection)
            Rien dans le catalogue ne vérifie qu'un module resté "appliqué avec succès" (version à jour dans applied_policies.json) correspond encore à l'état réel du système — un admin qui modifie manuellement sshd_config.d/99-vaultaire-gpo.conf en SSH direct fausserait l'état sans que rien ne le détecte. Il faut un scan périodique de conformité, pas seulement une application ponctuelle.
7.[GPO] - Reporting de conformité centralisé
            Vue d'ensemble côté serveur : quelle version de policy chaque machine a effectivement appliquée avec succès, quelles machines sont en échec/en retard — sans ça, tu n'as aucune visibilité sur l'état réel du parc.

8.[LDAP] - un mode synchro sur un anuaire existant qui permet de beneficier des fonctionalite de vaultaire mais en le lians a un AD deja existant 

9.[FAIT-IA] [MFA] - possibilité d'activer le MFA via code TOTP pour la connection sur l'interface web admin ou non (il faut aussi pouvoir forcer l'activation a la premiere connection )
            [FAIT] TOTP RFC 6238 implemente sans dependance (core/global/security/totp),
                   verifie contre les 6 vecteurs de test de la RFC.
            [FAIT] Enrolement en deux temps sur /profil/mfa : secret ecrit puis active
                   seulement apres validation d'un premier code.
            [FAIT] Forcage PAR GROUPE (groups.mfa_required) et non par compte : un nouvel
                   arrivant y est soumis du seul fait de son entree.
            [FAIT] Etape intermediaire dans un registre SEPARE (session/pending.go) :
                   ValidateToken ne peut pas voir un jeton en attente.
            [FAIT] Nouveau droit write:mfa pour reinitialiser le MFA d'un tiers.
            Voir MFA_et_Expiration.md.
            A REVOIR : pas de QR code (clé + lien otpauth seulement) — un generateur
            servi depuis /static serait a ajouter, jamais depuis un CDN.

10.[FAIT-IA] [AUTH] - il faut pouvoir config un temps d'expiration des mots de passe politique global
            [FAIT] Politique globale dans server_settings, page /admin/authpolicy reservee
                   au groupe vaultaire, atteinte depuis le tableau de bord (le bandeau de
                   navigation n'est pas modifie). Duree 0 = desactive, valeur par defaut.
            [FAIT] Expiration bloquante sur LDAP et Ducky/PAM ; le web laisse entrer mais
                   n'autorise QUE le changement de mot de passe — sinon chaque expiration
                   deviendrait un ticket support.
            [FAIT] Preavis affiche sur le profil pendant les N derniers jours.
            [FAIT] Le compte d'amorcage vaultaire est exempte (compte de dernier recours).
            Voir MFA_et_Expiration.md.
            A CORRIGER : la justification de l'exemption est partiellement fausse. Le SQL
            d'amorcage insere salt='abc123salt', qui n'est pas de l'hexadecimal :
            hex.DecodeString echoue et ComparePasswords retourne false AVANT tout calcul.
            Le compte vaultaire ne peut donc PAS s'authentifier par mot de passe (web et
            LDAP). Il n'est utilisable que par le chemin Ducky, qui le traite en cas
            particulier (CheckAuthentification.go) avec un defi chiffre par cle. Soit on
            lui donne un vrai sel, soit on corrige la doc.


12.[LDAP] - Remplacer les encodeurs BER ecrits a la main par go-asn1-ber
            Chemins : core/ldap/LDAP_BIND-UNBIND/LDAP_bind.go:20 et 29-44
                      core/ldap/LDAP_BIND-UNBIND/LDAP_Unbind.go:27,40,44
                      core/ldap/LDAP_EXTENDED-REQUEST/LDAP_ExtendedRequest.go:13-42

            DEUX BUGS DISTINCTS, tous deux dus a un octet de longueur unique.

            1. La forme longue n'est pas geree. « full := []byte{0x30, byte(len(payload))} »
               n'est valide que pour une longueur <= 127. A partir de 128, BER exige la
               forme longue (0x81 nn, 0x82 nnnn...). byte(200) emet 0xC8, qu'un client lit
               comme « forme longue, 72 octets de longueur suivent » : le flux se
               desynchronise et tout le reste de la connexion est illisible.

            2. L'identifiant de message est tronque. « 0x02, 0x01, byte(messageID) » : le
               message 256 devient 0. Un client qui garde sa connexion ouverte — SSSD,
               JumpServer, un pool applicatif — depasse 255 operations en quelques minutes
               et recoit ensuite des reponses qu'il ne peut plus correler. Symptome typique
               « marche en test, casse en production apres quelques minutes ».

            CORRECTIF. github.com/go-asn1-ber/asn1-ber est DEJA une dependance du projet et
            deja utilise correctement pour les reponses SEARCH (core/ldap/LDAP_common.go).
            Ces trois encodeurs manuels n'ont aucune raison d'exister : les reecrire sur
            ber.Encode / ber.NewInteger / ber.NewString, comme LDAP_common.go.

            Aucun changement de protocole : c'est le meme LDAP, correctement encode. Pas de
            validation prealable necessaire, contrairement au point 11.
