#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "pam_common.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    const char *password = NULL;

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        vaultaire_log_err("pam_get_user failed");
        return PAM_USER_UNKNOWN;
    }

    if (!is_vaultaire_user(username) || !vaultaire_is_valid_username(username)) {
        vaultaire_log_info("User %s ignored (not vaultaire domain or invalid)", username);
        return PAM_IGNORE;
    }

    /* Chronometrage, ecrit seulement en mode debug (TO-DO 199). */
    struct vaultaire_chrono chrono;
    memset(&chrono, 0, sizeof(chrono));
    vaultaire_chrono_marquer(&chrono.debut);

    // Optionnel : Récupération du password MFA si transmis via la conv SSH
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    vaultaire_log_info("Password retrieved (len=%zu)", password ? strlen(password) : 0);

    /* SECOND FACTEUR : la seconde invite — TO-DO 95.
     *
     * # Pourquoi une invite et non un code accole au mot de passe
     *
     * C'est la recette du bind LDAP, et elle y est SUBIE faute de mieux : le
     * protocole LDAP n'a pas de place pour un second champ. Ici, si. Accoler
     * rendrait ambigu tout mot de passe qui finit par six chiffres, et mettrait
     * le code dans la meme variable que le mot de passe — donc dans les memes
     * journaux, les memes tampons et les memes gestionnaires de mots de passe.
     *
     * # Si la conversation n'est pas disponible
     *
     * On envoie « 0000 ». C'est le cas d'une pile PAM non interactive, et
     * surtout celui de l'authentification SSH PAR CLE : sshd n'y ouvre pas de
     * conversation, donc rien ne peut etre demande.
     *
     * Le resultat est FERME et non ouvert : « 0000 » vaut « je n'ai pas de
     * second facteur », et le core REFUSE cette valeur pour un compte qui en a
     * un. Une connexion par cle sur un compte a second facteur est donc
     * refusee — c'est le comportement voulu, et la voie pour la rendre
     * possible est « AuthenticationMethods publickey,keyboard-interactive »
     * cote sshd, qui fait tourner cette pile APRES la cle.
     *
     * Le code n'est NI journalise, NI conserve : meme regle que le mot de passe. */
    char otp[VAULTAIRE_OTP_MAX];
    {
        char *saisi = NULL;
        int rc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &saisi, "%s", VAULTAIRE_INVITE_OTP);
        if (rc == PAM_SUCCESS && saisi) {
            snprintf(otp, sizeof(otp), "%s", saisi);
            /* Efface avant de rendre la memoire : le code reste valide jusqu'a
             * 90 secondes, et un tampon libere n'est pas un tampon nettoye. */
            memset(saisi, 0, strlen(saisi));
            free(saisi);
        } else {
            snprintf(otp, sizeof(otp), "%s", VAULTAIRE_OTP_SANS_MFA);
        }
    }

    vaultaire_chrono_marquer(&chrono.saisie);

    // 1. Demande des clés au Daemon Vaultaire
    char req[VAULTAIRE_MAX_BUF];
    char resp[VAULTAIRE_MAX_BUF];
    /* Champs ECHAPPES : un mot de passe contenant un guillemet produisait
     * auparavant un JSON invalide, et ce compte ne pouvait jamais se
     * connecter. Voir vaultaire_build_check_request. */
    if (vaultaire_build_check_request(username, password, otp, req, sizeof(req)) != 0) {
        memset(otp, 0, sizeof(otp));
        return PAM_AUTH_ERR;
    }
    /* Le code a servi : il ne doit plus exister en memoire. La requete, elle,
     * le porte encore — elle est envoyee puis sort de portee. */
    memset(otp, 0, sizeof(otp));

    if (vaultaire_socket_send_recv(req, resp, sizeof(resp)) != 0) {
        vaultaire_log_err("SSH pre-auth failed via socket for %s", username);
        return PAM_AUTHINFO_UNAVAIL;
    }

    
    /* La REPONSE n'est plus journalisee en entier.
     *
     * Elle porte le statut, le drapeau administrateur et les CLES PUBLIQUES de
     * l'utilisateur. Le journal, lisible localement, donnait ainsi a qui le
     * voulait la liste des comptes du domaine qui se connectent, leur niveau de
     * privilege et leurs cles — une cartographie du parc qui grandissait sans
     * rotation ni bornage.
     *
     * On journalise ce qui sert au diagnostic : la longueur, et le statut une
     * fois extrait. */
    vaultaire_chrono_marquer(&chrono.reponse);
    vaultaire_log_info("Reponse du daemon pour %s (%zu octets)", username, strlen(resp));
    char status[32] = {0};
    vaultaire_json_get_string(resp, "status", status, sizeof(status));

    if (strcmp(status, "success") != 0) {
        vaultaire_log_err("SSH pre-auth rejected for %s", username);
        vaultaire_chrono_rapport(&chrono, "sshd", username, resp, status[0] ? status : "refus");
        return PAM_PERM_DENIED;
    }

    /* LE MESSAGE DU CORE, presente a l'utilisateur — TO-DO 99.
     *
     * Meme role que dans pam_login_custom_module.c, voir le commentaire
     * detaille qui s'y trouve.
     *
     * Sur CE chemin, le message n'atteint pas toujours l'utilisateur : quand
     * sshd authentifie par CLE PUBLIQUE, il n'y a pas de conversation
     * interactive et pam_info n'a nulle part ou ecrire. C'est sans consequence
     * — le retour est ignore, la session s'ouvre — mais c'est la raison pour
     * laquelle l'avertissement ne peut pas tenir lieu de mecanisme de
     * contrainte : il informe, il n'impose rien. */
    char notice[VAULTAIRE_NOTICE_MAX] = {0};
    if (vaultaire_json_get_string(resp, "notice", notice, sizeof(notice)) == 0 && notice[0]) {
        (void)pam_info(pamh, "%s", notice);
    }

    /* Le COMPTE est l'affaire de l'agent (TO-DO 197) : il l'a cree, a pose
     * authorized_keys, le groupe d'administration et le contexte SELinux
     * avant de repondre. Il ne reste ici que le mot de passe local, qui demande
     * crypt() pour etre compare sans reecrire /etc/shadow a chaque connexion.
     * Voir vaultaire_sync_local_password. */
    if (!vaultaire_sync_local_password(username, password)) {
        vaultaire_chrono_rapport(&chrono, "sshd", username, resp, "mot de passe local en echec");
        return PAM_AUTH_ERR;
    }
    vaultaire_chrono_rapport(&chrono, "sshd", username, resp, "success");

    vaultaire_log_info("SSH provisioning complete for %s. Passing control to OpenSSH.", username);

    // On retourne PAM_SUCCESS pour valider l'étape de provisionnement PAM SSH
    return PAM_SUCCESS; 
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
/* Phase « account » : ce compte a-t-il encore le droit d'ouvrir une session ?
 *
 * Rendait PAM_SUCCESS sans rien regarder : un compte verrouille gardait son
 * acces tant que son mot de passe local restait valide.
 *
 * Le controle est LOCAL — verrouillage, expiration, shell. Aucun appel reseau :
 * cette phase s'execute a chaque connexion, et la faire dependre du core
 * verrouillerait tout le parc a la premiere coupure. La revocation centrale a
 * son propre chemin (categorie 06), qui agit sur le compte local ; on lit ici
 * le resultat de ce travail. */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;

    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        return PAM_USER_UNKNOWN;
    }

    /* Un compte local ordinaire ne nous concerne pas : les autres modules de la
     * pile en decident. */
    if (!is_vaultaire_user(username)) {
        return PAM_IGNORE;
    }

    if (vaultaire_local_account_usable(username) != 0) {
        vaultaire_log_err("Session refusee pour %s : compte inutilisable", username);
        return PAM_ACCT_EXPIRED;
    }
    return PAM_SUCCESS;
}