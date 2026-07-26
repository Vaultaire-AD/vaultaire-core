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

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username)
        return PAM_USER_UNKNOWN;

    if (!is_vaultaire_user(username) || !vaultaire_is_valid_username(username))
        return PAM_IGNORE;

    // Optionnel : Récupération du password MFA si transmis via la conv SSH
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

    // 1. Demande des clés au Daemon Vaultaire
    char req[VAULTAIRE_MAX_BUF];
    char resp[VAULTAIRE_MAX_BUF];
    snprintf(req, sizeof(req), "{\"check\":{\"user\":\"%s\",\"password\":\"%s\"}}", 
             username, password ? password : "");

    if (vaultaire_socket_send_recv(req, resp, sizeof(resp)) != 0) {
        vaultaire_log_err("SSH pre-auth failed via socket for %s", username);
        return PAM_AUTHINFO_UNAVAIL;
    }

    char status[32] = {0};
    bool is_admin = false;
    vaultaire_json_get_string(resp, "status", status, sizeof(status));
    vaultaire_json_get_bool(resp, "is_admin", &is_admin);

    if (strcmp(status, "success") != 0) {
        vaultaire_log_err("SSH pre-auth rejected for %s", username);
        return PAM_PERM_DENIED;
    }

    // 2. Création de l'utilisateur local (avec ou sans pass)
    if (!ensure_local_user_with_password(username, password))
        return PAM_AUTH_ERR;

    // 3. Application des privilèges Sudo
    if (is_admin) vaultaire_add_user_to_sudo_group(username);
    else vaultaire_remove_user_from_sudo_group(username);

    // 4. Ecriture des clés SSH dans ~/.ssh/authorized_keys
    char **keys = NULL;
    size_t key_count = 0;
    if (vaultaire_json_get_ssh_keys(resp, &keys, &key_count) == 0 && keys) {
        setup_user_ssh_keys(username, keys, key_count);
        for (size_t i = 0; i < key_count; i++) free(keys[i]);
        free(keys);
    }

    vaultaire_log_info("SSH provisioning complete for %s. Passing control to OpenSSH.", username);

    // On retourne PAM_SUCCESS pour valider l'étape de provisionnement PAM SSH
    return PAM_SUCCESS; 
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }