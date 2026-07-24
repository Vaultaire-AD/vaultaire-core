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

    if (pam_get_user(pamh, &username, "Username: ") != PAM_SUCCESS || !username)
        return PAM_USER_UNKNOWN;

    if (!is_vaultaire_user(username) || !vaultaire_is_valid_username(username))
        return PAM_IGNORE;

    if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, "Password: ") != PAM_SUCCESS || !password)
        return PAM_AUTH_ERR;

    // 1. Requete au socket Vaultaire
    char req[VAULTAIRE_MAX_BUF];
    char resp[VAULTAIRE_MAX_BUF];
    snprintf(req, sizeof(req), "{\"auth\":{\"user\":\"%s\",\"password\":\"%s\"}}", username, password);

    if (vaultaire_socket_send_recv(req, resp, sizeof(resp)) != 0) {
        vaultaire_log_err("Socket auth failed for %s", username);
        return PAM_AUTHINFO_UNAVAIL;
    }

    // 2. Traitement des réponses
    char status[32] = {0};
    bool is_admin = false;
    vaultaire_json_get_string(resp, "status", status, sizeof(status));
    vaultaire_json_get_bool(resp, "is_admin", &is_admin);

    if (strcmp(status, "success") != 0) {
        vaultaire_log_err("Auth rejected for %s (status: %s)", username, status);
        return PAM_AUTH_ERR;
    }

    // 3. User local & Mot de passe local (shadow)
    if (!ensure_local_user_with_password(username, password))
        return PAM_AUTH_ERR;

    // 4. Provisioning Droits
    if (is_admin) vaultaire_add_user_to_sudo_group(username);
    else vaultaire_remove_user_from_sudo_group(username);

    // 5. Injecter aussi les Clés SSH au passage
    char **keys = NULL;
    size_t key_count = 0;
    if (vaultaire_json_get_ssh_keys(resp, &keys, &key_count) == 0 && keys) {
        setup_user_ssh_keys(username, keys, key_count);
        for (size_t i = 0; i < key_count; i++) free(keys[i]);
        free(keys);
    }

    vaultaire_log_info("Login successful for Vaultaire user: %s", username);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }