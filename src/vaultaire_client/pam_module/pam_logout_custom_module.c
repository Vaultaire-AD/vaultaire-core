/*
 * pam_logout_custom_module.c
 * PAM module: notifies Vaultaire on session close.
 * Sends {"close":{"user":"...","action":"S_close"}} to socket.
 */

#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pam_common.h"

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;

    if (pam_get_item(pamh, PAM_USER, (const void **)&username) != PAM_SUCCESS || !username) {
        vaultaire_log_err("PAM: could not get username on close_session");
        return PAM_SESSION_ERR;
    }

    vaultaire_log_info("PAM: closing session for %s", username);

    char req[VAULTAIRE_MAX_BUF];
    snprintf(req, sizeof(req), "{\"close\":{\"user\":\"%s\",\"action\":\"S_close\"}}", username);
    if (vaultaire_socket_send(req) != 0)
        vaultaire_log_err("PAM: failed to send close request for %s", username);

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
