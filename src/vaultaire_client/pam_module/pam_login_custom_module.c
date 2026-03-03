/*
 * pam_login_custom_module.c
 * PAM module: password auth via Vaultaire socket; ensures local user and sudo rights.
 * Sends {"auth":{"user":"...","password":"..."}}; on success creates/updates local user and sets sudo.
 */

#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <shadow.h>
#include <grp.h>

#include "pam_common.h"

/* --- Local password auth (shadow) --- */
static int authenticate_locally(const char *username, const char *password) {
    struct spwd *sp = getspnam(username);
    if (!sp || !sp->sp_pwdp || sp->sp_pwdp[0] == '\0')
        return 0;
    char *hashed = crypt(password, sp->sp_pwdp);
    if (!hashed || strcmp(sp->sp_pwdp, hashed) != 0)
        return 0;
    return 1;
}

/* --- Ensure local user exists and set password --- */
static int ensure_local_user_with_password(const char *username, const char *password) {
    if (getpwnam(username)) return 1;
    char cmd[VAULTAIRE_CMD_SIZE];
    snprintf(cmd, sizeof(cmd), "useradd --shell /bin/bash -c '%s@vaultaire' %s", username, username);
    if (system(cmd) != 0) {
        vaultaire_log_err("useradd failed for %s", username);
        return 0;
    }
    snprintf(cmd, sizeof(cmd), "echo \"%s:%s\" | chpasswd", username, password);
    if (system(cmd) != 0) {
        vaultaire_log_err("chpasswd failed for %s", username);
        return 0;
    }
    vaultaire_log_info("Created local user %s", username);
    return 1;
}

/* --- Remote auth + local provisioning --- */
static int check_user_via_socket(const char *username, const char *password,
                                 char *status_out, size_t status_size, bool *is_admin_out) {
    char req[VAULTAIRE_MAX_BUF];
    snprintf(req, sizeof(req), "{\"auth\":{\"user\":\"%s\",\"password\":\"%s\"}}", username, password);
    char resp[VAULTAIRE_MAX_BUF];
    if (vaultaire_socket_send_recv(req, resp, sizeof(resp)) != 0) {
        vaultaire_log_err("socket auth failed for %s", username);
        strncpy(status_out, "timeout", status_size - 1);
        status_out[status_size - 1] = '\0';
        *is_admin_out = false;
        return -1;
    }
    resp[strcspn(resp, "\n\r")] = '\0';
    if (vaultaire_json_get_string(resp, "status", status_out, status_size) != 0)
        strncpy(status_out, "timeout", status_size - 1);
    vaultaire_json_get_bool(resp, "is_admin", is_admin_out);
    return 0;
}

static int check_user_exists(const char *username, const char *password) {
    char status[32];
    bool is_admin = false;

    vaultaire_log_info("Checking user %s remotely", username);
    if (check_user_via_socket(username, password, status, sizeof(status), &is_admin) != 0)
        return 0;

    if (strcmp(status, "timeout") == 0) {
        vaultaire_log_info("Remote timeout for %s, fallback to local auth", username);
        return authenticate_locally(username, password);
    }
    if (strcmp(status, "failed") == 0) {
        vaultaire_log_err("Remote auth failed for %s", username);
        return 0;
    }
    if (strcmp(status, "success") != 0) {
        vaultaire_log_err("Unknown status '%s' for %s", status, username);
        return 0;
    }

    if (!ensure_local_user_with_password(username, password)) {
        vaultaire_log_err("Failed to ensure local user %s", username);
        return 0;
    }
    if (is_admin)
        vaultaire_add_user_to_sudo_group(username);
    else
        vaultaire_remove_user_from_sudo_group(username);

    vaultaire_log_info("User %s authenticated successfully", username);
    return 1;
}

/* --- PAM hooks --- */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    const char *password = NULL;

    if (pam_get_user(pamh, &username, "Username: ") != PAM_SUCCESS || !username)
        return PAM_USER_UNKNOWN;
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, "Password: ") != PAM_SUCCESS || !password)
        return PAM_AUTH_ERR;

    if (strchr(username, '@') != NULL) {
        if (!vaultaire_is_valid_username(username)) {
            vaultaire_log_err("invalid username: %s", username);
            return PAM_AUTH_ERR;
        }
        if (check_user_exists(username, password))
            return PAM_SUCCESS;
        return PAM_AUTH_ERR;
    }
    if (authenticate_locally(username, password))
        return PAM_SUCCESS;
    return PAM_AUTH_ERR;
}
