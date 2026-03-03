/*
 * pam_vaultaire_ssh.c
 * PAM module: SSH key provisioning and local user setup before key auth.
 * Sends {"check":{"user":"username"}} to Vaultaire socket; on success ensures user, installs keys, sets sudo.
 */

#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <sys/stat.h>
#include <limits.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "pam_common.h"

/* --- SSH-specific: ensure user (no password), install keys, delete user --- */

static int ensure_local_user_no_password(const char *username) {
    struct passwd *pw = getpwnam(username);
    char cmd[512];
    
    // 1. Si l'utilisateur n'existe pas, on le crée (c'est forcément un futur user Vaultaire)
    if (pw == NULL) {
        char comment[128];
        snprintf(comment, sizeof(comment), "%s@vaultaire", username);
        vaultaire_log_info("Creating new Vaultaire user: %s", username);

        snprintf(cmd, sizeof(cmd), 
                 "/usr/sbin/useradd -m -s /bin/bash -p '*' -c '%s' %s", 
                 comment, username);
        
        if (system(cmd) != 0) {
            vaultaire_log_err("Failed to create user %s", username);
            return -1;
        }
        pw = getpwnam(username); // Récupère l'UID généré
    } 
    // 2. Si l'utilisateur existe, on vérifie STRICTEMENT si c'est un user Vaultaire
    else {
        if (!is_vaultaire_user(username)) {
            vaultaire_log_info("User %s is local/system, skipping permission fixes.", username);
            return 0; // On ne touche à rien (ni shadow, ni chown)
        }

        // Si c'est un user Vaultaire, on s'assure qu'il n'est pas bloqué (!!)
        snprintf(cmd, sizeof(cmd), "/usr/sbin/usermod -p '*' %s", username);
        system(cmd);
    }

    // 3. Application des correctifs de permissions (UNIQUEMENT pour Vaultaire users)
    if (pw != NULL) {
        // Fix de l'UID sur le home (si reliquat d'une autre install)
        snprintf(cmd, sizeof(cmd), "chown -R %u:%u /home/%s", 
                 pw->pw_uid, pw->pw_gid, username);
        system(cmd);

        // StrictMode SSH : 700 sur le Home
        snprintf(cmd, sizeof(cmd), "chmod 700 /home/%s", username);
        system(cmd);
    }

    return 0;
}

static int install_ssh_keys_for_user(const char *username, char **ssh_keys, size_t key_count) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        vaultaire_log_err("install_ssh_keys: user %s not found", username);
        return -1;
    }
    char sshdir[PATH_MAX];
    if (snprintf(sshdir, sizeof(sshdir), "%s/.ssh", pw->pw_dir) >= (int)sizeof(sshdir)) return -1;
    if (mkdir(sshdir, 0700) != 0 && errno != EEXIST) {
        vaultaire_log_err("mkdir(%s): %s", sshdir, strerror(errno));
        return -1;
    }
    chown(sshdir, pw->pw_uid, pw->pw_gid);
    chmod(sshdir, 0700);

    char authfile[PATH_MAX];
    if (snprintf(authfile, sizeof(authfile), "%s/authorized_keys", sshdir) >= (int)sizeof(authfile)) return -1;
    FILE *f = fopen(authfile, "w");
    if (!f) {
        vaultaire_log_err("fopen(%s): %s", authfile, strerror(errno));
        return -1;
    }
    for (size_t i = 0; i < key_count; i++) {
        if (!ssh_keys[i] || ssh_keys[i][0] == '\0') continue;
        if (strncmp(ssh_keys[i], "ssh-", 4) != 0) {
            vaultaire_log_err("Invalid SSH key format for user %s", username);
            continue;
        }
        fprintf(f, "%s\n", ssh_keys[i]);
    }
    fclose(f);
    chmod(authfile, 0600);
    chown(authfile, pw->pw_uid, pw->pw_gid);
    return 0;
}

// static void delete_local_user(const char *username) {
//     char cmd[VAULTAIRE_CMD_SIZE];
//     snprintf(cmd, sizeof(cmd), "userdel -r %s >/dev/null 2>&1 || true", username);
//     (void)system(cmd);
// }

/* --- PAM auth hook --- */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        vaultaire_log_err("pam_get_user failed");
        return PAM_USER_UNKNOWN;
    }
    // if (strchr(username, '@') == NULL)
    //     return PAM_IGNORE;
    if (!is_vaultaire_user(username)) {
        vaultaire_log_err("User %s is not a Vaultaire user, ignoring", username);
        return PAM_IGNORE;
    }

    if (!vaultaire_is_valid_username(username)) {
        vaultaire_log_err("invalid username: %s", username);
        return PAM_PERM_DENIED;
    }

    char req[VAULTAIRE_MAX_BUF];
    snprintf(req, sizeof(req), "{\"check\":{\"user\":\"%s\"}}", username);
    char resp[VAULTAIRE_MAX_BUF];
    if (vaultaire_socket_send_recv(req, resp, sizeof(resp)) != 0) {
        vaultaire_log_err("send_check_request failed for %s", username);
        return PAM_PERM_DENIED;
    }

    char status[64];
    bool is_admin = false;
    char **ssh_keys = NULL;
    size_t key_count = 0;

    if (vaultaire_json_get_string(resp, "status", status, sizeof(status)) != 0) {
        vaultaire_log_err("parse status failed");
        return PAM_PERM_DENIED;
    }
    vaultaire_json_get_bool(resp, "is_admin", &is_admin);
    vaultaire_json_get_ssh_keys(resp, &ssh_keys, &key_count);

    vaultaire_log_info("vaultaire: user=%s status=%s is_admin=%s", username, status, is_admin ? "true" : "false");

    if (strcmp(status, "success") == 0) {
        if (ensure_local_user_no_password(username) != 0) {
            vaultaire_log_err("Could not ensure local user %s", username);
            if (ssh_keys) { for (size_t i = 0; i < key_count; i++) free(ssh_keys[i]); free(ssh_keys); }
            return PAM_PERM_DENIED;
        }
        if (key_count > 0 && install_ssh_keys_for_user(username, ssh_keys, key_count) != 0) {
            vaultaire_log_err("Failed installing ssh keys for %s", username);
            for (size_t i = 0; i < key_count; i++) free(ssh_keys[i]); free(ssh_keys);
            return PAM_PERM_DENIED;
        }
        for (size_t i = 0; i < key_count; i++) free(ssh_keys[i]);
        free(ssh_keys);
        if (is_admin)
            vaultaire_add_user_to_sudo_group(username);
        else
            vaultaire_remove_user_from_sudo_group(username);
        return PAM_IGNORE;
    }
    // delete_local_user(username);
    vaultaire_log_info("vaultaire: access denied for %s", username);
    return PAM_PERM_DENIED;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
