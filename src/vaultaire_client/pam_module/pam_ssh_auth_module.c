/*
 * pam_vaultaire_ssh.c
 * PAM module: SSH key provisioning and local user setup before key auth.
 * Sends {"check":{"user":"username"}} to Vaultaire socket; on success ensures user, installs keys, sets sudo.
 */

#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
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

// static int ensure_local_user_no_password(const char *username) {
//     struct passwd *pw = getpwnam(username);
//     char cmd[512];
    
//     // 1. Si l'utilisateur n'existe pas, on le crée (c'est forcément un futur user Vaultaire)
//     if (pw == NULL) {
//         char comment[128];
//         snprintf(comment, sizeof(comment), "%s@vaultaire", username);
//         vaultaire_log_info("Creating new Vaultaire user: %s", username);

//         snprintf(cmd, sizeof(cmd), 
//                  "/usr/sbin/useradd -m -s /bin/bash -p '*' -c '%s' %s", 
//                  comment, username);
        
//         if (system(cmd) != 0) {
//             vaultaire_log_err("Failed to create user %s", username);
//             return -1;
//         }
//         pw = getpwnam(username); // Récupère l'UID généré
//     } 
//     // 2. Si l'utilisateur existe, on vérifie STRICTEMENT si c'est un user Vaultaire
//     else {
//         if (!is_vaultaire_user(username)) {
//             vaultaire_log_info("User %s is local/system, skipping permission fixes.", username);
//             return 0; // On ne touche à rien (ni shadow, ni chown)
//         }

//         // Si c'est un user Vaultaire, on s'assure qu'il n'est pas bloqué (!!)
//         snprintf(cmd, sizeof(cmd), "/usr/sbin/usermod -p '*' %s", username);
//         system(cmd);
//     }

//     // 3. Application des correctifs de permissions (UNIQUEMENT pour Vaultaire users)
//     if (pw != NULL) {
//         // Fix de l'UID sur le home (si reliquat d'une autre install)
//         snprintf(cmd, sizeof(cmd), "chown -R %u:%u /home/%s", 
//                  pw->pw_uid, pw->pw_gid, username);
//         system(cmd);

//         // StrictMode SSH : 700 sur le Home
//         snprintf(cmd, sizeof(cmd), "chmod 700 /home/%s", username);
//         system(cmd);
//     }

//     return 0;
// }

// static int install_ssh_keys_for_user(const char *username, char **ssh_keys, size_t key_count) {
//     struct passwd *pw = getpwnam(username);
//     if (!pw) {
//         vaultaire_log_err("install_ssh_keys: user %s not found", username);
//         return -1;
//     }
//     char sshdir[PATH_MAX];
//     if (snprintf(sshdir, sizeof(sshdir), "%s/.ssh", pw->pw_dir) >= (int)sizeof(sshdir)) return -1;
//     if (mkdir(sshdir, 0700) != 0 && errno != EEXIST) {
//         vaultaire_log_err("mkdir(%s): %s", sshdir, strerror(errno));
//         return -1;
//     }
//     chown(sshdir, pw->pw_uid, pw->pw_gid);
//     chmod(sshdir, 0700);

//     char authfile[PATH_MAX];
//     if (snprintf(authfile, sizeof(authfile), "%s/authorized_keys", sshdir) >= (int)sizeof(authfile)) return -1;
//     FILE *f = fopen(authfile, "w");
//     if (!f) {
//         vaultaire_log_err("fopen(%s): %s", authfile, strerror(errno));
//         return -1;
//     }
//     for (size_t i = 0; i < key_count; i++) {
//         if (!ssh_keys[i] || ssh_keys[i][0] == '\0') continue;
//         if (strncmp(ssh_keys[i], "ssh-", 4) != 0) {
//             vaultaire_log_err("Invalid SSH key format for user %s", username);
//             continue;
//         }
//         fprintf(f, "%s\n", ssh_keys[i]);
//     }
//     fclose(f);
//     chmod(authfile, 0600);
//     chown(authfile, pw->pw_uid, pw->pw_gid);
//     return 0;
// }

// static void delete_local_user(const char *username) {
//     char cmd[VAULTAIRE_CMD_SIZE];
//     snprintf(cmd, sizeof(cmd), "userdel -r %s >/dev/null 2>&1 || true", username);
//     (void)system(cmd);
// }

/* --- PAM auth hook --- */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    const char *password;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *pmsg;
    struct pam_response *pam_resp = NULL;
    char req_buf[VAULTAIRE_MAX_BUF];
    char json_res[VAULTAIRE_MAX_BUF];
    char status[64] = {0};

    openlog("VAULTAIRE_PAM", LOG_PID | LOG_NDELAY, LOG_AUTH);

    // 1. Récupérer le nom d'utilisateur
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        syslog(LOG_ERR, "Vaultaire-PAM: Failed to get username");
        closelog();
        return PAM_USER_UNKNOWN;
    }

    // On ignore les utilisateurs qui n'ont pas le tag @vaultaire dans leur GECOS
    if (!is_vaultaire_user(username)) {
        closelog();
        return PAM_IGNORE; 
    }

    // 2. Demander le mot de passe (MFA)
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) {
        closelog();
        return PAM_AUTH_ERR;
    }

    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = "Vaultaire MFA Password: ";
    pmsg = &msg;

    if (conv->conv(1, &pmsg, &pam_resp, conv->appdata_ptr) != PAM_SUCCESS || !pam_resp) {
        syslog(LOG_ERR, "Vaultaire-PAM: Conversation failed for %s", username);
        closelog();
        return PAM_AUTH_ERR;
    }
    password = pam_resp[0].resp; 

    // 3. Préparation requête JSON pour le daemon
    // On suppose que le daemon Go va créer le user/clés s'il valide ce password
    snprintf(req_buf, sizeof(req_buf), "{\"check\":{\"user\":\"%s\",\"password\":\"%s\"}}", username, password);

    // Nettoyage immédiat du mot de passe en mémoire stack/heap
    if (pam_resp[0].resp) {
        memset(pam_resp[0].resp, 0, strlen(pam_resp[0].resp));
        free(pam_resp[0].resp);
    }
    free(pam_resp);

    // 4. Envoi au daemon Go
    // Le daemon doit : 1. Vérifier l'auth | 2. Créer le user | 3. Installer les clés | 4. Répondre
    if (vaultaire_socket_send_recv(req_buf, json_res, sizeof(json_res)) != 0) {
        syslog(LOG_ERR, "Vaultaire-PAM: Daemon communication failed");
        closelog();
        return PAM_AUTHINFO_UNAVAIL;
    }

    // 5. Analyse de la réponse
    vaultaire_json_get_string(json_res, "status", status, sizeof(status));

    if (strcmp(status, "success") == 0) {
        syslog(LOG_INFO, "Vaultaire-PAM: Authentication successful for %s", username);
        closelog();
        return PAM_SUCCESS;
    }
    
    syslog(LOG_WARNING, "Vaultaire-PAM: Authentication rejected for %s", username);
    closelog();
    return PAM_PERM_DENIED;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
