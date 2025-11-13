/*
 * pam_vaultaire_ssh.c
 * Module PAM léger pour provisioning SSH keys & création d'utilisateur avant auth par clé.
 *
 * Comportement :
 *  - pam_sm_authenticate() : envoie {"check":{"user":"username"}} au socket UNIX (SOCKET_PATH)
 *  - attend une réponse JSON : {"status":"success"|"failed", "is_admin":true|false, "ssh_keys":["...","..."]}
 *  - si success : ensure local user, install keys, set sudo selon is_admin -> retourne PAM_SUCCESS
 *  - si failed : supprime local user (optionnel) -> retourne PAM_PERM_DENIED
 *
 * IMPORTANT :
 *  - Exécuter en root (module PAM).
 *  - Recommandations de sécurité mentionnées plus bas.
 */

#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <limits.h>

#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <syslog.h>

#define MAX_BUFFER_SIZE 4096
#define SOCKET_PATH "/tmp/vaultaire_client.sock"
#define CMD_SIZE 512

/* --- utilitaires simples --- */

static void log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(LOG_AUTH | LOG_INFO, fmt, ap);
    va_end(ap);
}

static void log_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(LOG_AUTH | LOG_ERR, fmt, ap);
    va_end(ap);
}

/* Send a simple JSON check request (no password) and receive server response into resp (zero-terminated) */
static int send_check_request(const char *username, char *resp, size_t resp_size) {
    int sock = -1;
    struct sockaddr_un addr;
    char req[MAX_BUFFER_SIZE];
    ssize_t s;

    if (!username || !resp) return -1;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        log_err("socket(): %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_err("connect() to %s failed: %s", SOCKET_PATH, strerror(errno));
        close(sock);
        return -1;
    }

    /* Requête minimale (format convenu) */
    snprintf(req, sizeof(req), "{\"check\":{\"user\":\"%s\"}}", username);

    s = send(sock, req, strlen(req), 0);
    if (s < 0) {
        log_err("send(): %s", strerror(errno));
        close(sock);
        return -1;
    }

    /* lire la réponse (on suppose qu'elle tient dans resp buffer) */
    s = recv(sock, resp, resp_size - 1, 0);
    if (s < 0) {
        log_err("recv(): %s", strerror(errno));
        close(sock);
        return -1;
    }
    resp[s] = '\0';
    close(sock);
    return 0;
}

/* rudimentaire parser JSON (pas de dépendance JSON externe) :
   extrait "status", "is_admin" (true/false) et la zone de tableau ssh_keys (contenu entre [ ] ) */
static void parse_response(const char *resp, char *status_out, size_t status_sz, bool *is_admin_out, char *ssh_keys_out, size_t ssh_keys_sz) {
    status_out[0] = '\0';
    *is_admin_out = false;
    ssh_keys_out[0] = '\0';

    if (!resp) return;

    /* status */
    char *p = strstr(resp, "\"status\"");
    if (p) {
        char *q = strstr(p, ":");
        if (q) {
            q++;
            while (*q == ' ' || *q == '"' ) q++;
            char tmp[64] = {0};
            int i = 0;
            while (q[i] && q[i] != '"' && q[i] != ',' && i < (int)sizeof(tmp)-1) {
                tmp[i] = q[i];
                i++;
            }
            tmp[i] = '\0';
            strncpy(status_out, tmp, status_sz-1);
        }
    }

    /* is_admin */
    p = strstr(resp, "\"is_admin\"");
    if (p) {
        char *q = strstr(p, ":");
        if (q) {
            q++;
            if (strstr(q, "true")) *is_admin_out = true;
            else *is_admin_out = false;
        }
    }

    /* ssh_keys array extraction (between first [ and ] after "ssh_keys") */
    p = strstr(resp, "\"ssh_keys\"");
    if (p) {
        char *l = strchr(p, '[');
        char *r = strchr(p, ']');
        if (l && r && r > l) {
            size_t len = r - l - 1;
            if (len >= ssh_keys_sz) len = ssh_keys_sz - 1;
            strncpy(ssh_keys_out, l+1, len);
            ssh_keys_out[len] = '\0';
        }
    }
}

/* Validate username to avoid shell injection etc. */
static bool is_valid_username(const char *username) {
    if (!username) return false;
    if (strchr(username, '/') || strchr(username, ' ') || strchr(username, ';') || strchr(username, '&') || strchr(username, ':')) return false;
    return true;
}

/* Ensure local user exists; if not create with useradd, no password set here (SSH key only).
   Returns 0 on success, -1 on failure.
   Warning: uses system() for simplicity; production: prefer fork/exec with argv. */
static int ensure_local_user_no_password(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw) return 0; /* already exists */

    char cmd[CMD_SIZE];
    /* create user with home directory, bash shell */
    snprintf(cmd, sizeof(cmd), "useradd -m -s /bin/bash -c 'vaultaire_user' %s", username);
    int rc = system(cmd);
    if (rc != 0) {
        log_err("useradd failed for %s (rc=%d)", username, rc);
        return -1;
    }
    return 0;
}

/* Install ssh keys from a simplified CSV-like content extracted earlier.
   ssh_keys_raw is like: " \"ssh-ed25519 AAA...\",\"ssh-rsa AAA...\" " (commas and optional quotes)
*/
static int install_ssh_keys_for_user(const char *username, const char *ssh_keys_raw) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        log_err("install_ssh_keys_for_user: user %s not found", username);
        return -1;
    }

    char sshdir[PATH_MAX];
    snprintf(sshdir, sizeof(sshdir), "%s/.ssh", pw->pw_dir);

    if (mkdir(sshdir, 0700) != 0) {
        if (errno != EEXIST) {
            log_err("mkdir(%s): %s", sshdir, strerror(errno));
            return -1;
        }
    }
    if (chown(sshdir, pw->pw_uid, pw->pw_gid) != 0) {
        log_err("chown(.ssh): %s", strerror(errno));
    }

    char authfile[PATH_MAX];
    snprintf(authfile, sizeof(authfile), "%s/authorized_keys", sshdir);

    FILE *f = fopen(authfile, "w");
    if (!f) {
        log_err("fopen(%s): %s", authfile, strerror(errno));
        return -1;
    }

    /* naive split by comma, trim quotes/spaces */
    char *copy = NULL;
    if (ssh_keys_raw && ssh_keys_raw[0]) {
        copy = strdup(ssh_keys_raw);
        char *tok;
        char *saveptr = NULL;
        tok = strtok_r(copy, ",", &saveptr);
        while (tok) {
            /* trim spaces and quotes */
            while (*tok == ' ' || *tok == '"' || *tok == '\'') tok++;
            char *end = tok + strlen(tok) - 1;
            while (end > tok && (*end == ' ' || *end == '"' || *end == '\'')) { *end = '\0'; end--; }

            if (strlen(tok) > 10) {
                fprintf(f, "%s\n", tok);
            }
            tok = strtok_r(NULL, ",", &saveptr);
        }
        free(copy);
    }

    fclose(f);
    chmod(authfile, 0600);
    chown(authfile, pw->pw_uid, pw->pw_gid);
    return 0;
}

/* Add or remove sudo group membership; detect a suitable sudo-like group automatically */
static int detect_sudo_group(char *group, size_t gsize) {
    const char *candidates[] = { "sudo", "wheel", "admin", "staff" };
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); ++i) {
        struct group *g = getgrnam(candidates[i]);
        if (g) {
            strncpy(group, candidates[i], gsize-1);
            group[gsize-1] = '\0';
            return 0;
        }
    }
    /* fallback: create sudo group */
    strncpy(group, "sudo", gsize-1);
    group[gsize-1] = '\0';
    system("getent group sudo >/dev/null 2>&1 || groupadd sudo");
    return 0;
}

static int add_user_to_group(const char *username, const char *group) {
    char cmd[CMD_SIZE];
    if (system("command -v usermod >/dev/null 2>&1") == 0) {
        snprintf(cmd, sizeof(cmd), "usermod -aG %s %s", group, username);
    } else {
        /* fallback for minimal systems */
        snprintf(cmd, sizeof(cmd), "adduser %s %s 2>/dev/null || echo"); /* best effort */
    }
    return system(cmd);
}
static int remove_user_from_group(const char *username, const char *group) {
    char cmd[CMD_SIZE];
    if (system("command -v gpasswd >/dev/null 2>&1") == 0) {
        snprintf(cmd, sizeof(cmd), "gpasswd -d %s %s", username, group);
    } else {
        /* fallback awk edit of /etc/group is risky; we'll best-effort use deluser if present */
        snprintf(cmd, sizeof(cmd), "deluser %s %s 2>/dev/null || true", username, group);
    }
    return system(cmd);
}

/* delete local user and home - best effort */
static void delete_local_user(const char *username) {
    char cmd[CMD_SIZE];
    snprintf(cmd, sizeof(cmd), "userdel -r %s >/dev/null 2>&1 || true", username);
    system(cmd);
}

/* --- PAM hook for auth --- */
/* This module is intended to be placed in the "auth" stack for sshd.
   It runs a check to fetch keys & admin flag. If success -> provisioning -> PAM_SUCCESS
   If failed -> removes user (optional) and returns PAM_PERM_DENIED
*/

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    int ret = pam_get_user(pamh, &username, NULL);
    if (ret != PAM_SUCCESS || !username) {
        log_err("pam_get_user failed");
        return PAM_USER_UNKNOWN;
    }

    /* validate */
    if (!is_valid_username(username)) {
        log_err("invalid username: %s", username);
        return PAM_PERM_DENIED;
    }

    /* contact remote service to check rights and fetch keys */
    char resp[MAX_BUFFER_SIZE];
    if (send_check_request(username, resp, sizeof(resp)) != 0) {
        log_err("send_check_request failed for %s", username);
        /* conservative: deny */
        return PAM_PERM_DENIED;
    }

    char status[64];
    bool is_admin = false;
    char ssh_keys_raw[2048];
    parse_response(resp, status, sizeof(status), &is_admin, ssh_keys_raw, sizeof(ssh_keys_raw));

    log_info("vaultaire: user=%s status=%s is_admin=%s", username, status, is_admin ? "true" : "false");

    if (strcmp(status, "success") == 0) {
        /* Ensure local user exists */
        if (ensure_local_user_no_password(username) != 0) {
            log_err("Could not ensure local user %s", username);
            return PAM_PERM_DENIED;
        }
        /* Install public keys (if any) */
        if (ssh_keys_raw[0]) {
            if (install_ssh_keys_for_user(username, ssh_keys_raw) != 0) {
                log_err("Failed installing ssh keys for %s", username);
                /* continue: keys failure shouldn't necessarily block? We choose to deny to be safe */
                return PAM_PERM_DENIED;
            }
        }

        /* Sudo membership */
        char group[64];
        detect_sudo_group(group, sizeof(group));
        if (is_admin) {
            add_user_to_group(username, group);
        } else {
            remove_user_from_group(username, group);
        }

        return PAM_SUCCESS;
    } else {
        /* failed -> delete user if exists and deny */
        delete_local_user(username);
        log_info("vaultaire: access denied for %s -> deleted local account if present", username);
        return PAM_PERM_DENIED;
    }
}

/* No credential setting needed here */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/* Not used (account mgmt) but we return success */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
