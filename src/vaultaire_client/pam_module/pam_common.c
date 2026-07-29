/*
 * pam_common.c
 * Shared implementation for Vaultaire PAM modules.
 */

#define _GNU_SOURCE
#include "pam_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <linux/limits.h>

/* --- Logging --- */
static void vaultaire_log_v(const char *prefix, const char *fmt, va_list ap) {
    FILE *f = fopen("/var/log/vaultaire/vaultaire_pam.log", "a");
    if (f) {
        fprintf(f, "[%s] ", prefix);
        vfprintf(f, fmt, ap);
        fprintf(f, "\n");
        fclose(f);
    }
}

void vaultaire_log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vaultaire_log_v("INFO", fmt, ap);
    va_end(ap);
}

void vaultaire_log_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vaultaire_log_v("ERROR", fmt, ap);
    va_end(ap);
}



int is_vaultaire_user(const char *username) {
    if (username == NULL)
        return 0;

    return strchr(username, '@') != NULL;
}

bool vaultaire_is_valid_username(const char *username) {
    if (!username) return false;
    if (strpbrk(username, "/ ;&:\n\r\t")) return false;
    return true;
}


/* --- Commande exécutée via subprocess --- */
static int run_useradd(const char *username) {
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) {
        execl("/usr/sbin/useradd", "useradd", "-m", "--shell", "/bin/bash",
              "-c", "vaultaire", username, (char *)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int run_chpasswd(const char *username, const char *password) {
    int fd[2];
    if (pipe(fd) != 0) return 0;
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]); close(fd[1]);
        return 0;
    }
    if (pid == 0) {
        dup2(fd[0], STDIN_FILENO);
        close(fd[0]); close(fd[1]);
        execl("/usr/sbin/chpasswd", "chpasswd", (char *)NULL);
        _exit(127);
    }
    close(fd[0]);
    dprintf(fd[1], "%s:%s\n", username, password);
    close(fd[1]);
    int status;
    if (waitpid(pid, &status, 0) < 0) return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int ensure_local_user_with_password(const char *username, const char *password) {
    if (!getpwnam(username)) {
        if (!run_useradd(username)) {
            vaultaire_log_err("useradd failed for %s", username);
            return 0;
        }
        vaultaire_log_info("Created local user %s", username);
    }

    if (password && password[0] != '\0') {
        if (!run_chpasswd(username, password)) {
            vaultaire_log_err("chpasswd failed for %s", username);
            return 0;
        }
    }
    return 1;
}

/* --- Provisioning Clés SSH --- */
int setup_user_ssh_keys(const char *username, char **keys, size_t key_count) {
    struct passwd *pw = getpwnam(username);
    if (!pw) return 0;

    char ssh_dir[PATH_MAX];
    char auth_keys_path[PATH_MAX];
    int n;

    n = snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", pw->pw_dir);
    if (n < 0 || (size_t)n >= sizeof(ssh_dir)) {
        vaultaire_log_err("Home path too long for %s", username);
        return 0;
    }

    n = snprintf(auth_keys_path, sizeof(auth_keys_path), "%s/authorized_keys", ssh_dir);
    if (n < 0 || (size_t)n >= sizeof(auth_keys_path)) {
        vaultaire_log_err("authorized_keys path too long for %s", username);
        return 0;
    }

    // Création du répertoire .ssh
    if (mkdir(ssh_dir, 0700) != 0 && errno != EEXIST) {
        vaultaire_log_err("Failed to create ssh dir %s: %s", ssh_dir, strerror(errno));
        return 0;
    }
    chown(ssh_dir, pw->pw_uid, pw->pw_gid);

    // Écriture du fichier authorized_keys
    FILE *f = fopen(auth_keys_path, "w");
    if (!f) {
        vaultaire_log_err("Failed to open %s: %s", auth_keys_path, strerror(errno));
        return 0;
    }

    for (size_t i = 0; i < key_count; i++) {
        fprintf(f, "%s\n", keys[i]);
    }
    fclose(f);

    chmod(auth_keys_path, 0600);
    chown(auth_keys_path, pw->pw_uid, pw->pw_gid);

    vaultaire_log_info("Provisioned %2zu SSH key(s) for %s", key_count, username);
    return 1;
}



/* --- Socket --- */
static int connect_socket(void) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        vaultaire_log_err("socket(): %s", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, VAULTAIRE_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        vaultaire_log_err("connect() to %s: %s", VAULTAIRE_SOCKET_PATH, strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

int vaultaire_socket_send_recv(const char *request, char *resp, size_t resp_size) {
    if (!request) return -1;
    int sock = connect_socket();
    if (sock < 0) return -1;
    size_t len = strlen(request);
    if (send(sock, request, len, 0) != (ssize_t)len) {
        vaultaire_log_err("send(): %s", strerror(errno));
        close(sock);
        return -1;
    }
    if (resp && resp_size > 0) {
        ssize_t n = recv(sock, resp, resp_size - 1, 0);
        if (n < 0) {
            vaultaire_log_err("recv(): %s", strerror(errno));
            close(sock);
            return -1;
        }
        resp[n] = '\0';
    }
    close(sock);
    return 0;
}

int vaultaire_socket_send(const char *request) {
    return vaultaire_socket_send_recv(request, NULL, 0);
}


/* --- Sudo group --- */
static const char *sudo_group_candidates[] = { "sudo", "wheel", "admin", "staff", "root" };

int vaultaire_detect_sudo_group(char *group, size_t gsize) {
    for (size_t i = 0; i < sizeof(sudo_group_candidates) / sizeof(sudo_group_candidates[0]); i++) {
        struct group *g = getgrnam(sudo_group_candidates[i]);
        if (g) {
            strncpy(group, sudo_group_candidates[i], gsize - 1);
            group[gsize - 1] = '\0';
            return 0;
        }
    }
    strncpy(group, "sudo", gsize - 1);
    group[gsize - 1] = '\0';
    (void)system("getent group sudo >/dev/null 2>&1 || groupadd sudo");
    return 0;
}

int vaultaire_add_user_to_sudo_group(const char *username) {
    char group[64];
    if (vaultaire_detect_sudo_group(group, sizeof(group)) != 0) return -1;
    char cmd[VAULTAIRE_CMD_SIZE];
    if (system("command -v usermod >/dev/null 2>&1") == 0)
        snprintf(cmd, sizeof(cmd), "usermod -aG %s %s", group, username);
    else
        snprintf(cmd, sizeof(cmd), "adduser %s %s 2>/dev/null || true", username, group);
    return system(cmd);
}

int vaultaire_remove_user_from_sudo_group(const char *username) {
    char group[64];
    if (vaultaire_detect_sudo_group(group, sizeof(group)) != 0) return -1;
    char cmd[VAULTAIRE_CMD_SIZE];
    if (system("command -v gpasswd >/dev/null 2>&1") == 0)
        snprintf(cmd, sizeof(cmd), "gpasswd -d %s %s", username, group);
    else
        snprintf(cmd, sizeof(cmd), "deluser %s %s 2>/dev/null || true", username, group);
    return system(cmd);
}

/* --- JSON helpers (minimal, no external lib) --- */
int vaultaire_json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    if (!json || !key || !out || out_size == 0) return -1;
    out[0] = '\0';
    size_t key_len = strlen(key);
    char search[128];
    if (key_len + 4 >= sizeof(search)) return -1;
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    const char *start = p;
    while (*p && *p != '"') p++;
    if (!*p) return -1;
    size_t len = (size_t)(p - start);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

int vaultaire_json_get_bool(const char *json, const char *key, bool *out) {
    if (!json || !key || !out) return -1;
    size_t key_len = strlen(key);
    char search[128];
    if (key_len + 4 >= sizeof(search)) return -1;
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    *out = (strncmp(p, "true", 4) == 0);
    return 0;
}

int vaultaire_json_get_ssh_keys(const char *json, char ***keys_out, size_t *count_out) {
    if (!json || !keys_out || !count_out) return -1;
    *keys_out = NULL;
    *count_out = 0;

    const char *p = strstr(json, "\"ssh_keys\"");
    if (!p) return 0;
    p = strchr(p, '[');
    if (!p) return 0;
    p++;

    char **keys = NULL;
    size_t count = 0;

    while (*p && *p != ']') {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p != '"') break;
        p++; // Sauter le " ouvrant

        const char *start = p;
        // Trouver la fin de la string en ignorant les \" (guillemets échappés)
        while (*p && !(*p == '"' && *(p-1) != '\\')) p++;
        if (!*p) break;

        size_t raw_len = (size_t)(p - start);
        char *key = malloc(raw_len + 1);
        if (!key) break;

        // Copie intelligente pour supprimer les échappements (ex: \/ -> /)
        size_t j = 0;
        for (size_t i = 0; i < raw_len; i++) {
            if (start[i] == '\\' && i + 1 < raw_len) {
                // On saute le backslash si c'est un slash ou un guillemet échappé
                if (start[i+1] == '/' || start[i+1] == '"' || start[i+1] == '\\') {
                    continue; 
                }
            }
            key[j++] = start[i];
        }
        key[j] = '\0';

        char **tmp = realloc(keys, sizeof(char *) * (count + 1));
        if (!tmp) { free(key); break; }
        keys = tmp;
        keys[count++] = key;
        p++; // Sauter le " fermant
    }
    *keys_out = keys;
    *count_out = count;
    return 0;
}