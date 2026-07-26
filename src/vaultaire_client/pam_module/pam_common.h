/*
 * pam_common.h
 * Shared definitions and API for Vaultaire PAM modules (login, logout, SSH auth).
 * No PAM types here — pure C helpers for socket, logging, user/sudo, JSON.
 */

#ifndef PAM_VAULTAIRE_COMMON_H
#define PAM_VAULTAIRE_COMMON_H

#include <stddef.h>
#include <stdbool.h>
#include <linux/limits.h>   // pour PATH_MAX

/* --- Constants (single source of truth) --- */

#define VAULTAIRE_SOCKET_PATH    "/tmp/vaultaire_client.sock"
#define VAULTAIRE_MAX_BUF        4096
#define VAULTAIRE_CMD_SIZE       512

/* --- Logging (syslog, LOG_AUTH) --- */
void vaultaire_log_info(const char *fmt, ...);
void vaultaire_log_err(const char *fmt, ...);


int is_vaultaire_user(const char *username);
/* --- UNIX socket: send JSON request; optionally receive response --- */
/* Returns 0 on success, -1 on error. If resp and resp_size > 0, response is written (null-terminated). */
int vaultaire_socket_send_recv(const char *request, char *resp, size_t resp_size);
/* Fire-and-forget (e.g. close session); returns 0 on success, -1 on error. */
int vaultaire_socket_send(const char *request);

/* --- Username validation (injection-safe) --- */
bool vaultaire_is_valid_username(const char *username);

/* --- Sudo group: detect and add/remove user --- */
int vaultaire_detect_sudo_group(char *group, size_t gsize);
int vaultaire_add_user_to_sudo_group(const char *username);
int vaultaire_remove_user_from_sudo_group(const char *username);

/* --- Minimal JSON helpers (no external lib) --- */
/* Get string value for key "key" into out (at most out_size bytes). Returns 0 on success. */
int vaultaire_json_get_string(const char *json, const char *key, char *out, size_t out_size);
/* Get boolean for key "key". Returns 0 on success, -1 if not found. */
int vaultaire_json_get_bool(const char *json, const char *key, bool *out);

/* --- SSH keys array: parse "ssh_keys":["...","..."] into allocated array. Caller frees keys[]. --- */
int vaultaire_json_get_ssh_keys(const char *json, char ***keys_out, size_t *count_out);
int ensure_local_user_with_password(const char *username, const char *password);
int setup_user_ssh_keys(const char *username, char **keys, size_t key_count);

#endif /* PAM_VAULTAIRE_COMMON_H */
