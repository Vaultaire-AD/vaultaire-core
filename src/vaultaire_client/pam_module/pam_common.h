/*
 * pam_common.h
 * Shared definitions and API for Vaultaire PAM modules (login, logout, SSH auth).
 * No PAM types here — pure C helpers for socket, logging, user/sudo, JSON.
 */

#ifndef PAM_VAULTAIRE_COMMON_H
#define PAM_VAULTAIRE_COMMON_H

#include <stddef.h>
#include <sys/types.h>
#include <stdbool.h>
#include <linux/limits.h>   // pour PATH_MAX

/* --- Constants (single source of truth) --- */

/* Canal vers l'agent.
 *
 * Etait /tmp/vaultaire_client.sock, en mode 0666. Le mot de passe en clair de
 * CHAQUE connexion y transite.
 *
 * /tmp est accessible en ecriture a tous : quand l'agent ne tournait pas — au
 * demarrage de la machine, apres un arret — n'importe quel compte local pouvait
 * creer le socket a cette place, recevoir les mots de passe, et repondre
 * {"status":"success","is_admin":true}. Ce module en tire directement un ajout
 * au groupe sudo : elevation locale vers root.
 *
 * /run/vaultaire est en 0700 root:root, le socket en 0600. */
#define VAULTAIRE_SOCKET_PATH    "/run/vaultaire/pam.sock"
#define VAULTAIRE_MAX_BUF        4096
#define VAULTAIRE_CMD_SIZE       512

/* --- Logging (syslog, LOG_AUTH) --- */
void vaultaire_log_info(const char *fmt, ...);
void vaultaire_log_err(const char *fmt, ...);


int is_vaultaire_user(const char *username);
/* --- UNIX socket: send JSON request; optionally receive response --- */
/* Returns 0 on success, -1 on error. If resp and resp_size > 0, response is written (null-terminated). */
int vaultaire_socket_send_recv(const char *request, char *resp, size_t resp_size);

/* Meme chose, sur un chemin de socket DONNE.
 *
 * Separee pour etre testable : verifier que la lecture est bien bouclee demande
 * un faux daemon qui repond en plusieurs morceaux, donc un socket a soi. */
int vaultaire_socket_send_recv_path(const char *chemin, const char *request,
                                     char *resp, size_t resp_size);
/* Fire-and-forget (e.g. close session); returns 0 on success, -1 on error. */
int vaultaire_socket_send(const char *request);

/* --- Controle du socket avant connexion --- */
/* Verifie que le socket appartient bien a l'agent : proprietaire attendu, mode
 * non permissif, et vrai socket plutot qu'un lien symbolique. Expose pour etre
 * testable. Retourne 1 si digne de confiance, 0 sinon. */
int socket_is_trustworthy(const char *path);

/* --- Username validation (injection-safe) --- */
bool vaultaire_is_valid_username(const char *username);

/* --- Sudo group: detect and add/remove user --- */
int vaultaire_detect_sudo_group(char *group, size_t gsize);
int vaultaire_add_user_to_sudo_group(const char *username);
int vaultaire_remove_user_from_sudo_group(const char *username);

/* --- Phase « account » : le compte peut-il encore ouvrir une session ? --- */
/* Lit l'etat LOCAL : verrouillage, expiration du compte, expiration du mot de
 * passe au-dela du delai de grace, shell interdit. Aucun appel reseau — cette
 * phase s'execute a chaque connexion, et la faire dependre du core
 * verrouillerait tout le parc en cas de coupure.
 * Retourne 0 si la session peut s'ouvrir, -1 sinon. */
int vaultaire_local_account_usable(const char *username);

/* --- Construction de requetes JSON --- */
/* Echappe une chaine pour l'inserer dans du JSON (RFC 8259 s7).
 * Retourne 0, ou -1 si la place manque — jamais une chaine tronquee. */
int vaultaire_json_escape(const char *src, char *out, size_t out_size);

/* Assemble la requete d'authentification, champs echappes. Point unique de
 * construction : les deux modules PAM l'assemblaient chacun de leur cote, avec
 * le meme defaut recopie. */
int vaultaire_build_check_request(const char *username, const char *password,
                                  char *out, size_t out_size);

/* --- Minimal JSON helpers (no external lib) --- */
/* Get string value for key "key" into out (at most out_size bytes). Returns 0 on success. */
int vaultaire_json_get_string(const char *json, const char *key, char *out, size_t out_size);
/* Get boolean for key "key". Returns 0 on success, -1 if not found. */
int vaultaire_json_get_bool(const char *json, const char *key, bool *out);

/* --- SSH keys array: parse "ssh_keys":["...","..."] into allocated array. Caller frees keys[]. ---
 *
 * Rend 0 SEULEMENT si le tableau a ete lu en entier — un tableau vide compte
 * pour un succes, avec *count_out a 0. Rend -1 si le champ manque, s'il ne
 * porte pas un tableau, ou si la reponse est coupee.
 *
 * Cette distinction est le coeur du contrat : l'appelant reecrit
 * authorized_keys, donc « plus aucune cle » (ecrire un fichier vide) et
 * « reponse illisible » (ne rien toucher) ne peuvent pas se ressembler. */
int vaultaire_json_get_ssh_keys(const char *json, char ***keys_out, size_t *count_out);
int ensure_local_user_with_password(const char *username, const char *password);
int setup_user_ssh_keys(const char *username, char **keys, size_t key_count);

/* Ecrit authorized_keys dans un repertoire personnel DONNE.
 * Separee pour etre testable : un test du garde-fou contre les liens
 * symboliques doit fournir son propre repertoire, faute de quoi la fonction
 * renonce avant d'ecrire et le test ne mesure rien. */
int vaultaire_write_ssh_keys(const char *home, uid_t uid, gid_t gid,
                              char **keys, size_t key_count);

#endif /* PAM_VAULTAIRE_COMMON_H */
