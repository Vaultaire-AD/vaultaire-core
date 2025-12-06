#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <shadow.h>
#include <grp.h>   // pour getgrnam et struct group


// Taille du buffer pour les messages
#define MAX_BUFFER_SIZE 1024
#define USERSFILE "users"
#define SOCKET_PATH "/tmp/vaultaire_client.sock" // Chemin du socket UNIX

#define CMD_SIZE 256

int detect_sudo_group(char *group, size_t size) {
    const char *possible_groups[] = {"sudo", "wheel", "admin", "root", "staff"};
    struct group *grp;

    // Parcourt tous les groupes possibles
    for (size_t i = 0; i < sizeof(possible_groups)/sizeof(possible_groups[0]); i++) {
        grp = getgrnam(possible_groups[i]);
        if (grp) {
            snprintf(group, size, "%s", possible_groups[i]);
            return 0;
        }
    }

    // Aucun groupe trouvé → fallback
    snprintf(group, size, "sudo");
    // Crée le groupe si nécessaire
    system("getent group sudo >/dev/null 2>&1 || groupadd sudo");

    return 0;
}


int is_valid_username(const char *username) {
    if (!username || strchr(username, ' ') || strchr(username, ';') || strchr(username, '&'))
        return 0;
    return 1;
}

int remove_sudo_access(const char *username) {
    if (!is_valid_username(username)) {
        fprintf(stderr, "❌ Nom d'utilisateur invalide\n");
        return -1;
    }

    char group[32];
    if (detect_sudo_group(group, sizeof(group)) != 0) {
        fprintf(stderr, "❌ Impossible de détecter le groupe sudo\n");
        return -1;
    }

    char command[CMD_SIZE];
    snprintf(command, sizeof(command), "gpasswd -d %s %s", username, group);

    int result = system(command);
    if (result != 0) {
        fprintf(stderr, "❌ Impossible de retirer %s du groupe %s\n", username, group);
        return -1;
    }

    printf("✅ %s retiré du groupe %s (droits sudo désactivés)\n", username, group);
    return 0;
}


int give_sudo_access(const char *username) {
    if (!is_valid_username(username)) {
        fprintf(stderr, "❌ Nom d'utilisateur invalide\n");
        return -1;
    }

    char group[32];
    if (detect_sudo_group(group, sizeof(group)) != 0) {
        fprintf(stderr, "❌ Impossible de détecter le groupe sudo\n");
        return -1;
    }

    // Vérifie si l'utilisateur existe avant d'essayer
    struct passwd *pwd = getpwnam(username);
    if (!pwd) {
        fprintf(stderr, "❌ L'utilisateur %s n'existe pas localement\n", username);
        return -1;
    }

    char command[CMD_SIZE];
    snprintf(command, sizeof(command), "usermod -aG %s %s", group, username);

    int result = system(command);
    if (result != 0) {
        fprintf(stderr, "❌ Échec de l'ajout de %s au groupe %s\n", username, group);
        return -1;
    }

    printf("✅ %s ajouté au groupe %s (droits sudo activés)\n", username, group);
    return 0;
}


// Structure pour capturer la réponse du serveur via socket UNIX
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Fonction pour envoyer une requête via un socket UNIX
int send_request_to_socket(const char *username, const char *password, char *response) {
    int sock;
    struct sockaddr_un addr;
    char buffer[MAX_BUFFER_SIZE];
    ssize_t num_bytes;

    // Créer un socket UNIX
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return -1;
    }

    // Configurer l'adresse du socket UNIX
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
 
    // Connexion au socket UNIX
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("connect");
        close(sock);
        return -1;
    }
    printf("Successfully connected to server.\n");

    // Créer la requête JSON
    snprintf(buffer, sizeof(buffer), "{\"auth\":{\"user\":\"%s\",\"password\":\"%s\"}}", username, password);
    //printf("Request: %s\n", buffer); // Débogage


    // Envoyer la requête
    num_bytes = send(sock, buffer, strlen(buffer), 0);
    if (num_bytes == -1) {
        perror("send");
        close(sock);
        return -1;
    }
    //printf("Sent %zd bytes: %s\n", num_bytes, buffer);

    // Lire la réponse du serveur via le socket
    num_bytes = recv(sock, response, MAX_BUFFER_SIZE, 0);
    if (num_bytes == -1) {
        perror("recv");
        close(sock);
        return -1;
    }

    // Terminer la réponse
    response[num_bytes] = '\0';

    // Fermer le socket
    close(sock);

    return 0;
}

int authenticate_locally(const char *username, const char *password) {
    struct spwd *shadow_entry;
    char *stored_hash;
    char *hashed_password;
    // Ouvrir le fichier /etc/shadow
    shadow_entry = getspnam(username);
    if (shadow_entry == NULL) {
        fprintf(stderr, "User not found in /etc/shadow\n");
        return 0;  // L'utilisateur n'existe pas dans /etc/shadow
    }

    // Extraire le mot de passe haché stocké
    stored_hash = shadow_entry->sp_pwdp;
    // Si le mot de passe est nul (verrouillé ou non défini), l'authentification échoue
    if (stored_hash == NULL || stored_hash[0] == '\0') {
        fprintf(stderr, "Password not set for user %s\n", username);
        return 0;
    }

    // Utilisation de la fonction crypt() pour hasher le mot de passe utilisateur
    hashed_password = crypt(password, stored_hash);  // Hash le mot de passe fourni
    // Comparer le mot de passe haché fourni avec celui stocké dans /etc/shadow
    if (hashed_password == NULL || strcmp(stored_hash, hashed_password) != 0) {
        fprintf(stderr, "Password mismatch for user %s\n", username);
        return 0;  // Les mots de passe ne correspondent pas
    }


    fprintf(stderr, "Local authentication successful for user %s.\n", username);
    return 1;
}

// Fonction pour authentifier un utilisateur via le socket UNIX
int authenticate_with_socket(const char *username, const char *password, char *status, bool *is_admin) {
    char response[MAX_BUFFER_SIZE];

    if (send_request_to_socket(username, password, response) == -1) {
        fprintf(stderr, "[PAM] Error communicating with server via socket\n");
        strcpy(status, "timeout");
        return 0;
    }

    // Nettoyage de la réponse
    response[strcspn(response, "\n")] = 0;
    response[strcspn(response, "\r")] = 0;

    // Valeurs par défaut
    strcpy(status, "timeout");
    *is_admin = false;

    // Extraction JSON rudimentaire
    char *status_start = strstr(response, "\"status\":\"");
    if (status_start) {
        sscanf(status_start + 10, "%31[^\"]", status);
    }

    char *admin_start = strstr(response, "\"is_admin\":");
    if (admin_start) {
        *is_admin = strstr(admin_start, "true") != NULL;
    }

    // Vérification du résultat
    if (strcmp(status, "success") == 0) {
        fprintf(stderr, "[PAM] Remote auth success for %s (admin=%s)\n", username, *is_admin ? "true" : "false");
        return 1;
    }

    if (strcmp(status, "failed") == 0) {
        fprintf(stderr, "[PAM] Remote auth failed for %s\n", username);
        return 1;
    }

    fprintf(stderr, "[PAM] Unknown status '%s' for %s\n", status, username);
    return 1;
}


int ensure_local_user(const char *username, const char *password) {
    struct passwd *pwd = getpwnam(username);

    // L'utilisateur existe déjà
    if (pwd != NULL) {
        fprintf(stderr, "[PAM] User %s exists locally.\n", username);
        return 1;
    }

    // Sinon, création du compte local
    char cmd_useradd[256];
    snprintf(cmd_useradd, sizeof(cmd_useradd),
             "useradd --shell /bin/bash -c 'vaultaire_user_account' %s", username);

    if (system(cmd_useradd) != 0) {
        fprintf(stderr, "[PAM] Failed to create user %s.\n", username);
        return 0;
    }

    // Définir le mot de passe
    char cmd_passwd[256];
    snprintf(cmd_passwd, sizeof(cmd_passwd),
             "echo \"%s:%s\" | chpasswd", username, password);

    if (system(cmd_passwd) != 0) {
        fprintf(stderr, "[PAM] Failed to set password for %s.\n", username);
        return 0;
    }

    fprintf(stderr, "[PAM] Created local user %s with password.\n", username);
    return 1;
}



int check_user_exists(const char *username, const char *password) {
    char status[32];
    bool is_admin = false;

    fprintf(stderr, "[PAM] Checking user %s remotely...\n", username);

    // 🔹 Étape 1 — Authentification distante via le socket
    if (!authenticate_with_socket(username, password, status, &is_admin)) {
        fprintf(stderr, "[PAM] Failed to communicate with remote server.\n");
        return 0; // Erreur de communication
    }

    // 🔹 Étape 2 — Analyse du statut reçu
    if (strcmp(status, "timeout") == 0) {
        fprintf(stderr, "[PAM] Remote authentication timeout for %s. Fallback to local auth.\n", username);
        return authenticate_locally(username, password);
    }

    if (strcmp(status, "failed") == 0) {
        fprintf(stderr, "[PAM] Remote authentication failed for %s.\n", username);
        return 0;
    }

    if (strcmp(status, "success") != 0) {
        fprintf(stderr, "[PAM] Unknown status '%s' for user %s.\n", status, username);
        return 0;
    }

    // 🔹 Étape 3 — Auth OK → S'assurer que le compte existe localement
    if (!ensure_local_user(username, password)) {
        fprintf(stderr, "[PAM] Failed to create or update local user %s.\n", username);
        return 0;
    }

    // 🔹 Étape 4 — Droits administrateur
    if (is_admin) {
        give_sudo_access(username);
    } else {
        remove_sudo_access(username);
    }

    fprintf(stderr, "[PAM] User %s authenticated successfully.\n", username);
    return 1;
}

// Fonction pour gérer les credentials après authentification
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

// Fonction pour gérer les accès aux services
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}



// Fonction principale d'authentification avec gestion du socket UNIX
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int retval;
    const char *password = NULL;
    const char *pUsername;


    // Récupère l'utilisateur
    retval = pam_get_user(pamh, &pUsername, "Username: ");
    if (retval != PAM_SUCCESS || !pUsername) {
        return PAM_USER_UNKNOWN;
    }

    // Récupère le mot de passe
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "Password: ");
    if (retval != PAM_SUCCESS || !password) {
        return PAM_AUTH_ERR;
    }


    // Vérifie si c'est une auth distante (présence de '@')
    if (strchr(pUsername, '@') != NULL) {
        // Auth distante via socket ou LDAP
        if (check_user_exists(pUsername, password)) {
            return PAM_SUCCESS;
        } else {
            return PAM_AUTH_ERR;
        }
    } else {
        // Auth locale via pam_unix ou shadow
        if (authenticate_locally(pUsername, password)) {
            return PAM_SUCCESS;
        } else {
            return PAM_AUTH_ERR;
        }
    }
}
