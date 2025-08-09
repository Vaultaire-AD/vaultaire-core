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

// Taille du buffer pour les messages
#define MAX_BUFFER_SIZE 1024
#define USERSFILE "users"
#define SOCKET_PATH "/tmp/vaultaire_client.sock" // Chemin du socket UNIX

#define CMD_SIZE 256

int detect_sudo_group(char *group, size_t size) {
    FILE *fp = fopen("/etc/os-release", "r");
    if (!fp) return -1;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "ID=", 3) == 0) {
            char *id_value = line + 3;

            // Nettoyage des guillemets et sauts de ligne
            id_value[strcspn(id_value, "\n")] = 0; // remove newline
            if (id_value[0] == '"') {
                id_value++; // skip opening "
                char *quote = strchr(id_value, '"');
                if (quote) *quote = '\0';
            }

            if (strcmp(id_value, "rocky") == 0 || strcmp(id_value, "rhel") == 0) {
                snprintf(group, size, "wheel");
            } else {
                snprintf(group, size, "sudo");
            }

            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1; // ID not found
}


int is_valid_username(const char *username) {
    if (!username || strchr(username, ' ') || strchr(username, ';') || strchr(username, '&'))
        return 0;
    return 1;
}

int remove_sudo_access(const char *username) {
    char command[CMD_SIZE];
    char group[16];

    if (!is_valid_username(username)) {
        fprintf(stderr, "❌ Erreur : nom d'utilisateur invalide\n");
        return -1;
    }

    if (detect_sudo_group(group, sizeof(group)) != 0) {
        fprintf(stderr, "❌ Erreur : impossible de détecter le groupe sudo\n");
        return -1;
    }

    snprintf(command, CMD_SIZE, "gpasswd -d %s %s > /dev/null 2>&1", username, group);
    int result = system(command);

    if (result != 0) {
        fprintf(stderr, "❌ Erreur : suppression de %s du groupe %s échouée\n", username, group);
        return -1;
    }

    printf("✅ L'utilisateur %s n'a plus les permissions sudo (groupe %s).\n", username, group);
    return 0;
}

int give_sudo_access(const char *username) {
    char command[CMD_SIZE];
    char group[16];

    if (!is_valid_username(username)) {
        fprintf(stderr, "❌ Erreur : nom d'utilisateur invalide\n");
        return -1;
    }

    if (detect_sudo_group(group, sizeof(group)) != 0) {
        fprintf(stderr, "❌ Erreur : impossible de détecter le groupe sudo\n");
        return -1;
    }

    snprintf(command, CMD_SIZE, "usermod -aG %s %s > /dev/null 2>&1", group, username);
    int result = system(command);

    if (result != 0) {
        fprintf(stderr, "❌ Erreur : ajout de %s au groupe %s échoué\n", username, group);
        return -1;
    }

    printf("✅ L'utilisateur %s a maintenant les permissions sudo (groupe %s).\n", username, group);
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
int authenticate_with_socket(const char *username, const char *password, char *status) {
    char response[MAX_BUFFER_SIZE];

    if (send_request_to_socket(username, password, response) == -1) {
        fprintf(stderr, "Error communicating with server via socket\n");
        strcpy(status, "timeout");  // Timeout
        return 1;  // Échec
    }

    response[strcspn(response, "\n")] = 0;  // Enlever le retour à la ligne
    response[strcspn(response, "\r")] = 0;  // Enlever le retour chariot

    char extracted_status[32] = "timeout";  // Valeur par défaut
    bool extracted_is_admin = false;

    // 🔍 Extraction du "status"
    char *status_start = strstr(response, "\"status\":\"");
    if (status_start) {
        sscanf(status_start + 10, "%31[^\"]", extracted_status);
    }

    // 🔍 Extraction de "is_admin"
    char *admin_start = strstr(response, "\"is_admin\":");
    if (admin_start) {
        extracted_is_admin = strstr(admin_start, "true") != NULL;
    }

    // 🔄 Stocker les valeurs extraites dans les variables d'entrée
    strcpy(status, extracted_status);
    bool *is_admin = &extracted_is_admin;



    // Chercher le mot "status":"success" dans la réponse
    if (strcmp(status, "success") == 0) {
        printf("Response from server contains success\n");
        if (*is_admin){
            give_sudo_access(username);
        }else{
            remove_sudo_access(username);
        }
        strcpy(status, "success");
        return 1;  // Succès
    }
    // Chercher le mot "status":"failed" dans la réponse
    else if (strcmp(status, "failed") == 0) {
        printf("Response from server contains failed\n");
        strcpy(status, "failed");
        return 0;  // Échec
    }

    strcpy(status, "timeout");
    return 1;  // Échec par défaut si le statut est inconnu
}


int check_user_exists(const char *username, const char *password) {
    fprintf(stderr, "Checking user %s remotely...\n", username);

    char status[32];
    // Vérifier l'existence de l'utilisateur via le socket
    if (authenticate_with_socket(username, password, status)) {
        // Statut de succès
        if (strcmp(status, "success") == 0) {
            // Vérifier si l'utilisateur existe localement
            struct passwd *pwd = getpwnam(username);
            if (pwd != NULL) {
                fprintf(stderr, "User %s exists locally.\n", username);
                return 1;  // Utilisateur trouvé localement
            } else {
                // Créer un utilisateur local si nécessaire
                char command[256];
                snprintf(command, sizeof(command), "useradd --shell /bin/bash -c vaultaire_user_account %s", username);
                if (system(command) == 0) {
                    fprintf(stderr, "User %s created locally.\n", username);
                    
                    // Ajouter le mot de passe pour l'utilisateur créé
                    char password_command[256];
                    snprintf(password_command, sizeof(password_command), "echo \"%s:%s\" | chpasswd", username, password);
                    if (system(password_command) == 0) {
                        fprintf(stderr, "Password set for user %s.\n", username);
                        return 1;  // Succès
                    } else {
                        fprintf(stderr, "Failed to set password for user %s.\n", username);
                        return 0;  // Échec
                    }
                } else {
                    fprintf(stderr, "Failed to create user %s locally.\n", username);
                    return 0;  // Échec
                }
            }
        }
        // Si le statut est "failed"
        else if (strcmp(status, "failed") == 0) {
            fprintf(stderr, "Authentication failed for user %s.\n", username);
            return 0;  // Échec d'authentification
        }
        // Si le statut est "timeout"
        else if (strcmp(status, "timeout") == 0) {
            fprintf(stderr, "Authentication timeout for user %s.\n", username);
            if(!authenticate_locally(username, password)){
                return 0; 
            }else{
                return 1;
            }
            
        }
    } else {
        fprintf(stderr, "Failed to communicate with the server.\n");
        return 0;  // Échec de communication
    }
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

    // pam_get_user demande et accepte le nom d'utilisateur
    retval = pam_get_user(pamh, &pUsername, "Username: ");
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    // Vérification des utilisateurs root et adm_local → Authentification locale avec pam_unix
    if (strcmp(pUsername, "root") == 0 || strcmp(pUsername, "adm_local") == 0) {
        printf("Authentification locale pour %s\n", pUsername);

        // Récupérer le mot de passe via PAM
        retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "PASSWORD: ");
        if (retval != PAM_SUCCESS) {
            fprintf(stderr, "Can't get password\n");
            return PAM_PERM_DENIED;
        }

        // Appeler explicitement pam_unix.so
        if(!authenticate_locally(pUsername, password)){
            return PAM_PERM_DENIED;
        }else{
            return PAM_SUCCESS;
        }
    }

        // pam_get_authtok demande et accepte le mot de passe de l'utilisateur
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "PASSWORD: ");
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "Can't get password\n");
        return PAM_PERM_DENIED;
    }

    printf("Welcome %s\n", pUsername);

    // Vérifier si l'utilisateur existe localement ou sur le serveur distant
    if (!check_user_exists(pUsername, password)) {
        fprintf(stderr, "User does not exist in /etc/passwd\n");
        return PAM_PERM_DENIED; // L'utilisateur n'existe pas
    }else {
        return PAM_SUCCESS;
    }
}
