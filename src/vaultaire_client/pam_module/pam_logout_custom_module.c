#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>


#define SOCKET_PATH "/tmp/vaultaire_client.sock"  // Remplace par ton vrai chemin
#define MAX_BUFFER_SIZE 1024

int send_close_request_to_socket(const char *username) {
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

    // Créer la requête JSON de fermeture
    snprintf(buffer, sizeof(buffer), "{\"close\":{\"user\":\"%s\",\"action\":\"S_close\"}}", username);


    // Envoyer la requête
    num_bytes = send(sock, buffer, strlen(buffer), 0);
    if (num_bytes == -1) {
        perror("send");
        close(sock);
        return -1;
    }

    printf("Requête de fermeture envoyée pour l'utilisateur: %s\n", username);

    // Fermer le socket
    close(sock);

    return 0;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    
    if (pam_get_item(pamh, PAM_USER, (const void **)&username) != PAM_SUCCESS || username == NULL) {
        syslog(LOG_ERR, "PAM: Impossible de récupérer le nom d'utilisateur");
        return PAM_SESSION_ERR;
    }

    syslog(LOG_INFO, "PAM: Fermeture de session pour l'utilisateur %s", username);

    // Envoyer la requête de fermeture au serveur via le socket UNIX
    if (send_close_request_to_socket(username) == -1) {
        syslog(LOG_ERR, "PAM: Échec de l'envoi de la requête de fermeture pour %s", username);
    }

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("Session opened successfully.\n");
    return PAM_SUCCESS;
}
