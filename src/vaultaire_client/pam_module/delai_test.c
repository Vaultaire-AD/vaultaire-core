/*
 * delai_test.c — TO-DO 198 : le module n'attend pas l'agent sans fin.
 *
 * Compile avec -DVAULTAIRE_DELAI_REPONSE_MS=400 (run_tests.sh) : un faux agent
 * accepte la connexion et ne repond jamais, puis un autre rend un octet toutes
 * les 150 ms sans jamais fermer. Dans les deux cas, la lecture doit s'arreter
 * a l'echeance — la seconde est celle que SO_RCVTIMEO laisserait passer.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "pam_common.h"

static int echecs = 0;
static void ok(const char *quoi, int cond) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", quoi);
    if (!cond) echecs++;
}

static long ms_depuis(const struct timespec *d) {
    struct timespec m;
    clock_gettime(CLOCK_MONOTONIC, &m);
    return (m.tv_sec - d->tv_sec) * 1000L + (m.tv_nsec - d->tv_nsec) / 1000000L;
}

/* Lance un faux agent ; goutte : 0 = muet, 1 = un octet toutes les 150 ms. */
static pid_t faux_agent(const char *chemin, int goutte) {
    unlink(chemin);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, chemin, sizeof(a.sun_path) - 1);
    if (srv < 0 || bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(srv, 1) != 0) {
        return -1;
    }
    pid_t f = fork();
    if (f == 0) {
        int c = accept(srv, NULL, NULL);
        for (int i = 0; i < 100 && c >= 0; i++) {
            if (goutte && write(c, " ", 1) < 0) break;
            usleep(150000);
        }
        _exit(0);
    }
    close(srv);
    return f;
}

static void essai(const char *nom, int goutte) {
    char chemin[128];
    snprintf(chemin, sizeof(chemin), "/tmp/vlt-delai-%d-%d.sock", (int)getpid(), goutte);
    pid_t f = faux_agent(chemin, goutte);
    if (f < 0) { ok("preparation du faux agent", 0); return; }
    usleep(50000);

    struct timespec d;
    clock_gettime(CLOCK_MONOTONIC, &d);
    char resp[4096] = {0};
    int r = vaultaire_socket_send_recv_path(chemin, "{\"check\":{}}", resp, sizeof(resp));
    long duree = ms_depuis(&d);

    char quoi[256];
    snprintf(quoi, sizeof(quoi), "%s : abandon (r=%d) en %ld ms, echeance %d ms",
             nom, r, duree, VAULTAIRE_DELAI_REPONSE_MS);
    ok(quoi, r == -1 && duree >= VAULTAIRE_DELAI_REPONSE_MS - 50
                 && duree < VAULTAIRE_DELAI_REPONSE_MS + 1000);

    kill(f, SIGKILL);
    int st; waitpid(f, &st, 0);
    unlink(chemin);
}

int main(void) {
    printf("--- TO-DO 198 : echeance de la reponse de l'agent ---\n");
    essai("agent muet", 0);
    essai("agent qui rend un octet toutes les 150 ms", 1);
    printf("\n%s\n", echecs ? "DES TESTS ECHOUENT" : "tous les tests passent");
    return echecs ? 1 : 0;
}
