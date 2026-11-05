/*
 * chrono_test.c — TO-DO 199 : le module n'ecrit ses durees qu'en mode debug.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "pam_common.h"

static int echecs = 0;
static void ok(const char *quoi, int cond) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", quoi);
    if (!cond) echecs++;
}

static long taille(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 ? (long)st.st_size : -1;
}

int main(void) {
    printf("--- TO-DO 199 : chronometrage du module ---\n");
    char rep[] = "/tmp/vltchronoXXXXXX";
    if (!mkdtemp(rep)) { ok("repertoire de test", 0); return 1; }
    char chemin[256];
    snprintf(chemin, sizeof(chemin), "%s/connexions.log", rep);

    struct vaultaire_chrono c;
    memset(&c, 0, sizeof(c));
    vaultaire_chrono_marquer(&c.debut);
    usleep(120000);                       /* la « saisie » */
    vaultaire_chrono_marquer(&c.saisie);
    usleep(60000);                        /* l'attente de l'agent */
    vaultaire_chrono_marquer(&c.reponse);

    vaultaire_chrono_rapport_vers(chemin, &c, "sshd", "alice@dom",
                                  "{\"status\":\"success\",\"is_admin\":false}", "success");
    ok("sans \"chrono\" dans la reponse : rien n'est ecrit", taille(chemin) == -1);

    vaultaire_chrono_rapport_vers(chemin, &c, "sshd", "alice@dom",
                                  "{\"status\":\"success\",\"chrono\":false}", "success");
    ok("\"chrono\": false : rien n'est ecrit", taille(chemin) == -1);

    vaultaire_chrono_rapport_vers(chemin, &c, "sshd", "alice@dom",
                                  "{\"status\":\"success\",\"chrono\":true,\"ssh_keys\":[]}", "success");
    char ligne[512] = {0};
    FILE *f = fopen(chemin, "r");
    if (f) { if (!fgets(ligne, sizeof(ligne), f)) ligne[0] = 0; fclose(f); }
    printf("       %s", ligne);

    long saisie = -1, attente = -1;
    const char *p = strstr(ligne, "saisie ");
    if (p) saisie = strtol(p + 7, NULL, 10);
    p = strstr(ligne, "attente agent ");
    if (p) attente = strtol(p + 14, NULL, 10);
    ok("\"chrono\": true : la ligne est ecrite, compte et service nommes",
       strstr(ligne, " pam alice@dom [sshd] success : ") != NULL);
    ok("la saisie est mesuree (~120 ms)", saisie >= 110 && saisie < 400);
    ok("l'attente de l'agent est mesuree (~60 ms)", attente >= 50 && attente < 300);
    ok("l'heure porte les millisecondes", strlen(ligne) > 24 && ligne[19] == '.');
    struct stat st;
    ok("le journal est en 0600", stat(chemin, &st) == 0 && (st.st_mode & 0777) == 0600);

    unlink(chemin); rmdir(rep);
    printf("\n%s\n", echecs ? "DES TESTS ECHOUENT" : "tous les tests passent");
    return echecs ? 1 : 0;
}
