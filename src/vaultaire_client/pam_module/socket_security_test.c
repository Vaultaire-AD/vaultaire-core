/*
 * socket_security_test.c
 *
 * Tests du garde-fou qui protege le canal PAM.
 *
 * ============================================================================
 * LA FAILLE DONT CES TESTS PROTEGENT
 * ============================================================================
 *
 * Le socket vivait dans /tmp, en mode 0666. Le mot de passe en clair de chaque
 * connexion y transite.
 *
 * /tmp etant accessible en ecriture a tous, n'importe quel compte local pouvait
 * creer le socket a cette place quand l'agent ne tournait pas — au demarrage de
 * la machine, apres un arret — capturer les mots de passe et repondre :
 *
 *     {"status":"success","is_admin":true}
 *
 * Ce module en tirait directement un ajout au groupe sudo. Elevation vers root.
 *
 * ============================================================================
 * CE QUE CES TESTS VERIFIENT
 * ============================================================================
 *
 * socket_is_trustworthy est la SECONDE barriere — la premiere etant le
 * repertoire /run/vaultaire en 0700 root:root, qu'un non-root ne peut pas
 * franchir. Elle existe pour le jour ou la premiere cede : repertoire recree a
 * la main, image deployee avec le mauvais mode.
 *
 * Chaque cas ci-dessous correspond a une facon concrete d'usurper l'agent.
 *
 * ============================================================================
 * POURQUOI VAULTAIRE_SOCKET_OWNER
 * ============================================================================
 *
 * Le controle exige que le socket appartienne a root. Aucune machine de
 * developpement ne permet de creer un fichier appartenant a root sans etre root.
 *
 * Les tests se compilent donc avec -DVAULTAIRE_SOCKET_OWNER=<uid courant>, ce
 * qui deplace la cible sans changer la LOGIQUE : « appartient a qui il faut »
 * reste teste, y compris le cas « appartient a quelqu'un d'autre ».
 *
 * La constante n'est surchargeable qu'a la compilation. Rien — ni variable
 * d'environnement, ni fichier — ne peut la changer sur une machine deployee.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "pam_common.h"

static int echecs = 0;

static void verifier(const char *quoi, int condition) {
    printf("  [%s] %s\n", condition ? "PASS" : "FAIL", quoi);
    if (!condition) {
        echecs++;
    }
}

/* Cree un vrai socket unix a l'emplacement demande. */
static int creer_socket(const char *chemin, mode_t mode) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, chemin, sizeof(addr.sun_path) - 1);

    unlink(chemin);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (chmod(chemin, mode) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    char base[] = "/tmp/vltsockXXXXXX";
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 2;
    }

    char sock_ok[128], sock_large[128], fichier[128], lien[128], absent[128];
    snprintf(sock_ok, sizeof(sock_ok), "%s/ok.sock", base);
    snprintf(sock_large, sizeof(sock_large), "%s/large.sock", base);
    snprintf(fichier, sizeof(fichier), "%s/pas_un_socket", base);
    snprintf(lien, sizeof(lien), "%s/lien.sock", base);
    snprintf(absent, sizeof(absent), "%s/absent.sock", base);

    /* Deux modes d'execution.
     *
     * En mode « usurpation », le controle a ete compile pour attendre un AUTRE
     * proprietaire que celui des fichiers crees ici. Les cas nominaux echouent
     * alors par construction : on ne joue que l'assertion qui a du sens. */
    const int mode_usurpation = getenv("VAULTAIRE_TEST_ATTEND_AUTRE_UID") != NULL;

    int fd_ok = creer_socket(sock_ok, 0600);
    int fd_large = -1;

    if (mode_usurpation) {
        /* Le coeur de l'attaque : le socket existe, c'est bien un socket, son
         * mode est correct — mais il n'appartient pas a l'agent. */
        verifier("un socket appartenant a un AUTRE utilisateur est REFUSE",
                 fd_ok >= 0 && socket_is_trustworthy(sock_ok) == 0);
        goto fin;
    }

    /* --- Cas nominal : vrai socket, bon proprietaire, mode 0600 ------------ */
    verifier("un socket 0600 du bon proprietaire est accepte",
             fd_ok >= 0 && socket_is_trustworthy(sock_ok) == 1);

    /* --- Mode trop large : c'est le 0666 d'origine ------------------------- */
    fd_large = creer_socket(sock_large, 0666);
    verifier("un socket en 0666 est REFUSE (le mode d'origine)",
             fd_large >= 0 && socket_is_trustworthy(sock_large) == 0);

    /* Le groupe seul suffit a disqualifier : un socket 0620 laisse ecrire tout
     * membre du groupe, ce qui suffit a intercepter les mots de passe. */
    if (fd_large >= 0) {
        chmod(sock_large, 0620);
        verifier("un socket accessible en ecriture au GROUPE est REFUSE",
                 socket_is_trustworthy(sock_large) == 0);
        chmod(sock_large, 0602);
        verifier("un socket accessible en ecriture aux AUTRES est REFUSE",
                 socket_is_trustworthy(sock_large) == 0);
    }

    /* --- Pas un socket ----------------------------------------------------- */
    FILE *f = fopen(fichier, "w");
    if (f) {
        fputs("je ne suis pas un socket\n", f);
        fclose(f);
    }
    verifier("un fichier ordinaire a la place du socket est REFUSE",
             socket_is_trustworthy(fichier) == 0);

    /* --- Lien symbolique vers un socket legitime ---------------------------
     *
     * Le cas que lstat attrape et que stat laisserait passer. Un attaquant qui
     * peut poser un lien choisit la cible : il redirige les mots de passe vers
     * son propre socket, tout en presentant une chaine de controle valide.
     */
    if (symlink(sock_ok, lien) == 0) {
        verifier("un lien symbolique vers un socket valide est REFUSE (lstat, pas stat)",
                 socket_is_trustworthy(lien) == 0);
    } else {
        verifier("creation du lien symbolique de test", 0);
    }

    /* --- Socket absent ----------------------------------------------------- */
    verifier("un chemin inexistant est REFUSE",
             socket_is_trustworthy(absent) == 0);

fin:
    if (fd_ok >= 0) close(fd_ok);
    if (fd_large >= 0) close(fd_large);
    unlink(sock_ok);
    unlink(sock_large);
    unlink(fichier);
    unlink(lien);
    rmdir(base);

    printf("\n%s\n", echecs ? "DES TESTS ECHOUENT" : "tous les tests passent");
    return echecs ? 1 : 0;
}
