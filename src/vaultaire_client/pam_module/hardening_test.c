/*
 * hardening_test.c
 *
 * Tests des corrections des points MAJEURS de l'audit.
 *
 *   4  authorized_keys ecrit en root sans protection contre les liens
 *   5  mot de passe injecte dans du JSON sans echappement
 *   6  injection shell dans la gestion du groupe sudo
 *
 * Chaque cas correspond a une exploitation concrete, pas a une propriete
 * abstraite : c'est ce qui permet de verifier que le test echoue bien sur le
 * code d'avant.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <pwd.h>

#include "pam_common.h"

static int echecs = 0;
static void ok(const char *quoi, int cond) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", quoi);
    if (!cond) echecs++;
}

int main(void) {
    printf("--- Point 5 : echappement JSON ---\n");

    char out[512], req[4096];

    vaultaire_json_escape("simple", out, sizeof(out));
    ok("texte ordinaire inchange", strcmp(out,"simple")==0);

    vaultaire_json_escape("a\"b", out, sizeof(out));
    ok("guillemet echappe", strcmp(out,"a\\\"b")==0);

    vaultaire_json_escape("a\\b", out, sizeof(out));
    ok("barre oblique inverse echappee", strcmp(out,"a\\\\b")==0);

    vaultaire_json_escape("a\nb", out, sizeof(out));
    ok("saut de ligne echappe", strcmp(out,"a\\nb")==0);

    vaultaire_json_escape("a\x01z", out, sizeof(out));
    ok("caractere de controle en \\u00XX", strcmp(out,"a\\u0001z")==0);

    /* accents : octets >= 0x80 laisses intacts, sinon le mot de passe change */
    vaultaire_json_escape("mot\xc3\xa9passe", out, sizeof(out));
    ok("UTF-8 preserve", strcmp(out,"mot\xc3\xa9passe")==0);

    /* place insuffisante : ECHEC, jamais une chaine tronquee */
    char petit[4];
    ok("place insuffisante -> erreur", vaultaire_json_escape("abcdefgh", petit, sizeof(petit))!=0);

    /* LE cas : le mot de passe avec guillemet doit produire un JSON VALIDE */
    vaultaire_build_check_request("admin@dom", "pa\"ss", req, sizeof(req));
    ok("requete avec guillemet bien formee",
       strcmp(req,"{\"check\":{\"user\":\"admin@dom\",\"password\":\"pa\\\"ss\"}}")==0);
    printf("       %s\n", req);

    /* injection : le mot de passe ne doit pas pouvoir ajouter un champ */
    vaultaire_build_check_request("attaquant@dom", "x\",\"user\":\"admin@dom", req, sizeof(req));
    ok("injection neutralisee (un seul champ user)",
       strstr(req,"\"user\":\"attaquant@dom\"")!=NULL &&
       strstr(req,"\",\"user\":\"admin@dom\"")==NULL);
    printf("       %s\n", req);

    
    printf("\n--- Point 6 : liste blanche des noms ---\n");

    ok("alice@dom accepte",            vaultaire_is_valid_username("alice@dom"));
    ok("point tiret souligne acceptes",vaultaire_is_valid_username("a.b-c_d@dom"));
    /* Les injections que l'ancienne liste noire laissait passer */
    ok("$(id) REFUSE",   !vaultaire_is_valid_username("alice$(id)@dom"));
    ok("backtick REFUSE",!vaultaire_is_valid_username("alice`id`@dom"));
    ok("pipe REFUSE",    !vaultaire_is_valid_username("alice|id@dom"));
    ok("guillemet REFUSE",!vaultaire_is_valid_username("alice\"@dom"));
    ok("apostrophe REFUSE",!vaultaire_is_valid_username("alice'@dom"));
    ok("parentheses REFUSE",!vaultaire_is_valid_username("alice()@dom"));
    ok("chevron REFUSE", !vaultaire_is_valid_username("alice>x@dom"));
    ok("etoile REFUSE",  !vaultaire_is_valid_username("alice*@dom"));
    /* Ce que l'ancienne refusait deja */
    ok("espace REFUSE",  !vaultaire_is_valid_username("alice bob"));
    ok("point-virgule REFUSE",!vaultaire_is_valid_username("alice;id"));
    ok("slash REFUSE",   !vaultaire_is_valid_username("alice/x"));
    /* Nouveaux */
    ok("tiret initial REFUSE (serait pris pour une option)",
       !vaultaire_is_valid_username("-rf@dom"));
    ok("vide REFUSE",    !vaultaire_is_valid_username(""));
    ok("NULL REFUSE",    !vaultaire_is_valid_username(NULL));
    
    printf("\n--- Point 4 : ecriture des cles, liens symboliques ---\n");

    /* On fabrique un repertoire personnel a nous, et on y pose un piege :
     * authorized_keys est un LIEN vers une cible sensible.
     *
     * On appelle vaultaire_write_ssh_keys et non setup_user_ssh_keys : cette
     * derniere resout le compte dans /etc/passwd et renonce avant d'ecrire pour
     * un nom inconnu — le test passerait alors au vert SANS RIEN MESURER, ce
     * qui s'est effectivement produit au premier essai.
     */
    char base[] = "/tmp/vltkeysXXXXXX";
    if (mkdtemp(base)) {
        char sshdir[256], lien[320], cible[320], reel[320];
        snprintf(sshdir, sizeof(sshdir), "%s/.ssh", base);
        snprintf(cible,  sizeof(cible),  "%s/cible-sensible", base);
        snprintf(lien,   sizeof(lien),   "%s/authorized_keys", sshdir);
        snprintf(reel,   sizeof(reel),   "%s/authorized_keys", sshdir);

        mkdir(sshdir, 0700);
        FILE *c = fopen(cible, "w");
        if (c) { fputs("CONTENU D ORIGINE\n", c); fclose(c); }
        ok("preparation du piege (authorized_keys est un lien)", symlink(cible, lien) == 0);

        char *cles[] = { (char *)"ssh-ed25519 AAAAtest cle-legitime" };
        vaultaire_write_ssh_keys(base, getuid(), getgid(), cles, 1);

        /* LE test : la cible du lien ne doit pas avoir ete touchee. */
        char tampon[64] = {0};
        FILE *v = fopen(cible, "r");
        if (v) { if (fgets(tampon, sizeof(tampon), v) == NULL) tampon[0] = 0; fclose(v); }
        ok("la cible du lien n'a PAS ete ecrasee",
           strncmp(tampon, "CONTENU D ORIGINE", 17) == 0);

        /* Et le fichier reel doit porter les cles, en 0600. */
        struct stat st;
        int existe = (lstat(reel, &st) == 0);
        ok("authorized_keys existe et n'est plus un lien",
           existe && S_ISREG(st.st_mode));
        ok("authorized_keys est en 0600 des sa creation",
           existe && (st.st_mode & 0777) == 0600);

        char ligne[128] = {0};
        FILE *k = fopen(reel, "r");
        if (k) { if (fgets(ligne, sizeof(ligne), k) == NULL) ligne[0] = 0; fclose(k); }
        ok("la cle legitime a bien ete ecrite",
           strstr(ligne, "cle-legitime") != NULL);

        /* Une cle contenant un saut de ligne en fabriquerait DEUX, dont la
         * seconde serait choisie par celui qui l'a fournie. */
        char *malveillante[] = {
            (char *)"ssh-ed25519 AAAAok bonne",
            (char *)"ssh-ed25519 AAAAx x\nssh-ed25519 AAAAinjectee attaquant"
        };
        vaultaire_write_ssh_keys(base, getuid(), getgid(), malveillante, 2);
        int injectee = 0;
        FILE *r2 = fopen(reel, "r");
        if (r2) {
            char l[256];
            while (fgets(l, sizeof(l), r2)) {
                if (strstr(l, "injectee")) injectee = 1;
            }
            fclose(r2);
        }
        ok("une cle contenant un saut de ligne est ecartee", !injectee);

        unlink(reel); unlink(cible); rmdir(sshdir); rmdir(base);
    }

    /* Le repertoire personnel LUI-MEME remplace par un lien.
     *
     * Cas reel : /home/<user> pointe vers /root ou vers le home d'un autre.
     * Sans O_NOFOLLOW sur la premiere ouverture, on ecrirait dans la cible.
     * Ce cas n'etait pas couvert au premier essai — revele par la mutation. */
    char base2[] = "/tmp/vlthomeXXXXXX";
    if (mkdtemp(base2)) {
        char vraidir[256], faux[256], temoin[320];
        snprintf(vraidir, sizeof(vraidir), "%s/reel", base2);
        snprintf(faux,    sizeof(faux),    "%s/piege", base2);
        snprintf(temoin,  sizeof(temoin),  "%s/reel/.ssh/authorized_keys", base2);

        mkdir(vraidir, 0700);
        ok("preparation : le home est un lien", symlink(vraidir, faux) == 0);

        char *cles2[] = { (char *)"ssh-ed25519 AAAAtest via-lien" };
        int r = vaultaire_write_ssh_keys(faux, getuid(), getgid(), cles2, 1);

        ok("un home qui est un lien symbolique est REFUSE", r == 0);
        ok("rien n'a ete ecrit dans la cible du lien", access(temoin, F_OK) != 0);

        unlink(faux); rmdir(vraidir); rmdir(base2);
    }

    printf("\n--- Point 9 : les cles revoquees ne doivent pas survivre ---\n");

    /* Le fichier est REECRIT a chaque connexion a partir de ce que le serveur
     * rend. Encore faut-il savoir distinguer « ce compte n'a plus aucune cle »
     * de « je n'ai pas su lire la reponse » : le premier doit vider le fichier,
     * le second ne doit toucher a rien.
     *
     * L'ancienne version rendait 0 dans les deux cas, et l'appelant ajoutait un
     * « && keys » qui sautait l'ecriture des que la liste etait vide. Revoquer
     * la DERNIERE cle d'un compte etait donc la seule revocation sans effet :
     * l'ancien authorized_keys restait en place et ouvrait encore la session. */
    {
        char **k = NULL;
        size_t n = 99;

        /* Tableau vide : succes, zero cle. C'est ce qui declenche l'effacement. */
        int r = vaultaire_json_get_ssh_keys(
            "{\"status\":\"success\",\"is_admin\":false,\"ssh_keys\":[]}", &k, &n);
        ok("tableau vide : lecture REUSSIE (et non 'illisible')", r == 0);
        ok("tableau vide : zero cle rendue", n == 0);
        free(k); k = NULL; n = 99;

        /* Champ absent : la reponse n'est pas exploitable. */
        r = vaultaire_json_get_ssh_keys("{\"status\":\"success\",\"is_admin\":true}", &k, &n);
        ok("champ ssh_keys absent : REFUSE", r == -1);
        free(k); k = NULL; n = 99;

        /* null : ce que produit un encodeur JSON sur une tranche non
         * initialisee. Le prendre pour une liste vide effacerait les cles d'un
         * utilisateur en regle. */
        r = vaultaire_json_get_ssh_keys("{\"status\":\"success\",\"ssh_keys\":null}", &k, &n);
        ok("ssh_keys a null : REFUSE", r == -1);
        free(k); k = NULL; n = 99;

        /* Reponse coupee au milieu du tableau : le socket a rendu un morceau. */
        r = vaultaire_json_get_ssh_keys("{\"ssh_keys\":[\"ssh-ed25519 AAAAa a\",\"ssh-ed", &k, &n);
        ok("tableau non ferme (reponse coupee) : REFUSE", r == -1);
        ok("rien n'est rendu sur une lecture partielle", n == 0 && k == NULL);
        free(k); k = NULL; n = 99;

        /* Cas nominal, pour que les refus ci-dessus ne passent pas simplement
         * parce que la fonction refuserait tout. */
        r = vaultaire_json_get_ssh_keys(
            "{\"ssh_keys\":[\"ssh-ed25519 AAAAa poste\",\"ssh-ed25519 AAAAb portable\"]}", &k, &n);
        ok("deux cles bien formees : lues", r == 0 && n == 2);
        ok("la premiere cle est intacte",
           n == 2 && strcmp(k[0], "ssh-ed25519 AAAAa poste") == 0);
        for (size_t i = 0; i < n; i++) free(k[i]);
        free(k);
    }

    /* Et l'ecriture elle-meme : zero cle doit VIDER un fichier existant. */
    char base3[] = "/tmp/vltrevokXXXXXX";
    if (mkdtemp(base3)) {
        char sshdir3[256], reel3[320];
        snprintf(sshdir3, sizeof(sshdir3), "%s/.ssh", base3);
        snprintf(reel3,   sizeof(reel3),   "%s/authorized_keys", sshdir3);
        mkdir(sshdir3, 0700);

        FILE *v = fopen(reel3, "w");
        if (v) { fputs("ssh-ed25519 AAAAvieille portable-vole\n", v); fclose(v); }
        ok("preparation : une ancienne cle est en place", access(reel3, F_OK) == 0);

        vaultaire_write_ssh_keys(base3, getuid(), getgid(), NULL, 0);

        struct stat st3;
        int vide = (stat(reel3, &st3) == 0 && st3.st_size == 0);
        ok("zero cle VIDE authorized_keys (revocation totale effective)", vide);

        /* Une cle, puis une autre : la premiere ne doit pas subsister. */
        char *avant[] = { (char *)"ssh-ed25519 AAAAancienne poste" };
        char *apres[] = { (char *)"ssh-ed25519 AAAAnouvelle poste" };
        vaultaire_write_ssh_keys(base3, getuid(), getgid(), avant, 1);
        vaultaire_write_ssh_keys(base3, getuid(), getgid(), apres, 1);

        int trouve_ancienne = 0, trouve_nouvelle = 0;
        FILE *r3 = fopen(reel3, "r");
        if (r3) {
            char l[256];
            while (fgets(l, sizeof(l), r3)) {
                if (strstr(l, "AAAAancienne")) trouve_ancienne = 1;
                if (strstr(l, "AAAAnouvelle")) trouve_nouvelle = 1;
            }
            fclose(r3);
        }
        ok("la cle remplacee a disparu du fichier", !trouve_ancienne);
        ok("la nouvelle cle est bien la", trouve_nouvelle);

        unlink(reel3); rmdir(sshdir3); rmdir(base3);
    }

    printf("\n--- Point 12 : lecture socket en plusieurs segments ---\n");

    /* Un faux daemon qui repond en DEUX morceaux, avec une pause entre les deux.
     *
     * C'est le cas reel : la reponse porte les cles SSH, et une seule cle
     * RSA-4096 en base64 depasse le kilo-octet. Un unique recv rendait alors un
     * JSON tronque — le champ status restait vide et l'authentification etait
     * refusee, sans que rien ne designe la cause. */
    {
        char chemin[128];
        snprintf(chemin, sizeof(chemin), "/tmp/vlt-recv-%d.sock", (int)getpid());
        unlink(chemin);

        int srv = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un a;
        memset(&a, 0, sizeof(a));
        a.sun_family = AF_UNIX;
        strncpy(a.sun_path, chemin, sizeof(a.sun_path) - 1);

        if (srv >= 0 && bind(srv, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(srv, 1) == 0) {
            pid_t f = fork();
            if (f == 0) {
                int c = accept(srv, NULL, NULL);
                if (c >= 0) {
                    char poubelle[4096];
                    recv(c, poubelle, sizeof(poubelle), MSG_DONTWAIT);
                    /* Premier morceau, pause, second morceau. La pause force le
                     * decoupage : sans elle, le noyau pourrait tout livrer d'un
                     * coup et le test ne mesurerait rien. */
                    const char *m1 = "{\"status\":\"suc";
                    const char *m2 = "cess\",\"is_admin\":false}";
                    if (write(c, m1, strlen(m1)) < 0) { }
                    usleep(120000);
                    if (write(c, m2, strlen(m2)) < 0) { }
                    close(c);
                }
                close(srv);
                _exit(0);
            }
            close(srv);
            usleep(80000);

            /* On appelle le vrai code de lecture, sur notre socket. */
            char reponse[4096] = {0};
            vaultaire_socket_send_recv_path(chemin, "{\"check\":{}}", reponse, sizeof(reponse));

            char statut[32] = {0};
            vaultaire_json_get_string(reponse, "status", statut, sizeof(statut));
            ok("la reponse arrivee en deux segments est complete",
               strcmp(statut, "success") == 0);
            if (strcmp(statut, "success") != 0) {
                printf("       recu : %s\n", reponse);
            }

            int st; waitpid(f, &st, 0);
        }
        unlink(chemin);
    }

    printf("\n--- Point 19 : reconnaissance d'un compte du domaine ---\n");

    /* L'ancienne version rendait vrai des qu'un « @ » apparaissait. Un compte
     * LOCAL en comportant un etait alors envoye au daemon, et son mot de passe
     * local reecrit. */
    ok("alice@vaultaire.fr est un compte du domaine",
       is_vaultaire_user("alice@vaultaire.fr"));
    ok("root n'en est pas un",              !is_vaultaire_user("root"));
    ok("alice@localhost n'en est pas un (pas de point)",
       !is_vaultaire_user("alice@localhost"));
    ok("@dom.fr refuse (nom vide)",          !is_vaultaire_user("@dom.fr"));
    ok("alice@ refuse (domaine vide)",       !is_vaultaire_user("alice@"));
    ok("a@b@c.fr refuse (deux arobases)",    !is_vaultaire_user("a@b@c.fr"));
    ok("chaine vide refusee",                !is_vaultaire_user(""));
    ok("NULL refuse",                        !is_vaultaire_user(NULL));

    printf("\n--- Point 8 : etat local du compte ---\n");

    ok("un nom invalide est refuse",
       vaultaire_local_account_usable("alice$(id)@dom") != 0);
    /* Un compte du domaine encore inexistant doit PASSER : c'est le cas d'une
     * premiere connexion, ou le compte local sera cree par la phase auth.
     * Le refuser interdirait tout premier acces. */
    ok("un compte pas encore cree localement passe",
       vaultaire_local_account_usable("jamais-vu-ici@dom") == 0);
    /* root existe et n'est ni verrouille ni expire sur une machine saine. */
    ok("un compte local sain passe", vaultaire_local_account_usable("root") == 0);

    printf("\n%s\n", echecs ? "DES TESTS ECHOUENT" : "tous les tests passent");
    return echecs ? 1 : 0;
}
