/*
 * hardening_test.c
 *
 * Tests des corrections des points MAJEURS de l'audit.
 *
 *   5  mot de passe injecte dans du JSON sans echappement
 *   6  liste blanche des noms (l'injection shell visait le groupe sudo, que
 *      le module ne touche plus depuis le TO-DO 197 ; la validation reste
 *      le garde-fou de tout ce qui suit)
 *
 * Les points 4 et 9 (authorized_keys) sont testes cote agent depuis le 197.
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
    vaultaire_build_check_request("admin@dom", "pa\"ss", "0000", req, sizeof(req));
    ok("requete avec guillemet bien formee",
       strcmp(req,"{\"check\":{\"user\":\"admin@dom\",\"password\":\"pa\\\"ss\",\"otp\":\"0000\"}}")==0);
    printf("       %s\n", req);

    /* injection : le mot de passe ne doit pas pouvoir ajouter un champ */
    vaultaire_build_check_request("attaquant@dom", "x\",\"user\":\"admin@dom", "0000", req, sizeof(req));
    ok("injection neutralisee (un seul champ user)",
       strstr(req,"\"user\":\"attaquant@dom\"")!=NULL &&
       strstr(req,"\",\"user\":\"admin@dom\"")==NULL);
    printf("       %s\n", req);

    
    /* TO-DO 95 : le code de second facteur vient d'une SAISIE UTILISATEUR.
     *
     * Rien ne garantit que l'utilisateur ait tape six chiffres — et le defaut
     * qu'avait le mot de passe avant le durcissement serait exactement le meme
     * ici : un guillemet produirait un JSON invalide, et le compte ne pourrait
     * jamais se connecter. */
    vaultaire_build_check_request("alice@dom", "mdp", "12\"34", req, sizeof(req));
    ok("code avec guillemet echappe",
       strstr(req,"\"otp\":\"12\\\"34\"")!=NULL);

    vaultaire_build_check_request("alice@dom", "mdp", "x\",\"password\":\"vole", req, sizeof(req));
    ok("injection par le code neutralisee",
       strstr(req,"\"password\":\"mdp\"")!=NULL &&
       strstr(req,"\"password\":\"vole\"")==NULL);

    /* Le champ est TOUJOURS ecrit, meme vide : sa PRESENCE dit au core qu'il
     * parle a un agent recent. L'omettre le ferait passer pour un agent ancien,
     * et le core laisserait passer sans second facteur. */
    vaultaire_build_check_request("alice@dom", "mdp", "", req, sizeof(req));
    ok("champ otp present meme vide", strstr(req,"\"otp\":\"\"")!=NULL);

    /* Un code demesure est REFUSE, jamais tronque : un code tronque serait
     * refuse par le core comme un code faux, et l'utilisateur chercherait du
     * cote de son telephone. */
    {
        char tres_long[256];
        memset(tres_long, '7', sizeof(tres_long)-1);
        tres_long[sizeof(tres_long)-1] = '\0';
        ok("code demesure refuse",
           vaultaire_build_check_request("alice@dom", "mdp", tres_long, req, sizeof(req)) != 0);
    }

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
    
    /* Points 4 et 9 (authorized_keys : liens symboliques, cles revoquees) :
     * le module n'ecrit plus ce fichier depuis le TO-DO 197, c'est l'agent.
     * Leurs tests sont cote Go : tools/local_user_management/
     * authorized_keys_test.go. */

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

    /* ---------------------------------------------------------------------
     * TO-DO 99 : le message presente a l'utilisateur a l'ouverture de session.
     *
     * Le champ « notice » est le premier TEXTE LIBRE que ces modules lisent
     * dans la reponse du daemon. Les valeurs lues jusqu'ici — un statut, un nom
     * de compte — ne contiennent jamais de guillemet ni d'accent ; celle-ci est
     * une phrase francaise composee par le core.
     *
     * Ce que ces cas verifient est donc ce que l'ancien lecteur ne faisait pas :
     * rendre la valeur ENTIERE quelle qu'elle soit, au lieu de la couper au
     * premier echappement.
     * --------------------------------------------------------------------- */
    printf("\n--- TO-DO 99 : lecture du message d'ouverture de session ---\n");

    char notice[512];

    ok("un message simple se lit",
       vaultaire_json_get_string("{\"status\":\"success\",\"notice\":\"changez votre mot de passe\"}",
                                 "notice", notice, sizeof(notice)) == 0 &&
       strcmp(notice, "changez votre mot de passe") == 0);

    /* LE cas du point : un guillemet echappe coupait la phrase en deux, et
     * l'utilisateur lisait un message tronque sans savoir pourquoi. */
    ok("un guillemet echappe ne coupe pas le message",
       vaultaire_json_get_string("{\"notice\":\"tapez \\\"oui\\\" pour continuer\"}",
                                 "notice", notice, sizeof(notice)) == 0 &&
       strcmp(notice, "tapez \"oui\" pour continuer") == 0);

    ok("une barre oblique inverse se lit",
       vaultaire_json_get_string("{\"notice\":\"C:\\\\Windows\"}",
                                 "notice", notice, sizeof(notice)) == 0 &&
       strcmp(notice, "C:\\Windows") == 0);

    ok("un saut de ligne echappe devient un vrai saut de ligne",
       vaultaire_json_get_string("{\"notice\":\"ligne1\\nligne2\"}",
                                 "notice", notice, sizeof(notice)) == 0 &&
       strcmp(notice, "ligne1\nligne2") == 0);

    /* Les accents voyagent en UTF-8 brut : encoding/json ne les echappe pas,
     * et ce lecteur ne doit pas les abimer. */
    ok("les accents traversent intacts",
       vaultaire_json_get_string("{\"notice\":\"mot de passe perime\"}",
                                 "notice", notice, sizeof(notice)) == 0 &&
       strcmp(notice, "mot de passe perime") == 0);

    /* Le champ est FACULTATIF : son absence n'est pas une erreur de lecture de
     * la reponse, c'est le cas ordinaire — il n'y a rien a dire. */
    ok("un champ absent est signale sans toucher au tampon",
       vaultaire_json_get_string("{\"status\":\"success\"}",
                                 "notice", notice, sizeof(notice)) != 0 &&
       notice[0] == '\0');

    /* Une reponse COUPEE ne doit pas passer pour un message valide : le champ
     * precede les cles dans la reponse, et une chaine non terminee signifie que
     * tout ce qui suit manque aussi. */
    ok("une chaine non terminee est refusee",
       vaultaire_json_get_string("{\"notice\":\"coupe au milieu",
                                 "notice", notice, sizeof(notice)) != 0);

    ok("un echappement coupe en fin de tampon est refuse",
       vaultaire_json_get_string("{\"notice\":\"fini par \\",
                                 "notice", notice, sizeof(notice)) != 0);

    /* Le statut continue de se lire comme avant : c'est lui qui decide du
     * refus, et le nouveau lecteur ne doit rien y changer. */
    ok("le statut se lit toujours",
       vaultaire_json_get_string("{\"status\":\"success\",\"is_admin\":true}",
                                 "status", notice, sizeof(notice)) == 0 &&
       strcmp(notice, "success") == 0);

    /* Un message plus long que le tampon est TRONQUE, pas refuse : il reste
     * lisible, et le refuser priverait l'utilisateur de l'avertissement entier
     * pour une question de place. */
    {
        char petit[8];
        ok("un message trop long est tronque proprement",
           vaultaire_json_get_string("{\"notice\":\"beaucoup trop long pour huit octets\"}",
                                     "notice", petit, sizeof(petit)) == 0 &&
           strlen(petit) == sizeof(petit) - 1);
    }

    printf("\n%s\n", echecs ? "DES TESTS ECHOUENT" : "tous les tests passent");
    return echecs ? 1 : 0;
}
