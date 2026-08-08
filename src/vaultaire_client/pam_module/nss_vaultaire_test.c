#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

extern enum nss_status _nss_vaultaire_getpwnam_r(const char*, struct passwd*, char*, size_t, int*);
extern enum nss_status _nss_vaultaire_getpwuid_r(uid_t, struct passwd*, char*, size_t, int*);

static int echecs = 0;
static void ok(const char *quoi, int cond) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", quoi);
    if (!cond) echecs++;
}

int main(void) {
    struct passwd pw; char buf[1024]; int e = 0;
    enum nss_status st;

    /* --- deux utilisateurs distincts doivent avoir des UID distincts --- */
    struct passwd a, b; char ba[1024], bb[1024];
    _nss_vaultaire_getpwnam_r("alice@dom", &a, ba, sizeof(ba), &e);
    _nss_vaultaire_getpwnam_r("bob@dom",   &b, bb, sizeof(bb), &e);
    ok("alice et bob ont des UID DIFFERENTS (le defaut critique)", a.pw_uid != b.pw_uid);
    ok("alice a l'UID de la carte (5001)", a.pw_uid == 5001);
    ok("bob a l'UID de la carte (5002)",   b.pw_uid == 5002);

    /* --- les chaines pointent DANS le tampon (contrat NSS) --- */
    ok("pw_name pointe dans le tampon", a.pw_name >= ba && a.pw_name < ba + sizeof(ba));
    ok("pw_shell pointe dans le tampon", a.pw_shell >= ba && a.pw_shell < ba + sizeof(ba));
    ok("pw_dir pointe dans le tampon", a.pw_dir >= ba && a.pw_dir < ba + sizeof(ba));
    ok("le home est correct", strcmp(a.pw_dir, "/home/alice@dom") == 0);

    /* --- un nom absent de la carte n'obtient AUCUNE identite --- */
    st = _nss_vaultaire_getpwnam_r("inconnu@dom", &pw, buf, sizeof(buf), &e);
    ok("un nom absent de la carte donne NOTFOUND", st == NSS_STATUS_NOTFOUND);

    /* --- un nom local n'est pas intercepte --- */
    st = _nss_vaultaire_getpwnam_r("root", &pw, buf, sizeof(buf), &e);
    ok("un nom sans @ donne NOTFOUND", st == NSS_STATUS_NOTFOUND);

    /* --- garde-fou : une ligne hors plage est ignoree --- */
    st = _nss_vaultaire_getpwnam_r("pirate@dom", &pw, buf, sizeof(buf), &e);
    ok("une entree avec uid=0 est REFUSEE", st == NSS_STATUS_NOTFOUND);
    st = _nss_vaultaire_getpwnam_r("horsplage@dom", &pw, buf, sizeof(buf), &e);
    ok("une entree hors plage haute est REFUSEE", st == NSS_STATUS_NOTFOUND);
    st = _nss_vaultaire_getpwnam_r("pasunnombre@dom", &pw, buf, sizeof(buf), &e);
    ok("une entree dont l'uid n'est pas un nombre est REFUSEE", st == NSS_STATUS_NOTFOUND);

    /* --- tampon trop court : ERANGE, pas de troncature --- */
    char petit[8];
    e = 0;
    st = _nss_vaultaire_getpwnam_r("alice@dom", &pw, petit, sizeof(petit), &e);
    ok("tampon court -> TRYAGAIN", st == NSS_STATUS_TRYAGAIN);
    ok("tampon court -> errno ERANGE", e == ERANGE);

    /* --- resolution inverse --- */
    e = 0;
    st = _nss_vaultaire_getpwuid_r(5001, &pw, buf, sizeof(buf), &e);
    ok("getpwuid_r retrouve alice", st == NSS_STATUS_SUCCESS && strcmp(pw.pw_name, "alice@dom") == 0);
    st = _nss_vaultaire_getpwuid_r(0, &pw, buf, sizeof(buf), &e);
    ok("getpwuid_r(0) ne rend jamais root", st == NSS_STATUS_NOTFOUND);
    st = _nss_vaultaire_getpwuid_r(9999, &pw, buf, sizeof(buf), &e);
    ok("getpwuid_r d'un UID absent donne NOTFOUND", st == NSS_STATUS_NOTFOUND);

    printf("\n%s\n", echecs ? "DES TESTS ECHOUENT" : "tous les tests passent");
    return echecs ? 1 : 0;
}
