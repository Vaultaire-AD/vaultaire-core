/*
 * nss_vaultaire.c
 *
 * Resolution des comptes du domaine pour la libc.
 *
 * ============================================================================
 * POURQUOI CE MODULE A ETE REECRIT
 * ============================================================================
 *
 * La version precedente attribuait le MEME UID (5001) a tout nom contenant un
 * "@" :
 *
 *     #define VIRTUAL_UID 5001
 *     result->pw_uid = VIRTUAL_UID;
 *
 * Sous Unix, l'UID EST l'identite. Deux comptes qui le partagent sont le meme
 * utilisateur pour le noyau :
 *
 *   - alice@dom lit, modifie et supprime les fichiers de bob@dom ;
 *   - elle peut lui envoyer des signaux, donc tuer ses processus ;
 *   - ptrace est autorise entre eux : lecture de la memoire, donc des secrets
 *     en cours d'usage.
 *
 * Il n'y avait aucune separation entre les utilisateurs du domaine sur une
 * machine geree — l'inverse de ce qu'un annuaire apporte.
 *
 * ============================================================================
 * LE MODELE RETENU : UNE CARTE ECRITE PAR L'AGENT, LUE ICI
 * ============================================================================
 *
 * L'agent maintient /etc/vaultaire/uid.map et y attribue un UID unique et
 * stable par utilisateur. Ce module se contente de LIRE.
 *
 * Pourquoi ce partage des roles :
 *
 *   - un module NSS est charge dans TOUS les processus de la machine, y
 *     compris ceux qui n'ont aucun privilege. Il ne doit ni ecrire, ni ouvrir
 *     de socket, ni bloquer : une latence ici pese sur tout le systeme, et une
 *     ecriture demanderait des droits qu'un processus quelconque n'a pas ;
 *
 *   - l'agent, lui, connait l'annuaire et tourne en root. C'est le seul endroit
 *     ou l'attribution peut etre a la fois informee et sure.
 *
 * Un nom absent de la carte donne NSS_STATUS_NOTFOUND. Le module n'invente
 * jamais d'identite : c'est ce qui a cause le probleme d'origine.
 *
 * ============================================================================
 * ORDRE DANS nsswitch.conf
 * ============================================================================
 *
 *     passwd: files vaultaire
 *
 * "files" EN PREMIER, toujours. Une fois le compte local cree par PAM, c'est
 * /etc/passwd qui fait autorite : ce module ne sert plus que pour la fenetre
 * d'avant-premiere-connexion, ou sshd exige une entree passwd avant meme de
 * lancer l'authentification.
 *
 * L'ordre inverse masquerait l'UID reel du compte local par celui de la carte,
 * et toute divergence entre les deux deviendrait invisible.
 */

#define _GNU_SOURCE
#include <nss.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>

#define VAULTAIRE_UID_MAP "/etc/vaultaire/uid.map"

/* Bornes de la plage geree. Elles servent de garde-fou a la LECTURE : une carte
 * corrompue ou trafiquee ne doit pas pouvoir attribuer l'UID 0.
 *
 * C'est le controle qui compte le plus dans ce fichier. La carte est un fichier
 * texte ; si quoi que ce soit permettait d'y ecrire, la ligne
 *
 *     attaquant@dom:0:0
 *
 * ferait de ce compte root aux yeux de la libc. On refuse donc tout ce qui sort
 * de la plage, sans exception. */
#define VAULTAIRE_UID_MIN 5000
#define VAULTAIRE_UID_MAX 60000

/* Un nom de domaine se reconnait au "@". Regle heritee, conservee pour ne pas
 * lire la carte a chaque resolution de "root" ou "daemon" — ce qui arrive des
 * milliers de fois par seconde sur une machine chargee. */
static int looks_like_domain_user(const char *name) {
    return name != NULL && strchr(name, '@') != NULL;
}

/* Ecrit une chaine dans le tampon de l'appelant et fait avancer le curseur.
 *
 * Le contrat NSS impose que TOUTES les chaines de struct passwd pointent dans
 * ce tampon. La version precedente y manquait :
 *
 *     result->pw_name = (char *)name;    // memoire de l'appelant
 *     result->pw_shell = (char *)"/bin/bash";  // litteral
 *
 * Un appelant qui conserve la structure — le cas usuel — lisait alors une
 * memoire dont la duree de vie ne lui appartenait pas.
 *
 * Retourne NULL si la place manque : l'appelant doit alors rendre ERANGE, et
 * non tronquer. Tronquer un nom d'utilisateur ou un chemin de home produirait
 * une identite silencieusement fausse. */
static char *buf_put(const char *src, char **cursor, char *end) {
    size_t n = strlen(src) + 1;
    if ((size_t)(end - *cursor) < n) {
        return NULL;
    }
    char *out = *cursor;
    memcpy(out, src, n);
    *cursor += n;
    return out;
}

/* Cherche une entree dans la carte.
 *
 * Format, une entree par ligne :
 *
 *     nom:uid:gid
 *
 * Les lignes vides et celles commencant par '#' sont ignorees. Une ligne
 * malformee est ignoree AUSSI : la carte est ecrite par l'agent, mais elle
 * reste un fichier sur disque, et une ligne abimee ne doit pas faire perdre
 * les autres.
 *
 * Recherche par nom si want_name est non NULL, par UID sinon.
 *
 * Retourne 1 si trouve, 0 sinon. */
static int map_lookup(const char *want_name, uid_t want_uid,
                      char *name_out, size_t name_out_size,
                      uid_t *uid_out, gid_t *gid_out) {
    FILE *f = fopen(VAULTAIRE_UID_MAP, "re"); /* 'e' : O_CLOEXEC */
    if (!f) {
        return 0;
    }

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }

        char *nl = strchr(line, '\n');
        if (nl) {
            *nl = '\0';
        } else {
            /* Ligne plus longue que le tampon : on l'ignore ET on consomme le
             * reste, sinon la suite serait lue comme une nouvelle entree —
             * donc un nom d'utilisateur fabrique a partir d'un fragment. */
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') {
                /* rien */
            }
            continue;
        }

        char *sep1 = strchr(line, ':');
        if (!sep1) continue;
        *sep1 = '\0';
        char *sep2 = strchr(sep1 + 1, ':');
        if (!sep2) continue;
        *sep2 = '\0';

        const char *name = line;
        if (name[0] == '\0') continue;

        /* strtoul et non atoi : atoi ne signale aucune erreur et rend 0 sur une
         * entree illisible. Zero est l'UID de root. */
        char *fin = NULL;
        errno = 0;
        unsigned long uid = strtoul(sep1 + 1, &fin, 10);
        if (errno != 0 || fin == sep1 + 1 || *fin != '\0') continue;

        errno = 0;
        unsigned long gid = strtoul(sep2 + 1, &fin, 10);
        if (errno != 0 || fin == sep2 + 1 || *fin != '\0') continue;

        /* Le garde-fou : hors plage, la ligne n'existe pas. */
        if (uid < VAULTAIRE_UID_MIN || uid > VAULTAIRE_UID_MAX) continue;
        if (gid < VAULTAIRE_UID_MIN || gid > VAULTAIRE_UID_MAX) continue;

        int match = want_name ? (strcmp(name, want_name) == 0)
                              : ((uid_t)uid == want_uid);
        if (!match) continue;

        if (name_out) {
            if (strlen(name) >= name_out_size) break; /* nom aberrant : on renonce */
            strcpy(name_out, name);
        }
        *uid_out = (uid_t)uid;
        *gid_out = (gid_t)gid;
        found = 1;
        break;
    }

    fclose(f);
    return found;
}

/* Remplit struct passwd a partir d'un nom, d'un UID et d'un GID deja valides. */
static enum nss_status fill_passwd(const char *name, uid_t uid, gid_t gid,
                                   struct passwd *result,
                                   char *buffer, size_t buflen, int *errnop) {
    char home[256];
    int n = snprintf(home, sizeof(home), "/home/%s", name);
    if (n < 0 || (size_t)n >= sizeof(home)) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    char *cursor = buffer;
    char *end = buffer + buflen;

    char *p_name  = buf_put(name, &cursor, end);
    char *p_pass  = buf_put("x", &cursor, end);
    char *p_gecos = buf_put(name, &cursor, end);
    char *p_dir   = buf_put(home, &cursor, end);
    char *p_shell = buf_put("/bin/bash", &cursor, end);

    if (!p_name || !p_pass || !p_gecos || !p_dir || !p_shell) {
        /* Contrat NSS : tampon trop court => ERANGE + TRYAGAIN. L'appelant
         * recommence avec un tampon plus grand. La version precedente tronquait
         * en silence. */
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    result->pw_name   = p_name;
    result->pw_passwd = p_pass;
    result->pw_uid    = uid;
    result->pw_gid    = gid;
    result->pw_gecos  = p_gecos;
    result->pw_dir    = p_dir;
    result->pw_shell  = p_shell;

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_vaultaire_getpwnam_r(const char *name, struct passwd *result,
                                          char *buffer, size_t buflen, int *errnop) {
    if (!name || !result || !buffer || !errnop) {
        if (errnop) *errnop = EINVAL;
        return NSS_STATUS_UNAVAIL;
    }
    *errnop = 0;

    if (!looks_like_domain_user(name)) {
        return NSS_STATUS_NOTFOUND;
    }

    uid_t uid;
    gid_t gid;
    if (!map_lookup(name, 0, NULL, 0, &uid, &gid)) {
        /* Absent de la carte : on ne repond pas.
         *
         * C'est le changement de fond. L'ancienne version fabriquait une
         * identite pour n'importe quel nom comportant un "@" ; celle-ci ne
         * connait que ce que l'agent a effectivement attribue. */
        return NSS_STATUS_NOTFOUND;
    }

    return fill_passwd(name, uid, gid, result, buffer, buflen, errnop);
}

/* Resolution inverse, indispensable a "ls -l", "ps" et "id".
 *
 * L'ancienne version rendait NOTFOUND dans tous les cas, y compris pour son
 * propre UID virtuel : les fichiers des utilisateurs du domaine s'affichaient
 * avec un numero nu. */
enum nss_status _nss_vaultaire_getpwuid_r(uid_t uid, struct passwd *result,
                                          char *buffer, size_t buflen, int *errnop) {
    if (!result || !buffer || !errnop) {
        if (errnop) *errnop = EINVAL;
        return NSS_STATUS_UNAVAIL;
    }
    *errnop = 0;

    /* Filtre avant d'ouvrir le fichier : la resolution d'UID hors plage arrive
     * en permanence (root, daemon, services), et ouvrir la carte a chaque fois
     * couterait un acces disque pour rien. */
    if (uid < VAULTAIRE_UID_MIN || uid > VAULTAIRE_UID_MAX) {
        return NSS_STATUS_NOTFOUND;
    }

    char name[256];
    uid_t found_uid;
    gid_t found_gid;
    if (!map_lookup(NULL, uid, name, sizeof(name), &found_uid, &found_gid)) {
        return NSS_STATUS_NOTFOUND;
    }

    return fill_passwd(name, found_uid, found_gid, result, buffer, buflen, errnop);
}
