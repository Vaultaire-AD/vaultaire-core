#include <nss.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

// On définit un UID de base pour nos utilisateurs virtuels
#define VIRTUAL_UID 5001
#define VIRTUAL_GID 5001

enum nss_status _nss_vaultaire_getpwnam_r(const char *name, struct passwd *result, 
    char *buffer, size_t buflen, int *errnop) 
{

    // 1. On vérifie si c'est un compte de domaine (présence du @)
    if (strchr(name, '@') == NULL) {
        return NSS_STATUS_NOTFOUND; // Pas un compte de domaine, on laisse les autres modules gérer
    }
    // On remplit les informations bidons pour que SSH soit content
    result->pw_name = (char *)name;
    result->pw_passwd = (char *)"x";
    result->pw_uid = VIRTUAL_UID;
    result->pw_gid = VIRTUAL_GID;
    result->pw_gecos = (char *)name;
    
    // On génère dynamiquement le chemin du home : /home/nom_user
    char *home = buffer;
    snprintf(home, buflen, "/home/%s", name);
    result->pw_dir = home;
    
    result->pw_shell = (char *)"/bin/bash";

    return NSS_STATUS_SUCCESS;
}

// Obligatoire pour que 'id name' fonctionne aussi par UID
enum nss_status _nss_vaultaire_getpwuid_r(uid_t uid, struct passwd *result, 
    char *buffer, size_t buflen, int *errnop) 
{
    if (uid != VIRTUAL_UID) return NSS_STATUS_NOTFOUND;
    return NSS_STATUS_NOTFOUND; // On laisse 'files' gérer l'UID root
}