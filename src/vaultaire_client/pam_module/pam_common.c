/*
 * pam_common.c
 * Shared implementation for Vaultaire PAM modules.
 */

#define _GNU_SOURCE
#include "pam_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <linux/limits.h>

/* --- Logging --- */
static void vaultaire_log_v(const char *prefix, const char *fmt, va_list ap) {
    /* Si /var/log/vaultaire/ n'existe pas (déploiement qui a oublié de le
     * créer avant d'installer les modules PAM), fopen() échoue silencieusement
     * et tous les logs du module disparaissent sans aucune trace nulle part —
     * on a alors l'impression que le module n'est même pas chargé. On
     * s'assure donc que le dossier existe avant chaque écriture ; mkdir()
     * échoue silencieusement (et sans conséquence) s'il existe déjà. */
    mkdir("/var/log/vaultaire", 0750);

    /* Le journal porte les noms des comptes qui se connectent, leurs horaires et
     * leur statut administrateur. En 0644 — le mode par defaut de fopen — tout
     * utilisateur local en obtient la cartographie du parc.
     *
     * On ouvre donc par open() avec un mode EXPLICITE : fopen ne permet pas de
     * le choisir, et un chmod apres coup laisserait une fenetre.
     *
     * O_NOFOLLOW : le journal est dans un repertoire que l'on cree, mais un
     * module d'authentification n'ecrit pas a travers un lien. */
    int fd = open("/var/log/vaultaire/vaultaire_pam.log",
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (fd < 0) {
        return;
    }
    FILE *f = fdopen(fd, "a");
    if (f) {
        fprintf(f, "[%s] ", prefix);
        vfprintf(f, fmt, ap);
        fprintf(f, "\n");
        fclose(f);
    } else {
        close(fd);
    }
}

void vaultaire_log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vaultaire_log_v("INFO", fmt, ap);
    va_end(ap);
}

void vaultaire_log_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vaultaire_log_v("ERROR", fmt, ap);
    va_end(ap);
}



/* Un compte du domaine se reconnait a la forme « nom@domaine ».
 *
 * L'ancienne version rendait vrai des qu'un « @ » apparaissait quelque part. Un
 * compte LOCAL en comportant un — rare mais legal — etait alors traite comme un
 * compte du domaine : envoye au daemon, et son mot de passe local reecrit.
 *
 * On exige desormais la forme complete : nom non vide, un seul « @ », domaine
 * non vide comportant au moins un point. « root » et « alice@localhost » ne
 * passent plus ; « alice@vaultaire.fr » oui.
 *
 * Comparer au domaine REELLEMENT configure serait plus juste encore, mais les
 * modules PAM ne lisent aucune configuration — ils n'ont que le nom. C'est le
 * daemon qui tranche ensuite, et lui connait le domaine. */
int is_vaultaire_user(const char *username) {
    if (username == NULL || username[0] == '\0') {
        return 0;
    }

    const char *arobase = strchr(username, '@');
    if (arobase == NULL || arobase == username) {
        return 0;
    }
    if (strchr(arobase + 1, '@') != NULL) {
        return 0;
    }

    const char *domaine = arobase + 1;
    return domaine[0] != '\0' && strchr(domaine, '.') != NULL;
}

/* Liste BLANCHE des noms d'utilisateur.
 *
 * # Pourquoi la liste noire ne suffisait pas
 *
 * L'ancienne version refusait « / ; & : \n \r \t » et laissait passer tout le
 * reste. Ne figuraient donc PAS dans la liste :
 *
 *     `  $  |  (  )  '  "  <  >  \  *  ?  {  }  [  ]  !  #
 *
 * Or ce nom finit dans system(), qui passe par /bin/sh. Un nom de la forme
 *
 *     alice$(id > /tmp/preuve)@dom
 *
 * traversait la validation et s'executait EN ROOT.
 *
 * Une liste noire doit enumerer tout ce qui est dangereux — donc anticiper
 * chaque interpretation de chaque shell. Une liste blanche enumere ce qui est
 * legitime : la question devient « qu'est-ce qu'un nom d'utilisateur »,
 * a laquelle on sait repondre.
 *
 * Meme jeu de caracteres que isValidUserInput cote Go : [A-Za-z0-9._@-]. Les
 * deux validations doivent s'accorder, sinon un nom accepte d'un cote serait
 * rejete de l'autre. */
bool vaultaire_is_valid_username(const char *username) {
    if (!username || username[0] == '\0') return false;

    /* Borne de longueur : un nom aberrant n'a aucune raison d'exister, et
     * limite ce qui peut entrer dans les tampons en aval. */
    if (strlen(username) > 128) return false;

    /* Un nom ne commence pas par un tiret : il serait pris pour une OPTION par
     * les commandes qui le recoivent. « -rf » comme nom d'utilisateur. */
    if (username[0] == '-') return false;

    for (const char *p = username; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '_' || c == '-' || c == '@') {
            continue;
        }
        return false;
    }
    return true;
}


/* --- Commande exécutée via subprocess --- */
static int run_useradd(const char *username) {
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) {
        /* Ordre des arguments : chaque option porte sa valeur JUSTE APRES elle.
         *
         * La version precedente ecrivait :
         *
         *     "-m", "--shell", "-c", "vaultaire_user_account", "/bin/bash", username
         *
         * --shell consommait "-c" comme valeur, et il restait TROIS operandes la
         * ou useradd en attend une seule. Verifie sur le binaire reel :
         *
         *     useradd: invalid shell '-c'   (code de sortie 3)
         *
         * run_useradd retournait donc 0 a CHAQUE appel, et aucun compte local
         * n'a jamais ete cree par ce chemin. Le defaut restait invisible parce
         * que getpwnam() passe par NSS, et que le module libnss_vaultaire
         * repondait pour tout nom contenant un "@" : la condition
         * if (!getpwnam(username)) etait fausse, et run_useradd jamais appele. */
        execl("/usr/sbin/useradd", "useradd",
              "-m",
              "--shell", "/bin/bash",
              "-c", "vaultaire_user_account",
              username, (char *)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int run_chpasswd(const char *username, const char *password) {
    int fd[2];
    if (pipe(fd) != 0) return 0;
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]); close(fd[1]);
        return 0;
    }
    if (pid == 0) {
        dup2(fd[0], STDIN_FILENO);
        close(fd[0]); close(fd[1]);
        execl("/usr/sbin/chpasswd", "chpasswd", (char *)NULL);
        _exit(127);
    }
    close(fd[0]);

    /* SIGPIPE neutralise le temps de l'ecriture.
     *
     * Si execl a echoue — chpasswd absent d'une distribution minimale —
     * l'enfant sort aussitot et l'extremite de lecture se ferme. L'ecriture
     * recoit alors SIGPIPE, dont l'action par defaut est la TERMINAISON DU
     * PROCESSUS.
     *
     * Ce processus est celui qui a charge le module PAM : sshd, login ou sudo.
     * Un chpasswd manquant ne provoquait donc pas un echec d'authentification,
     * mais la mort brutale de l'appelant, sans message. */
    struct sigaction ignorer, ancienne;
    memset(&ignorer, 0, sizeof(ignorer));
    ignorer.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &ignorer, &ancienne);

    /* Le retour est VERIFIE : une ecriture partielle transmettrait un mot de
     * passe tronque, que chpasswd poserait sans erreur. Le compte local aurait
     * alors un mot de passe different de celui du centre — et son porteur ne
     * pourrait plus se connecter en local sans qu'on sache pourquoi. */
    int attendu = snprintf(NULL, 0, "%s:%s\n", username, password);
    int ecrit = dprintf(fd[1], "%s:%s\n", username, password);
    close(fd[1]);
    sigaction(SIGPIPE, &ancienne, NULL);

    if (ecrit < 0 || ecrit != attendu) {
        vaultaire_log_err("transmission a chpasswd incomplete pour %s", username);
        int st;
        waitpid(pid, &st, 0);
        return 0;
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Indique si le hash deja present dans /etc/shadow correspond au mot de passe
 * fourni.
 *
 * Le hash stocke sert de reglage a crypt_r : il porte l'algorithme, le cout et
 * le sel. Rechiffrer le mot de passe avec ce reglage doit redonner exactement
 * la meme chaine si le mot de passe est le meme.
 *
 * Retourne 1 si identique, 0 sinon (y compris quand la comparaison est
 * impossible : dans le doute on reecrit, c'est le comportement sur.) */
static int local_password_matches(const char *username, const char *password) {
    struct spwd *sp = getspnam(username);
    if (!sp || !sp->sp_pwdp) {
        /* Pas d'entree shadow lisible : compte tout juste cree, ou processus
         * sans les droits. On ne peut rien comparer. */
        return 0;
    }

    const char *stored = sp->sp_pwdp;

    /* Un hash exploitable commence par '$' ($6$, $y$, $2b$...). Les valeurs
     * "", "!", "*", "!!" designent un compte verrouille ou sans mot de passe :
     * ce ne sont pas des reglages crypt valides, et il faut poser un vrai hash. */
    if (stored[0] != '$') {
        return 0;
    }

    /* struct crypt_data fait plusieurs dizaines de kilo-octets avec libxcrypt :
     * trop pour la pile d'un module PAM, on l'alloue sur le tas. */
    struct crypt_data *cd = calloc(1, sizeof(*cd));
    if (!cd) {
        vaultaire_log_err("calloc crypt_data failed for %s", username);
        return 0;
    }

    char *computed = crypt_r(password, stored, cd);
    /* crypt_r signale un echec en renvoyant NULL ou une chaine commencant par
     * '*', qui ne peut jamais egaler un hash valide. */
    int match = (computed && computed[0] != '*' && strcmp(computed, stored) == 0);

    /* Le buffer contient un derive du mot de passe : on l'efface avant de
     * rendre la memoire, plutot que de la laisser reutilisable telle quelle. */
    explicit_bzero(cd, sizeof(*cd));
    free(cd);

    return match;
}

int ensure_local_user_with_password(const char *username, const char *password) {
    if (!getpwnam(username)) {
        if (!run_useradd(username)) {
            vaultaire_log_err("useradd failed for %s", username);
            return 0;
        }
        vaultaire_log_info("Created local user %s", username);
    }

    if (password && password[0] != '\0') {
        /* Comparaison avant reecriture. chpasswd etait lance a CHAQUE
         * connexion reussie, ce qui reecrivait /etc/shadow sans raison et
         * remettait a zero la date de dernier changement du mot de passe
         * (champ sp_lstchg) — de quoi fausser toute politique de peremption.
         * Le mot de passe central ne change que rarement : la comparaison
         * evite l'ecriture dans l'immense majorite des connexions. */
        if (local_password_matches(username, password)) {
            vaultaire_log_info("Local password already in sync for %s", username);
            return 1;
        }

        if (!run_chpasswd(username, password)) {
            vaultaire_log_err("chpasswd failed for %s", username);
            return 0;
        }
        vaultaire_log_info("Local password updated for %s (differed from central)", username);
    }
    return 1;
}

/* Restaure le contexte SELinux d'une arborescence.
 *
 * fork/exec plutot que de lier libselinux : lier imposerait une dependance de
 * compilation supplementaire aux modules PAM, alors que restorecon est present
 * partout ou SELinux l'est. Son absence est justement le signe qu'il n'y a rien
 * a restaurer.
 *
 * Sans effet et sans erreur sur une machine sans SELinux. */
static void vaultaire_restore_selinux(const char *chemin) {
    if (!chemin || chemin[0] != '/') {
        return;
    }
    if (access("/sbin/restorecon", X_OK) != 0 &&
        access("/usr/sbin/restorecon", X_OK) != 0) {
        /* Pas de SELinux : cas NORMAL, rien a journaliser. Le signaler a
         * chaque connexion remplirait le journal d'un bruit sans action. */
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        return;
    }
    if (pid == 0) {
        /* -RF : recursif et force. Sans -F, un fichier etiquete par heritage —
         * donc avec un contexte plausible mais faux — serait laisse tel quel. */
        execl("/sbin/restorecon", "restorecon", "-RF", chemin, (char *)NULL);
        execl("/usr/sbin/restorecon", "restorecon", "-RF", chemin, (char *)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        vaultaire_log_err("restorecon a echoue sur %s", chemin);
    }
}

/* --- Provisioning Clés SSH --- */
/* Depose les cles SSH d'un utilisateur, en ROOT, sans se faire detourner.
 *
 * # Ce que faisait la version precedente
 *
 *     snprintf(ssh_dir, ..., "%s/.ssh", pw->pw_dir);
 *     mkdir(ssh_dir, 0700);
 *     FILE *f = fopen(auth_keys_path, "w");   <-- suit les liens symboliques
 *     ...
 *     chmod(auth_keys_path, 0600);            <-- APRES l'ecriture
 *
 * Trois defauts, tous exploitables parce que ce code tourne en root.
 *
 * 1. SUIVI DE LIEN SYMBOLIQUE. pw_dir vaut /home/<nom>. Un utilisateur qui
 *    controle ce repertoire — ou qui gagne la course avant sa creation — y
 *    place .ssh/authorized_keys en lien vers /etc/shadow ou
 *    /root/.ssh/authorized_keys. fopen("w") suit le lien et ECRIT EN ROOT dans
 *    la cible. Le chown qui suivait la donnait ensuite a l'attaquant.
 *
 * 2. FENETRE DE PERMISSIONS. Le fichier naissait avec le mode par defaut,
 *    souvent 0644, et n'etait ramene a 0600 qu'apres ecriture. Entre les deux,
 *    les cles etaient lisibles par tous.
 *
 * 3. ECRITURE EN PLACE. Une interruption laissait un authorized_keys
 *    tronque — donc un utilisateur qui ne peut plus se connecter, sans que
 *    rien ne le signale.
 *
 * # Ce que fait la version ci-dessous
 *
 * Le repertoire personnel est ouvert UNE FOIS, par descripteur, et tout se
 * passe ensuite relativement a lui (openat, mkdirat, unlinkat, renameat).
 * Un chemin reconstruit a chaque etape peut designer autre chose entre deux
 * appels ; un descripteur, non.
 *
 * O_NOFOLLOW a chaque ouverture : un lien symbolique fait ECHOUER l'appel au
 * lieu d'etre suivi.
 *
 * Le mode 0600 est donne a la CREATION, pas apres. Le fichier n'existe jamais
 * avec des droits plus larges.
 *
 * Enfin : ecriture dans un temporaire, puis renameat. Le remplacement est
 * atomique — authorized_keys est soit l'ancien, soit le nouveau, jamais un
 * fragment. */
/* La resolution du compte, separee de l'ECRITURE.
 *
 * Cette separation n'est pas cosmetique : elle rend l'ecriture testable. Un
 * test du garde-fou contre les liens symboliques doit pouvoir fournir un
 * repertoire personnel a lui — sinon la fonction renonce avant d'ecrire, faute
 * de compte local, et le test passe au vert SANS RIEN MESURER.
 *
 * C'est exactement ce qui s'est produit au premier essai : la mutation
 * remplacant openat/O_NOFOLLOW par une ouverture ordinaire n'etait pas
 * detectee. */
int setup_user_ssh_keys(const char *username, char **keys, size_t key_count) {
    if (!vaultaire_is_valid_username(username)) {
        vaultaire_log_err("SECURITE: nom d'utilisateur refuse pour le depot des cles");
        return 0;
    }

    struct passwd *pw = getpwnam(username);
    if (!pw || !pw->pw_dir || pw->pw_dir[0] != '/') {
        return 0;
    }

    int r = vaultaire_write_ssh_keys(pw->pw_dir, pw->pw_uid, pw->pw_gid, keys, key_count);
    if (r) {
        vaultaire_log_info("Provisioned %2zu SSH key(s) for %s", key_count, username);
    }
    return r;
}

/* Ecrit authorized_keys dans un repertoire personnel DONNE. */
int vaultaire_write_ssh_keys(const char *home, uid_t uid, gid_t gid,
                              char **keys, size_t key_count) {
    if (!home || home[0] != '/') {
        return 0;
    }

    /* Le repertoire personnel, ouvert une fois. O_NOFOLLOW : s'il est lui-meme
     * un lien, on renonce plutot que d'ecrire ailleurs. */
    int home_fd = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (home_fd < 0) {
        vaultaire_log_err("SECURITE: %s inaccessible ou lien symbolique: %s", home, strerror(errno));
        return 0;
    }

    /* .ssh, cree relativement au home. EEXIST est normal. */
    if (mkdirat(home_fd, ".ssh", 0700) != 0 && errno != EEXIST) {
        vaultaire_log_err("creation de .ssh impossible pour %s: %s", home, strerror(errno));
        close(home_fd);
        return 0;
    }

    int ssh_fd = openat(home_fd, ".ssh", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(home_fd);
    if (ssh_fd < 0) {
        vaultaire_log_err("SECURITE: .ssh de %s inaccessible ou lien symbolique: %s",
                          home, strerror(errno));
        return 0;
    }
    if (fchown(ssh_fd, uid, gid) != 0) {
        vaultaire_log_err("chown de .ssh echoue pour %s: %s", home, strerror(errno));
    }

    /* Temporaire, cree en 0600 des l'origine.
     *
     * O_EXCL : la creation echoue si le nom existe deja, quel qu'il soit —
     * fichier ordinaire ou lien. C'est ce qui empeche un attaquant d'avoir
     * prepare la place. */
    const char *tmp_nom = ".authorized_keys.vaultaire";
    unlinkat(ssh_fd, tmp_nom, 0);
    int fd = openat(ssh_fd, tmp_nom,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        vaultaire_log_err("creation du fichier temporaire impossible pour %s: %s",
                          home, strerror(errno));
        close(ssh_fd);
        return 0;
    }

    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlinkat(ssh_fd, tmp_nom, 0);
        close(ssh_fd);
        return 0;
    }

    int ecriture_ok = 1;
    for (size_t i = 0; i < key_count; i++) {
        if (!keys[i]) continue;
        /* Une cle contenant un saut de ligne en fabriquerait DEUX dans le
         * fichier, dont la seconde serait choisie par celui qui l'a fournie. */
        if (strpbrk(keys[i], "\n\r")) {
            vaultaire_log_err("SECURITE: cle SSH contenant un saut de ligne ignoree pour %s", home);
            continue;
        }
        if (fprintf(f, "%s\n", keys[i]) < 0) {
            ecriture_ok = 0;
            break;
        }
    }

    /* fflush et fsync avant le rename : sans cela une coupure juste apres peut
     * laisser un fichier de taille correcte mais au contenu vide — et un
     * authorized_keys vide interdit toute connexion. */
    if (ecriture_ok && (fflush(f) != 0 || fsync(fileno(f)) != 0)) {
        ecriture_ok = 0;
    }
    if (fchown(fileno(f), uid, gid) != 0) {
        vaultaire_log_err("chown des cles echoue pour %s: %s", home, strerror(errno));
    }
    fclose(f);

    if (!ecriture_ok) {
        unlinkat(ssh_fd, tmp_nom, 0);
        close(ssh_fd);
        vaultaire_log_err("ecriture des cles echouee pour %s, ancien fichier conserve", home);
        return 0;
    }

    /* Publication atomique. */
    if (renameat(ssh_fd, tmp_nom, ssh_fd, "authorized_keys") != 0) {
        vaultaire_log_err("publication des cles echouee pour %s: %s", home, strerror(errno));
        unlinkat(ssh_fd, tmp_nom, 0);
        close(ssh_fd);
        return 0;
    }
    close(ssh_fd);

    /* Contexte SELinux : les fichiers crees heritent de /home, donc
     * home_root_t, au lieu de ssh_home_t. sshd refuse alors de les lire. */
    vaultaire_restore_selinux(home);

    return 1;
}



/* Etat local d'un compte du domaine — phase « account » de PAM.
 *
 * # Ce que cette phase repond
 *
 * L'authentification dit « c'est bien lui ». La phase account dit « a-t-il
 * encore le droit d'ouvrir une session ? ». Compte verrouille, expire, shell
 * interdit : autant de raisons de refuser quelqu'un dont le mot de passe est
 * pourtant juste.
 *
 * Les deux modules rendaient PAM_SUCCESS sans rien regarder. Un compte
 * verrouille par « vlt kill » gardait donc son acces tant que son mot de passe
 * local restait valide.
 *
 * # Pourquoi aucun appel reseau ici
 *
 * La phase account s'execute a CHAQUE ouverture de session. Y placer un appel
 * au core reviendrait a faire dependre toute connexion de la joignabilite du
 * reseau : une coupure verrouillerait tout le monde dehors, y compris
 * l'administrateur venu reparer.
 *
 * La revocation centrale a deja son chemin — la categorie de trames 06 — qui
 * agit sur le compte LOCAL. Ce controle lit donc le resultat de ce travail,
 * la ou il a ete inscrit : /etc/shadow et /etc/passwd.
 *
 * Retourne 0 si la session peut s'ouvrir, -1 sinon. */
int vaultaire_local_account_usable(const char *username) {
    if (!vaultaire_is_valid_username(username)) {
        return -1;
    }

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        /* Pas encore de compte local : c'est le cas d'une PREMIERE connexion,
         * ou le compte sera cree par la phase auth. Refuser ici empecherait
         * tout premier acces. */
        return 0;
    }

    /* Shell interdit : la maniere usuelle de desactiver un compte sans le
     * supprimer. */
    if (pw->pw_shell && (strstr(pw->pw_shell, "nologin") || strstr(pw->pw_shell, "/false"))) {
        vaultaire_log_info("compte %s desactive (shell %s)", username, pw->pw_shell);
        return -1;
    }

    struct spwd *sp = getspnam(username);
    if (!sp) {
        /* Entree shadow illisible : on ne peut RIEN conclure. On laisse passer
         * plutot que de refuser sur une absence d'information — la phase auth
         * reste, elle, entierement en vigueur. */
        return 0;
    }

    /* Verrouillage : « ! » ou « * » en tete du hash. C'est ce que pose
     * « usermod -L », et ce que la revocation ecrit. */
    if (sp->sp_pwdp && (sp->sp_pwdp[0] == '!' || sp->sp_pwdp[0] == '*')) {
        vaultaire_log_info("compte %s verrouille", username);
        return -1;
    }

    /* Date d'expiration du COMPTE (sp_expire), en jours depuis 1970.
     * -1 ou 0 signifie « pas d'expiration ». */
    long aujourd_hui = (long)(time(NULL) / 86400);
    if (sp->sp_expire > 0 && aujourd_hui >= sp->sp_expire) {
        vaultaire_log_info("compte %s expire", username);
        return -1;
    }

    /* Expiration du MOT DE PASSE, distincte de celle du compte.
     *
     * sp_max est la duree de validite ; sp_inact le delai de grace APRES
     * expiration. Le compte n'est reellement inutilisable qu'une fois les deux
     * ecoules — refuser des sp_max couperait des gens qui ont encore le droit
     * de se connecter pour changer leur mot de passe. */
    if (sp->sp_lstchg > 0 && sp->sp_max > 0 && sp->sp_inact >= 0) {
        long limite = sp->sp_lstchg + sp->sp_max + sp->sp_inact;
        if (aujourd_hui > limite) {
            vaultaire_log_info("compte %s : mot de passe expire au-dela du delai de grace", username);
            return -1;
        }
    }

    return 0;
}

/* --- Socket --- */

/* Verifie que le socket est bien celui de l'agent, et pas un imposteur.
 *
 * Le repertoire en 0700 root:root est la protection principale : un non-root ne
 * peut rien creer dedans. Ce controle est la seconde barriere, pour le jour ou
 * la premiere cede — repertoire recree a la main, image deployee avec le mauvais
 * mode, montage inattendu.
 *
 * Trois exigences :
 *   - le socket appartient a root ;
 *   - il n'est accessible en ecriture ni au groupe ni aux autres ;
 *   - c'est bien un socket, pas un fichier ordinaire ou un lien.
 *
 * lstat et non stat : stat SUIT les liens symboliques. Un lien pointant vers un
 * socket legitime passerait le controle tout en laissant son proprietaire
 * choisir la cible — donc rediriger les mots de passe ailleurs.
 *
 * Retourne 1 si le socket est digne de confiance, 0 sinon. */
/* Le proprietaire attendu est root, et ce n'est pas negociable en production.
 *
 * La constante est surchargeable a la COMPILATION uniquement, pour que la
 * suite de tests puisse verifier la logique sans etre root — ce qu'aucune
 * machine de developpement n'est. Aucune variable d'environnement, aucun
 * fichier de configuration : rien qui puisse etre change sur une machine
 * deployee. */
#ifndef VAULTAIRE_SOCKET_OWNER
#define VAULTAIRE_SOCKET_OWNER 0
#endif

int socket_is_trustworthy(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        vaultaire_log_err("socket %s introuvable: %s", path, strerror(errno));
        return 0;
    }
    if (!S_ISSOCK(st.st_mode)) {
        vaultaire_log_err("SECURITE: %s n'est pas un socket — connexion refusee", path);
        return 0;
    }
    if (st.st_uid != (uid_t)VAULTAIRE_SOCKET_OWNER) {
        vaultaire_log_err("SECURITE: socket %s appartient a l'uid %u, attendu %u "
                          "— tentative d'usurpation de l'agent, connexion refusee",
                          path, (unsigned)st.st_uid, (unsigned)VAULTAIRE_SOCKET_OWNER);
        return 0;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        vaultaire_log_err("SECURITE: socket %s accessible en ecriture au-dela de root "
                          "(mode %o) — connexion refusee", path, (unsigned)(st.st_mode & 07777));
        return 0;
    }
    return 1;
}

static int connect_socket(void) {
    /* Verification AVANT d'ouvrir quoi que ce soit : le seul moment ou l'on
     * peut encore renoncer sans avoir rien divulgue. */
    if (!socket_is_trustworthy(VAULTAIRE_SOCKET_PATH)) {
        return -1;
    }

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        vaultaire_log_err("socket(): %s", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    /* Controle de longueur explicite : sun_path fait 108 octets, et strncpy
     * tronque SANS le dire. Un chemin tronque designerait un autre fichier —
     * silencieusement. */
    if (strlen(VAULTAIRE_SOCKET_PATH) >= sizeof(addr.sun_path)) {
        vaultaire_log_err("chemin de socket trop long: %s", VAULTAIRE_SOCKET_PATH);
        close(sock);
        return -1;
    }
    strncpy(addr.sun_path, VAULTAIRE_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        vaultaire_log_err("connect() to %s: %s", VAULTAIRE_SOCKET_PATH, strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

int vaultaire_socket_send_recv(const char *request, char *resp, size_t resp_size) {
    return vaultaire_socket_send_recv_path(NULL, request, resp, resp_size);
}

/* Meme chose, sur un chemin DONNE — ou le chemin de production si NULL.
 *
 * Le controle socket_is_trustworthy n'est applique qu'au chemin de production :
 * un socket de test appartient a l'utilisateur qui lance les tests, pas a root. */
int vaultaire_socket_send_recv_path(const char *chemin, const char *request,
                                     char *resp, size_t resp_size) {
    if (!request) return -1;
    int sock;
    if (chemin) {
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct sockaddr_un ad;
            memset(&ad, 0, sizeof(ad));
            ad.sun_family = AF_UNIX;
            strncpy(ad.sun_path, chemin, sizeof(ad.sun_path) - 1);
            if (connect(sock, (struct sockaddr *)&ad, sizeof(ad)) < 0) {
                close(sock);
                sock = -1;
            }
        }
    } else {
        sock = connect_socket();
    }
    if (sock < 0) return -1;
    /* Ecriture bouclee, pour la meme raison que la lecture : send peut n'ecrire
     * qu'une partie de la requete, et une requete tronquee est un JSON invalide
     * que le daemon rejettera.
     *
     * MSG_NOSIGNAL : si le daemon a ferme entre-temps, on veut EPIPE en retour,
     * pas un signal qui tue le processus appelant. */
    size_t len = strlen(request);
    size_t envoye = 0;
    while (envoye < len) {
        ssize_t n = send(sock, request + envoye, len - envoye, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            vaultaire_log_err("send(): %s", strerror(errno));
            close(sock);
            return -1;
        }
        envoye += (size_t)n;
    }
    if (resp && resp_size > 0) {
        /* Lecture BOUCLEE jusqu'a la fin du flux.
         *
         * Un seul recv ne garantit rien : sur un socket flux, la reponse peut
         * arriver en plusieurs segments. Des que la charge depasse ce que le
         * noyau a mis a disposition, resp contenait un JSON tronque — le champ
         * status restait vide, et l'authentification etait refusee.
         *
         * Le cas se declenche d'autant plus facilement que la reponse porte les
         * cles SSH : une seule cle RSA-4096 en base64 depasse le kilo-octet. */
        size_t total = 0;
        for (;;) {
            ssize_t n = recv(sock, resp + total, resp_size - 1 - total, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                vaultaire_log_err("recv(): %s", strerror(errno));
                close(sock);
                return -1;
            }
            if (n == 0) {
                break;  /* le daemon a ferme : reponse complete */
            }
            total += (size_t)n;
            if (total >= resp_size - 1) {
                /* Tampon plein : on ARRETE et on le DIT. Continuer donnerait une
                 * reponse silencieusement tronquee, donc une decision prise sur
                 * une information incomplete. */
                vaultaire_log_err("reponse du daemon trop longue (%zu octets)", total);
                break;
            }
        }
        resp[total] = '\0';
    }
    close(sock);
    return 0;
}

int vaultaire_socket_send(const char *request) {
    return vaultaire_socket_send_recv(request, NULL, 0);
}


/* --- Sudo group --- */
static const char *sudo_group_candidates[] = { "sudo", "wheel", "admin", "staff", "root" };

/* Execute une commande SANS passer par un shell.
 *
 * # Pourquoi remplacer system()
 *
 * system() passe la chaine a /bin/sh, qui l'interprete : substitution de
 * commandes, expansion de variables, enchainements. Un nom d'utilisateur
 * arrivant dans cette chaine devient du code, execute EN ROOT.
 *
 * execvp recoit un TABLEAU d'arguments. Le noyau les transmet tels quels au
 * programme : aucun shell n'intervient, et un argument contenant « $(id) » est
 * simplement un argument contenant ces caracteres.
 *
 * La liste blanche sur le nom reste en place — deux barrieres valent mieux
 * qu'une, et celle-ci protege aussi les commandes qui recevraient un nom
 * commencant par un tiret.
 *
 * Retourne 0 si la commande a reussi, -1 sinon. */
static int run_no_shell(const char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Indique si un programme est disponible, sans passer par un shell. */
static int programme_disponible(const char *nom) {
    char chemin[PATH_MAX];
    static const char *repertoires[] = {
        "/usr/sbin", "/sbin", "/usr/bin", "/bin"
    };
    for (size_t i = 0; i < sizeof(repertoires) / sizeof(repertoires[0]); i++) {
        int n = snprintf(chemin, sizeof(chemin), "%s/%s", repertoires[i], nom);
        if (n > 0 && (size_t)n < sizeof(chemin) && access(chemin, X_OK) == 0) {
            return 1;
        }
    }
    return 0;
}

int vaultaire_detect_sudo_group(char *group, size_t gsize) {
    for (size_t i = 0; i < sizeof(sudo_group_candidates) / sizeof(sudo_group_candidates[0]); i++) {
        struct group *g = getgrnam(sudo_group_candidates[i]);
        if (g) {
            strncpy(group, sudo_group_candidates[i], gsize - 1);
            group[gsize - 1] = '\0';
            return 0;
        }
    }

    strncpy(group, "sudo", gsize - 1);
    group[gsize - 1] = '\0';

    /* Aucun groupe d'administration : on le cree. Sans shell, la ou
     * l'ancienne version enchainait deux commandes avec « || ». */
    if (programme_disponible("groupadd")) {
        const char *argv[] = { "groupadd", "sudo", NULL };
        (void)run_no_shell(argv);
    }
    return 0;
}

int vaultaire_add_user_to_sudo_group(const char *username) {
    /* La validation est refaite ICI, et non seulement chez l'appelant.
     *
     * Cette fonction est exportee : un futur appelant pourrait oublier de
     * valider. Le controle appartient a l'endroit qui execute, pas a celui qui
     * demande. */
    if (!vaultaire_is_valid_username(username)) {
        vaultaire_log_err("SECURITE: nom d'utilisateur refuse pour l'ajout au groupe sudo");
        return -1;
    }

    char group[64];
    if (vaultaire_detect_sudo_group(group, sizeof(group)) != 0) return -1;

    if (programme_disponible("usermod")) {
        const char *argv[] = { "usermod", "-aG", group, username, NULL };
        return run_no_shell(argv);
    }
    const char *argv[] = { "adduser", username, group, NULL };
    return run_no_shell(argv);
}

int vaultaire_remove_user_from_sudo_group(const char *username) {
    if (!vaultaire_is_valid_username(username)) {
        vaultaire_log_err("SECURITE: nom d'utilisateur refuse pour le retrait du groupe sudo");
        return -1;
    }

    char group[64];
    if (vaultaire_detect_sudo_group(group, sizeof(group)) != 0) return -1;

    if (programme_disponible("gpasswd")) {
        const char *argv[] = { "gpasswd", "-d", username, group, NULL };
        return run_no_shell(argv);
    }
    const char *argv[] = { "deluser", username, group, NULL };
    return run_no_shell(argv);
}

/* Echappe une chaine pour l'inserer dans du JSON — RFC 8259 section 7.
 *
 * # Le defaut que cela corrige
 *
 * La requete etait assemblee ainsi :
 *
 *     snprintf(req, sizeof(req),
 *              "{\"check\":{\"user\":\"%s\",\"password\":\"%s\"}}",
 *              username, password);
 *
 * Sans echappement. Consequence CERTAINE : tout mot de passe contenant un
 * guillemet ou une barre oblique inversee produit un JSON invalide. Le daemon
 * ne peut pas le decoder, la requete est rejetee, et le compte concerne ne peut
 * JAMAIS se connecter — avec pour seul symptome une erreur de decodage sans
 * rapport apparent avec le mot de passe.
 *
 * Consequence de structure : json.Decoder lit la premiere valeur complete et
 * ignore la suite. Un mot de passe de la forme
 *
 *     x\",\"user\":\"admin@dom
 *
 * produit un objet a cle « user » dupliquee, dont Go retient la DERNIERE : la
 * requete cible alors un autre utilisateur que celui qui s'authentifie.
 *
 * # Ce qui est echappe, et pourquoi seulement cela
 *
 * La RFC impose d'echapper le guillemet, la barre oblique inverse et tous les
 * caracteres de controle sous 0x20. Le reste passe tel quel : echapper plus
 * serait inutile, et surtout produirait une chaine que le daemon ne
 * reconnaitrait plus comme egale a ce que l'utilisateur a tape.
 *
 * Les octets >= 0x80 sont laisses intacts : une chaine UTF-8 valide le reste
 * apres echappement, et un mot de passe accentue doit voyager sans deformation.
 *
 * Retourne 0 si la place manque — jamais une chaine tronquee, qui serait un
 * AUTRE mot de passe. */
int vaultaire_json_escape(const char *src, char *out, size_t out_size) {
    if (!src || !out || out_size == 0) {
        return -1;
    }

    size_t j = 0;
    for (size_t i = 0; src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        const char *remplacement = NULL;
        char tampon[7];

        switch (c) {
        case '"':  remplacement = "\\\""; break;
        case '\\': remplacement = "\\\\"; break;
        case '\n': remplacement = "\\n";  break;
        case '\r': remplacement = "\\r";  break;
        case '\t': remplacement = "\\t";  break;
        case '\b': remplacement = "\\b";  break;
        case '\f': remplacement = "\\f";  break;
        default:
            if (c < 0x20) {
                /* Les autres caracteres de controle n'ont pas d'echappement
                 * court : la RFC impose la forme \uXXXX. */
                snprintf(tampon, sizeof(tampon), "\\u%04x", c);
                remplacement = tampon;
            }
            break;
        }

        if (remplacement) {
            size_t n = strlen(remplacement);
            if (j + n >= out_size) return -1;
            memcpy(out + j, remplacement, n);
            j += n;
        } else {
            if (j + 1 >= out_size) return -1;
            out[j++] = (char)c;
        }
    }

    out[j] = '\0';
    return 0;
}

/* Assemble la requete d'authentification, champs echappes.
 *
 * Un point unique de construction : les deux modules PAM l'assemblaient chacun
 * de leur cote, avec le meme defaut recopie. Une correction a un seul endroit
 * en aurait laisse un derriere elle. */
int vaultaire_build_check_request(const char *username, const char *password,
                                  char *out, size_t out_size) {
    char u[512];
    char p[512];

    if (vaultaire_json_escape(username ? username : "", u, sizeof(u)) != 0) {
        vaultaire_log_err("nom d'utilisateur trop long apres echappement");
        return -1;
    }
    if (vaultaire_json_escape(password ? password : "", p, sizeof(p)) != 0) {
        /* Le mot de passe n'est PAS journalise, ni meme sa longueur reelle :
         * ici on sait seulement qu'il ne tient pas. */
        vaultaire_log_err("mot de passe trop long apres echappement");
        return -1;
    }

    int n = snprintf(out, out_size,
                     "{\"check\":{\"user\":\"%s\",\"password\":\"%s\"}}", u, p);
    if (n < 0 || (size_t)n >= out_size) {
        vaultaire_log_err("requete d'authentification trop longue");
        return -1;
    }
    return 0;
}

/* --- JSON helpers (minimal, no external lib) --- */
int vaultaire_json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    if (!json || !key || !out || out_size == 0) return -1;
    out[0] = '\0';
    size_t key_len = strlen(key);
    char search[128];
    if (key_len + 4 >= sizeof(search)) return -1;
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    const char *start = p;
    while (*p && *p != '"') p++;
    if (!*p) return -1;
    size_t len = (size_t)(p - start);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

int vaultaire_json_get_bool(const char *json, const char *key, bool *out) {
    if (!json || !key || !out) return -1;
    size_t key_len = strlen(key);
    char search[128];
    if (key_len + 4 >= sizeof(search)) return -1;
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    *out = (strncmp(p, "true", 4) == 0);
    return 0;
}

/* Lit "ssh_keys":["...","..."].
 *
 * # Pourquoi le contrat de retour compte plus que l'analyse elle-meme
 *
 * L'appelant se sert du resultat pour REECRIRE authorized_keys. Il doit donc
 * pouvoir distinguer deux situations que l'ancienne version rendait
 * identiques — toutes deux « 0, zero cle » :
 *
 *   a) le serveur repond que ce compte n'a PLUS AUCUNE cle. Il faut alors
 *      ecrire un fichier vide, sinon les cles revoquees restent en place et
 *      continuent d'ouvrir la session. C'est le defaut signale.
 *
 *   b) la reponse est illisible — champ absent, tableau non ferme, chaine non
 *      terminee. Ecrire un fichier vide LA priverait de sa cle un compte qui
 *      en a une, sur un simple incident de lecture du socket.
 *
 * D'ou : 0 uniquement si le tableau a ete lu ENTIEREMENT, -1 sinon. Le cas (a)
 * rend 0 avec zero cle, le cas (b) rend -1. Confondre les deux, c'est choisir
 * entre laisser entrer un revoque et verrouiller un ayant droit.
 *
 * En cas d'echec, rien n'est rendu a l'appelant : les cles deja lues sont
 * liberees et *count_out reste a 0. Une liste partielle serait le pire des
 * deux mondes — assez credible pour etre ecrite, incomplete pour de bon.
 */
int vaultaire_json_get_ssh_keys(const char *json, char ***keys_out, size_t *count_out) {
    if (!json || !keys_out || !count_out) return -1;
    *keys_out = NULL;
    *count_out = 0;

    const char *p = strstr(json, "\"ssh_keys\"");
    if (!p) return -1;
    p += strlen("\"ssh_keys\"");
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;

    /* Un tableau, et rien d'autre. « null » arrive des qu'un encodeur JSON
     * serialise une tranche vide non initialisee ; le prendre pour une liste
     * vide effacerait les cles de l'utilisateur. */
    if (*p != '[') return -1;
    p++;

    char **keys = NULL;
    size_t count = 0;
    int erreur = 0;

    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p == ']') break;                 /* fin normale, y compris tableau vide */
        if (*p != '"') { erreur = 1; break; } /* tronque, ou autre chose qu'une chaine */
        p++; /* Sauter le " ouvrant */

        const char *start = p;
        /* Trouver la fin de la string en ignorant les \" (guillemets échappés) */
        while (*p && !(*p == '"' && *(p-1) != '\\')) p++;
        if (*p != '"') { erreur = 1; break; } /* chaine non terminee : reponse coupee */

        size_t raw_len = (size_t)(p - start);
        char *key = malloc(raw_len + 1);
        if (!key) { erreur = 1; break; }

        // Copie intelligente pour supprimer les échappements (ex: \/ -> /)
        size_t j = 0;
        for (size_t i = 0; i < raw_len; i++) {
            if (start[i] == '\\' && i + 1 < raw_len) {
                // On saute le backslash si c'est un slash ou un guillemet échappé
                if (start[i+1] == '/' || start[i+1] == '"' || start[i+1] == '\\') {
                    continue;
                }
            }
            key[j++] = start[i];
        }
        key[j] = '\0';

        char **tmp = realloc(keys, sizeof(char *) * (count + 1));
        if (!tmp) { free(key); erreur = 1; break; }
        keys = tmp;
        keys[count++] = key;
        p++; // Sauter le " fermant
    }

    if (erreur) {
        for (size_t i = 0; i < count; i++) free(keys[i]);
        free(keys);
        return -1;
    }

    *keys_out = keys;
    *count_out = count;
    return 0;
}