#!/bin/sh
# Diagnostic de la resolution des comptes du domaine.
#
#   sudo ./diagnose.sh [utilisateur@domaine]
#
# A executer SUR LA MACHINE CLIENTE, celle ou l'on tente de se connecter.
#
# ============================================================================
# POURQUOI CE SCRIPT
# ============================================================================
#
# Quand une connexion echoue avec :
#
#     Permission denied (publickey).
#
# et qu'AUCUN journal Vaultaire n'apparait, cela veut dire que sshd a refuse le
# compte AVANT d'executer quoi que ce soit de Vaultaire. Le probleme est donc en
# amont de tout ce que les journaux pourraient montrer — et c'est precisement ce
# qui rend ce cas difficile a diagnostiquer : il n'y a rien a lire.
#
# La chaine complete comporte six maillons. Ce script les teste un par un, dans
# l'ordre, et s'arrete au premier qui casse.
set -u

VERT=""; ROUGE=""; JAUNE=""; NEUTRE=""
if [ -t 1 ]; then
    VERT="$(printf '\033[32m')"; ROUGE="$(printf '\033[31m')"
    JAUNE="$(printf '\033[33m')"; NEUTRE="$(printf '\033[0m')"
fi

ECHECS=0
ok()    { printf "  %s[ OK ]%s %s\n" "$VERT" "$NEUTRE" "$1"; }
ko()    { printf "  %s[FAIL]%s %s\n" "$ROUGE" "$NEUTRE" "$1"; ECHECS=$((ECHECS+1)); }
avert() { printf "  %s[ ?? ]%s %s\n" "$JAUNE" "$NEUTRE" "$1"; }
info()  { printf "         %s\n" "$1"; }
titre() { printf "\n%s\n" "$1"; }

UTILISATEUR="${1:-}"
if [ -z "$UTILISATEUR" ]; then
    UTILISATEUR="diagnostic-$$@$(hostname -d 2>/dev/null || echo vaultaire.fr)"
    info "Aucun utilisateur fourni, test avec un nom jetable : $UTILISATEUR"
fi

MAP=/etc/vaultaire/uid.map
UIDSOCK=/run/vaultaire/public/uid.sock
PAMSOCK=/run/vaultaire/pam.sock

# ---------------------------------------------------------------------------
titre "1. Le module NSS est-il installe ?"
# ---------------------------------------------------------------------------
SO=""
for chemin in /lib64/libnss_vaultaire.so.2 \
              /lib/x86_64-linux-gnu/libnss_vaultaire.so.2 \
              /usr/lib64/libnss_vaultaire.so.2 \
              /usr/lib/x86_64-linux-gnu/libnss_vaultaire.so.2; do
    if [ -f "$chemin" ]; then SO="$chemin"; break; fi
done

if [ -z "$SO" ]; then
    ko "libnss_vaultaire.so.2 introuvable"
    info "La libc ne peut pas charger un module absent. Deployez-le :"
    info "  cp libnss_vaultaire.so.2 /lib64/ && chmod 755 /lib64/libnss_vaultaire.so.2"
else
    ok "trouve : $SO"
    info "$(ls -l "$SO" | awk '{print $1, $3, $5" octets", $6, $7, $8}')"
fi

# ---------------------------------------------------------------------------
titre "2. Est-ce la version RECENTE du module ?"
# ---------------------------------------------------------------------------
#
# C'est le controle le plus utile du script. Un binaire ancien produit
# exactement le meme symptome qu'un bug, et rien ne le distingue a l'oeil.
#
# La version recente contient deux chaines que l'ancienne n'a pas : le chemin de
# la carte et celui du socket d'allocation.
if [ -z "$SO" ]; then
    info "(saute : module absent)"
elif ! command -v strings >/dev/null 2>&1; then
    avert "commande « strings » absente, version non verifiable"
    info "Installez binutils, ou comparez la date du fichier avec votre build."
else
    A_LA_CARTE=0; A_LE_SOCKET=0
    strings "$SO" 2>/dev/null | grep -q "/etc/vaultaire/uid.map" && A_LA_CARTE=1
    strings "$SO" 2>/dev/null | grep -q "/run/vaultaire/public/uid.sock" && A_LE_SOCKET=1

    if [ "$A_LA_CARTE" = 1 ] && [ "$A_LE_SOCKET" = 1 ]; then
        ok "module a jour (carte + service d'allocation)"
    elif [ "$A_LA_CARTE" = 1 ]; then
        ko "module INTERMEDIAIRE : il lit la carte mais n'interroge pas l'agent"
        info "C'est la version qui casse toute PREMIERE connexion."
        info "Recompilez (auto-compil.sh) et redeployez le .so."
    else
        ko "module ANCIEN : il attribue le meme UID a tout le monde"
        info "Recompilez (auto-compil.sh) et redeployez le .so."
    fi
fi

# ---------------------------------------------------------------------------
titre "3. nsswitch.conf declare-t-il vaultaire ?"
# ---------------------------------------------------------------------------
LIGNE="$(grep -E '^passwd:' /etc/nsswitch.conf 2>/dev/null | head -1)"
if [ -z "$LIGNE" ]; then
    ko "aucune ligne passwd: dans /etc/nsswitch.conf"
else
    info "$LIGNE"
    if echo "$LIGNE" | grep -qw vaultaire; then
        ok "vaultaire est declare"
        # files DOIT venir en premier : sinon l'UID reel du compte local est
        # masque par celui de la carte, et toute divergence devient invisible.
        SANS_PASSWD="$(echo "$LIGNE" | sed 's/^passwd: *//')"
        PREMIER="$(echo "$SANS_PASSWD" | awk '{print $1}')"
        if [ "$PREMIER" = "files" ]; then
            ok "files vient en premier"
        else
            avert "files ne vient pas en premier (premier = $PREMIER)"
            info "Attendu : passwd: files vaultaire"
        fi
    else
        ko "vaultaire n'est PAS declare : le module n'est jamais consulte"
        info "Corrigez : sed -i '/^passwd:/ s/\$/ vaultaire/' /etc/nsswitch.conf"
    fi
fi

# ---------------------------------------------------------------------------
titre "4. L'agent tourne-t-il ?"
# ---------------------------------------------------------------------------
# Le motif s'arrete a 15 caracteres, et ce n'est pas un oubli.
#
# Le noyau tronque le nom de processus (comm) a TASK_COMM_LEN-1 = 15 octets.
# « vaultaire_client » en fait 16 : le systeme voit « vaultaire_clien ».
# Un « pgrep -x vaultaire_client » ne trouve donc JAMAIS l'agent, alors que
# systemctl le montre bien en cours d'execution — un faux negatif qui envoie
# chercher le probleme la ou il n'est pas.
#
# On ne peut pas non plus utiliser -f : il compare la ligne de commande entiere
# et matcherait ce script lui-meme, qui mentionne le nom.
if pgrep -x 'vaultaire_clien' >/dev/null 2>&1 || pgrep -x vaultaire_client >/dev/null 2>&1; then
    ok "processus vaultaire_client present"
    info "pid : $(pgrep -x 'vaultaire_clien' 2>/dev/null | tr '\n' ' ')"
else
    ko "aucun processus vaultaire_client"
    info "Sans agent, aucun utilisateur inconnu ne peut obtenir d'identite,"
    info "et personne ne peut authentifier qui que ce soit."
    info "  systemctl status vaultaire-client"
fi

if [ -d /var/log/vaultaire ]; then
    NB="$(find /var/log/vaultaire -type f 2>/dev/null | wc -l)"
    if [ "$NB" -eq 0 ]; then
        avert "/var/log/vaultaire est VIDE"
        info "L'agent n'a jamais rien ecrit : il ne demarre pas, ou il s'arrete"
        info "immediatement. Lancez-le au premier plan pour voir l'erreur :"
        info "  /opt/vaultaire/vaultaire_client"
    else
        ok "$NB fichier(s) de journal present(s)"
    fi
else
    avert "/var/log/vaultaire n'existe pas"
fi

# ---------------------------------------------------------------------------
titre "5. Les sockets sont-ils en place ?"
# ---------------------------------------------------------------------------
if [ -S "$UIDSOCK" ]; then
    ok "socket d'allocation present"
    info "$(ls -l "$UIDSOCK" | awk '{print $1, $3":"$4}')"
    MODE="$(stat -c '%a' "$UIDSOCK" 2>/dev/null)"
    case "$MODE" in
        *6|*7) ok "joignable par les processus non privilegies (mode $MODE)" ;;
        *)     ko "mode $MODE : NSS ne pourra pas l'atteindre depuis un processus ordinaire" ;;
    esac
else
    ko "socket d'allocation absent : $UIDSOCK"
    info "L'agent ne l'a pas cree. Version ancienne de l'agent, ou agent arrete."
fi

if [ -S "$PAMSOCK" ]; then
    ok "canal PAM present"
    MODE="$(stat -c '%a' "$PAMSOCK" 2>/dev/null)"
    [ "$MODE" = "600" ] && ok "canal PAM en 600 (correct)" \
                        || avert "canal PAM en $MODE, attendu 600"
elif [ -S /tmp/vaultaire_client.sock ]; then
    ko "l'agent utilise encore /tmp/vaultaire_client.sock"
    info "Agent ANCIEN face a des modules recents (ou l'inverse)."
    info "Les binaires et les modules doivent etre deployes ENSEMBLE."
else
    ko "aucun canal PAM : ni $PAMSOCK, ni l'ancien dans /tmp"
fi

# ---------------------------------------------------------------------------
titre "6. Dialogue direct avec le service d'allocation"
# ---------------------------------------------------------------------------
#
# On court-circuite NSS pour savoir si l'agent repond. Si ce test passe mais que
# le suivant echoue, le probleme est dans le module ; s'il echoue ici, il est
# dans l'agent.
if [ -S "$UIDSOCK" ]; then
    REPONSE=""
    if command -v socat >/dev/null 2>&1; then
        REPONSE="$(printf '%s\n' "$UTILISATEUR" | timeout 3 socat - "UNIX-CONNECT:$UIDSOCK" 2>/dev/null)"
    elif command -v python3 >/dev/null 2>&1; then
        REPONSE="$(timeout 3 python3 - "$UIDSOCK" "$UTILISATEUR" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode())
print(s.recv(256).decode().strip())
PY
)"
    else
        avert "ni socat ni python3 : test direct impossible"
    fi

    if [ -n "$REPONSE" ]; then
        ok "l'agent repond : $REPONSE"
    elif command -v socat >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
        ko "l'agent ne repond rien pour $UTILISATEUR"
        info "Nom refuse par la liste blanche, ou plafond atteint."
        info "Regardez le journal de l'agent."
    fi
else
    info "(saute : pas de socket)"
fi

# ---------------------------------------------------------------------------
titre "7. Resolution reelle, par la libc"
# ---------------------------------------------------------------------------
#
# LE test qui compte : c'est exactement ce que fait sshd avant d'authentifier.
RES="$(getent passwd "$UTILISATEUR" 2>/dev/null)"
if [ -n "$RES" ]; then
    ok "getent passwd $UTILISATEUR"
    info "$RES"
    UID_OBTENU="$(echo "$RES" | cut -d: -f3)"
    if [ "$UID_OBTENU" = "0" ]; then
        ko "UID 0 : c'est root, jamais acceptable"
    elif [ "$UID_OBTENU" = "5001" ] && [ -n "$SO" ] && ! strings "$SO" 2>/dev/null | grep -q uid.map; then
        avert "UID 5001 issu de l'ANCIEN module : tous les utilisateurs le partagent"
    fi
else
    ko "getent passwd $UTILISATEUR ne rend rien"
    info "C'est LA cause du « Permission denied (publickey) » sans journal :"
    info "sshd considere le compte inexistant et refuse AVANT d'executer"
    info "AuthorizedKeysCommand — donc rien de Vaultaire n'est lance."
fi

# ---------------------------------------------------------------------------
titre "8. Etat de la carte"
# ---------------------------------------------------------------------------
if [ -f "$MAP" ]; then
    NB="$(grep -cvE '^#|^$' "$MAP" 2>/dev/null || echo 0)"
    ok "$MAP : $NB entree(s)"
    [ "$NB" -gt 0 ] && grep -vE '^#|^$' "$MAP" | head -5 | sed 's/^/         /'
    MODE="$(stat -c '%a' "$MAP" 2>/dev/null)"
    [ "$MODE" = "644" ] && ok "mode 644 (lisible par NSS sans privilege)" \
                        || avert "mode $MODE, attendu 644"
else
    avert "$MAP absent"
    info "Normal si aucun utilisateur ne s'est encore connecte."
fi

# ---------------------------------------------------------------------------
printf "\n"
if [ "$ECHECS" -eq 0 ]; then
    printf "%sAucun probleme detecte.%s\n" "$VERT" "$NEUTRE"
    printf "Si la connexion echoue quand meme, le probleme est en aval :\n"
    printf "  sshd -T | grep -i authorizedkeyscommand\n"
    printf "  journalctl -u sshd -n 50\n"
else
    printf "%s%d probleme(s) detecte(s)%s — traitez-les dans l'ordre :\n" \
           "$ROUGE" "$ECHECS" "$NEUTRE"
    printf "chaque maillon depend des precedents.\n"
fi

exit $([ "$ECHECS" -eq 0 ] && echo 0 || echo 1)
