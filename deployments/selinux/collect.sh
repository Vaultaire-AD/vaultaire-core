#!/bin/sh
# Phase 1 — collecte des refus SELinux liés aux modules Vaultaire.
#
#   sudo ./collect.sh
#
# A executer SUR UNE MACHINE CLIENTE, de preference une machine de test.
#
# ============================================================================
# CE QUE FAIT CE SCRIPT, ET POURQUOI DANS CET ORDRE
# ============================================================================
#
# 1. Passe SELinux en PERMISSIVE — pas en disabled.
#
#    La difference est le coeur de la demarche. En enforcing, SELinux bloque au
#    PREMIER refus : le chemin d'execution s'arrete la, et les refus suivants
#    n'ont jamais lieu. On les decouvre donc un par un, en autant d'iterations
#    qu'il y a de problemes.
#
#    En permissive, rien n'est bloque mais TOUT est journalise. Le chemin
#    s'execute jusqu'au bout et l'on collecte l'ensemble des refus en une passe.
#
#    Disabled, en revanche, ne journalise rien du tout : ce serait perdre la
#    seule chose qu'on cherche.
#
# 2. Desactive les regles « dontaudit ».
#
#    C'est le piege que presque tout le monde rencontre. La politique de
#    reference contient des regles qui SUPPRIMENT la journalisation de certains
#    refus, jugees trop bruyantes. Ces refus se produisent quand meme et cassent
#    le fonctionnement, mais n'apparaissent nulle part.
#
#    On collecte donc avec « semodule -DB », et on remet l'etat normal a la fin.
#
# 3. Vide le journal d'audit, exerce les chemins, extrait les refus.
set -eu

VERT=""; ROUGE=""; JAUNE=""; NEUTRE=""
if [ -t 1 ]; then
    VERT="$(printf '\033[32m')"; ROUGE="$(printf '\033[31m')"
    JAUNE="$(printf '\033[33m')"; NEUTRE="$(printf '\033[0m')"
fi
titre() { printf "\n%s=== %s ===%s\n" "$JAUNE" "$1" "$NEUTRE"; }
avert() { printf "  %s[ ?? ]%s %s\n" "$JAUNE" "$NEUTRE" "$1"; }
ok()    { printf "  %s[ OK ]%s %s\n" "$VERT" "$NEUTRE" "$1"; }
ko()    { printf "  %s[FAIL]%s %s\n" "$ROUGE" "$NEUTRE" "$1"; }
info()  { printf "         %s\n" "$1"; }

SORTIE="${VAULTAIRE_SELINUX_OUT:-/tmp/vaultaire-selinux}"
UTILISATEUR="${1:-}"

[ "$(id -u)" -eq 0 ] || { echo "Ce script doit tourner en root."; exit 1; }
command -v getenforce >/dev/null 2>&1 || { echo "SELinux absent de cette machine."; exit 1; }

MODE_INITIAL="$(getenforce)"
MAP_SAUVE=""
mkdir -p "$SORTIE"

# Retour a l'etat initial quoi qu'il arrive — y compris si l'on interrompt le
# script au clavier. Laisser une machine en permissive avec les dontaudit
# desactives serait pire que le probleme qu'on cherche a resoudre.
restaurer() {
    printf "\n"
    titre "Restauration de l'etat initial"
    semodule -B >/dev/null 2>&1 && ok "regles dontaudit retablies"
    if [ -n "${MAP_SAUVE:-}" ] && [ -f "$MAP_SAUVE" ]; then
        cp -a "$MAP_SAUVE" "$MAP" && ok "carte des identifiants restauree"
    fi
    if [ "$MODE_INITIAL" = "Enforcing" ]; then
        setenforce 1 && ok "SELinux remis en enforcing"
    else
        info "SELinux etait deja en $MODE_INITIAL, rien a remettre"
    fi
}
trap restaurer EXIT INT TERM

titre "Etat de depart"
info "SELinux : $MODE_INITIAL"
info "Distribution : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
info "Resultats dans : $SORTIE"

# ---------------------------------------------------------------------------
titre "1. Passage en permissive et desactivation des dontaudit"
# ---------------------------------------------------------------------------
setenforce 0 2>/dev/null && ok "SELinux en permissive (rien n'est bloque, tout est journalise)"

if semodule -DB >/dev/null 2>&1; then
    ok "regles dontaudit desactivees"
    info "Sans cela, une partie des refus reste INVISIBLE : la politique de"
    info "reference supprime volontairement leur journalisation."
else
    ko "semodule -DB a echoue : certains refus resteront invisibles"
fi

# ---------------------------------------------------------------------------
titre "2. Contexte des acteurs"
# ---------------------------------------------------------------------------
#
# Sans ces informations, la politique ne peut pas etre ecrite : il faut savoir
# QUELS domaines demandent l'acces, et sous QUEL type sont les fichiers.
{
    echo "# Contextes releves le $(date -Is)"
    echo
    echo "## Domaine de l'agent"
    ps -eZ 2>/dev/null | grep -i vaultaire || echo "(agent non trouve dans ps -eZ)"
    echo
    echo "## Domaine de sshd"
    ps -eZ 2>/dev/null | grep -E 'sshd' | head -5
    echo
    echo "## Types des fichiers Vaultaire"
    ls -dZ /etc/vaultaire /etc/vaultaire/uid.map \
           /run/vaultaire /run/vaultaire/pam.sock \
           /run/vaultaire/public /run/vaultaire/public/uid.sock \
           /var/log/vaultaire \
           /usr/bin/vaultaire_client 2>&1
    echo
    echo "## Modules NSS et PAM"
    ls -Z /lib64/libnss_vaultaire.so.2 2>&1
    ls -Z /lib64/security/pam_*custom*.so /lib64/security/pam_ssh_auth_module.so 2>&1
} > "$SORTIE/contextes.txt"
ok "contextes releves dans $SORTIE/contextes.txt"
sed 's/^/         /' "$SORTIE/contextes.txt" | head -25

# ---------------------------------------------------------------------------
titre "3. Remise a zero du journal d'audit"
# ---------------------------------------------------------------------------
#
# On repere l'instant present plutot que d'effacer le journal : effacer
# detruirait des traces qui peuvent servir a autre chose, et le systeme d'audit
# n'est pas la propriete de Vaultaire.
DEBUT="$(date '+%m/%d/%Y %H:%M:%S')"
ok "marqueur pose a $DEBUT"

# ---------------------------------------------------------------------------
titre "4. Exercice des chemins"
# ---------------------------------------------------------------------------
#
# Chaque appel ci-dessous emprunte un chemin different du code. Il faut les
# parcourir TOUS : un refus qui ne se produit pas ne se collecte pas, et
# manquera dans la politique — pour ressurgir en production.

if [ -z "$UTILISATEUR" ]; then
    UTILISATEUR="collecte-$$@$(hostname -d 2>/dev/null || echo vaultaire.fr)"
fi
info "Utilisateur de test : $UTILISATEUR"

# 4a-prealable. On MET DE COTE la carte des identifiants.
#
#     Sans cela, un utilisateur deja present y est resolu immediatement et le
#     module NSS n'ouvre jamais le socket d'allocation — le chemin le plus
#     susceptible d'etre refuse n'est donc pas exerce, et son refus manque a la
#     collecte pour ressurgir en production.
#
#     Constate lors de la premiere collecte : aucun refus sur uid.map ni sur
#     uid.sock, alors que ce sont les deux nouveautes du module.
MAP=/etc/vaultaire/uid.map
MAP_SAUVE=""
if [ -f "$MAP" ]; then
    MAP_SAUVE="$SORTIE/uid.map.sauvegarde"
    cp -a "$MAP" "$MAP_SAUVE"
    : > "$MAP"
    ok "carte mise de cote (sauvegarde : $MAP_SAUVE)"
    info "Le chemin « utilisateur inconnu -> socket d'allocation » sera donc exerce."
fi

# 4a. Resolution NSS depuis un contexte NON confine (votre shell).
#     Sert de temoin : si meme celle-ci echoue, le probleme n'est pas SELinux.
getent passwd "$UTILISATEUR" >/dev/null 2>&1 \
    && ok "resolution depuis un shell root : repond" \
    || info "resolution depuis un shell root : ne repond pas"

# 4b. Resolution depuis le contexte de SSHD — LE cas qui compte.
#
#     runcon fait tourner une commande dans un autre contexte. C'est la seule
#     facon de reproduire ce que vit sshd sans passer par une vraie connexion.
if command -v runcon >/dev/null 2>&1; then
    # -r system_r en plus du type.
    #
    # « runcon -t sshd_t » seul conserve le ROLE courant, unconfined_r, et la
    # politique n'autorise pas unconfined_r a porter le type sshd_t : runcon
    # echoue alors AVANT meme de lancer getent. On lit « ECHOUE » et l'on croit
    # a un refus sur la resolution, alors que rien n'a ete resolu du tout.
    #
    # C'est un faux positif rencontre lors de la premiere collecte.
    ERR="$(runcon -r system_r -t sshd_t getent passwd "$UTILISATEUR" 2>&1 >/dev/null)" && RC=0 || RC=$?
    if [ "$RC" -eq 0 ]; then
        ok "resolution dans le contexte sshd_t : repond"
    elif [ -n "$ERR" ]; then
        avert "runcon n'a pas pu changer de contexte : $ERR"
        info "Le test n'a rien mesure. Seule une VRAIE connexion SSH tranchera."
    else
        ko "resolution dans le contexte sshd_t : ECHOUE"
        info "C'est exactement ce que vit sshd. La difference avec 4a"
        info "designe SELinux sans ambiguite."
    fi
else
    info "runcon absent : installez policycoreutils pour ce test"
fi

# 4c. Une VRAIE connexion SSH, si l'on peut en declencher une.
#
#     Le test le plus fidele : il emprunte le chemin complet, y compris
#     AuthorizedKeysCommand et la pile PAM.
info ""
info "Declenchez MAINTENANT une connexion SSH depuis un autre poste :"
info "    ssh $UTILISATEUR@$(hostname -I 2>/dev/null | awk '{print $1}')"
info ""
printf "         Appuyez sur Entree une fois la tentative faite (ou tout de suite pour sauter)... "
read -r _ || true

# 4d. Redemarrage de l'agent : couvre la creation des repertoires et sockets.
if systemctl is-active vaultaire_client >/dev/null 2>&1; then
    systemctl restart vaultaire_client && ok "agent redemarre (creation des sockets exercee)"
    sleep 2
fi

# ---------------------------------------------------------------------------
titre "5. Extraction des refus"
# ---------------------------------------------------------------------------
BRUT="$SORTIE/avc-brut.log"
: > "$BRUT"

if command -v ausearch >/dev/null 2>&1; then
    ausearch -m avc,user_avc,selinux_err -ts $DEBUT 2>/dev/null >> "$BRUT" || true
fi
# Le journal du noyau en complement : auditd n'est pas toujours installe, et
# les refus y apparaissent alors uniquement via dmesg.
journalctl -k --since "$DEBUT" 2>/dev/null | grep -i 'avc:' >> "$BRUT" || true

NB="$(grep -c 'denied' "$BRUT" 2>/dev/null || echo 0)"
if [ "$NB" -eq 0 ]; then
    ok "aucun refus enregistre"
    info "Soit tout est deja autorise, soit les chemins n'ont pas ete exerces."
    info "Verifiez que vous avez bien declenche une connexion a l'etape 4c."
else
    ko "$NB refus enregistre(s)"
fi

# --- Refus concernant Vaultaire uniquement ---------------------------------
#
# Le journal contient les refus de toute la machine. On isole ce qui nous
# concerne, sinon la politique generee autoriserait des choses sans rapport.
FILTRE="$SORTIE/avc-vaultaire.log"
grep -Ei 'vaultaire|nsswitch|sshd_t.*(sock_file|unix_stream)' "$BRUT" > "$FILTRE" 2>/dev/null || true
NBV="$(grep -c 'denied' "$FILTRE" 2>/dev/null || echo 0)"
info "dont $NBV concernant Vaultaire → $FILTRE"

if [ "$NBV" -gt 0 ]; then
    printf "\n"
    info "Refus concernant Vaultaire :"
    grep 'denied' "$FILTRE" | sed 's/^/         /' | head -20
fi

# --- Proposition de politique ----------------------------------------------
if command -v audit2allow >/dev/null 2>&1 && [ "$NBV" -gt 0 ]; then
    audit2allow -i "$FILTRE" > "$SORTIE/audit2allow.te" 2>/dev/null || true
    ok "proposition brute d'audit2allow → $SORTIE/audit2allow.te"
    info "A LIRE, jamais a appliquer telle quelle : audit2allow propose parfois"
    info "des regles bien plus larges que necessaire, et n'a aucune idee de"
    info "l'intention. Elle sert de point de comparaison avec vaultaire.te."
fi

printf "\n"
titre "Suite"
info "1. Relisez $FILTRE"
info "2. Comparez avec deployments/selinux/vaultaire.te"
info "3. Installez : sudo ./install.sh"
info ""
info "Envoyez $FILTRE et $SORTIE/contextes.txt si vous voulez une relecture."
