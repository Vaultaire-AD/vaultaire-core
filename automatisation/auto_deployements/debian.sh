#!/usr/bin/env bash

# ==============================================================================
# 🔧 Installation du client Vaultaire — Debian et Ubuntu (TO-DO 71)
# ==============================================================================
#
# Le pendant de rocky.sh. `create -c … -join` choisissait bien ce script sur un
# poste Debian ou Ubuntu, mais il n'existait pas : l'installation échouait au
# transfert.
#
# Mêmes étapes, même ordre, mêmes fichiers reçus du core. Ce qui diffère tient
# à la distribution, et à rien d'autre :
#
#   - les modules natifs vont dans le répertoire MULTIARCH
#     (/lib/x86_64-linux-gnu/security), repéré d'après pam_unix.so plutôt
#     qu'écrit en dur : il change avec l'architecture ;
#   - les piles PAM ne sont PAS réécrites. Celles de Debian tiennent en
#     « @include common-auth » et changent d'une version à l'autre ; ce script
#     y INSÈRE ses lignes et garde le reste, avec une copie de l'original ;
#   - le service SSH s'appelle « ssh » ;
#   - rien n'est installé par apt tant que rien ne manque.
#
# Deux précautions de plus que rocky.sh, parce qu'un module PAM qui ne se
# charge pas ferme la machine à TOUT le monde, comptes locaux compris :
#
#   - les modules sont éprouvés (ldd) AVANT que PAM ne soit touché ;
#   - sshd_config est validé (sshd -t) avant d'être gardé.
#
# ------------------------------------------------------------------------------
# Essai à blanc
# ------------------------------------------------------------------------------
#
#   VAULTAIRE_RACINE=/tmp/essai bash debian.sh
#
# Tous les chemins sont alors pris sous ce répertoire, et rien n'est demandé au
# système : ni apt, ni systemctl, ni sshd. C'est ce que jouent les tests, et ce
# qui permet de LIRE ce que le script ferait à une machine avant de le lui
# faire. Sans cette variable, le script agit pour de bon.

set -euo pipefail

R="${VAULTAIRE_RACINE:-}"
R="${R%/}"

# Couleurs pour les logs
C_INFO='\033[1;34m[INFO]\033[0m'
C_SUCCESS='\033[1;32m[SUCCÈS]\033[0m'
C_WARN='\033[1;33m[ATTENTION]\033[0m'
C_ERR='\033[1;31m[ERREUR]\033[0m'

log_info() { echo -e "${C_INFO} $1"; }
log_success() { echo -e "${C_SUCCESS} $1"; }
log_warn() { echo -e "${C_WARN} $1"; }
erreur() { echo -e "${C_ERR} $1" >&2; }

essai() { [[ -n "$R" ]]; }

# systeme lance une commande qui agit sur la machine. À blanc, elle est dite et
# non faite.
systeme() {
    if essai; then
        echo "[essai] $*"
        return 0
    fi
    "$@"
}

if essai; then
    log_warn "Essai à blanc sous ${R} : rien n'est demandé au système."
elif [[ $EUID -ne 0 ]]; then
    erreur "Ce script doit être exécuté en tant que root."
    exit 1
fi

log_info "Début du déploiement de Vaultaire Client (Debian / Ubuntu)..."

# ------------------------------------------------------------------------------
# 1. Où cette machine range ses modules
# ------------------------------------------------------------------------------
#
# D'après pam_unix.so : là où il est, PAM cherchera les nôtres. Et les
# bibliothèques NSS sont un cran au-dessus. Écrire « x86_64-linux-gnu » en dur
# aurait posé les modules au mauvais endroit sur un poste arm64 — où PAM, ne
# les trouvant pas, aurait refusé tout le monde.
PAM_DIR=""
for racine_lib in "$R/lib" "$R/usr/lib"; do
    [[ -d "$racine_lib" ]] || continue
    trouve="$(find "$racine_lib" -maxdepth 3 -name pam_unix.so -print -quit 2>/dev/null || true)"
    if [[ -n "$trouve" ]]; then
        PAM_DIR="$(dirname "$trouve")"
        break
    fi
done
if [[ -z "$PAM_DIR" ]]; then
    erreur "pam_unix.so introuvable sous /lib et /usr/lib : ce script ne sait pas où poser les modules PAM."
    exit 1
fi
NSS_DIR="$(dirname "$PAM_DIR")"
log_info "Modules PAM : ${PAM_DIR#"$R"} — bibliothèque NSS : ${NSS_DIR#"$R"}"

# ------------------------------------------------------------------------------
# 2. Déplacement et préparation des fichiers
# ------------------------------------------------------------------------------
log_info "Mise en place des binaires, bibliothèques et configurations..."
SRC="$R/opt/vaultaire"
CONF="$R/etc/vaultaire_client"
mkdir -p "$SRC/vaultaire_client" "$CONF/.ssh" "$R/var/log/vaultaire" "$R/usr/bin"

chmod 700 "$R/var/log/vaultaire"

# Déplacement sécurisé (si les fichiers source existent)
[[ -f "$SRC/vaultaire_client/pam_login_custom_module.so" ]] && mv -f "$SRC"/vaultaire_client/pam*.so "$PAM_DIR/"
[[ -f "$SRC/vaultaire_client/vaultaire_client" ]] && mv -f "$SRC/vaultaire_client/vaultaire_client" "$R/usr/bin/"
[[ -f "$SRC/client_software.yaml" ]] && mv -f "$SRC/client_software.yaml" "$CONF/.ssh/"
[[ -f "$SRC/vaultaire_client/libnss_vaultaire.so.2" ]] && mv -f "$SRC/vaultaire_client/libnss_vaultaire.so.2" "$NSS_DIR/"
compgen -G "$SRC/*.pem" > /dev/null && mv -f "$SRC"/*.pem "$CONF/.ssh/"

# Empreinte de la clé publique du core.
#
# Elle arrive par ce canal — SCP au-dessus de SSH — et non par le réseau
# Ducky : c'est tout l'intérêt. L'agent compare la clé qu'il recevra plus tard
# par la trame « askkey » à cette empreinte, et refuse si elles diffèrent.
#
# Sans ce fichier, l'agent accepte la première clé venue, en le signalant dans
# son journal. Le déploiement reste donc possible sans, mais moins sûr.
[[ -f "$SRC/core_key_fingerprint" ]] && mv -f "$SRC/core_key_fingerprint" "$CONF/.ssh/"

# Clé du core héritée d'une installation précédente : supprimée quand une
# empreinte vient d'être déposée, pour que l'agent la redemande et la vérifie.
# Sans empreinte on ne touche à rien — on n'aurait rien pour valider la
# remplaçante. Le raisonnement complet est dans rocky.sh.
if [[ -f "$CONF/.ssh/core_key_fingerprint" ]]; then
    rm -f "$CONF/.ssh/serveurpublickey.pem"
    log_info "Clé du core éventuellement héritée supprimée : elle sera redemandée puis vérifiée contre l'empreinte."
fi

# Application stricte des permissions
[[ -f "$NSS_DIR/libnss_vaultaire.so.2" ]] && chmod 755 "$NSS_DIR/libnss_vaultaire.so.2"
[[ -f "$R/usr/bin/vaultaire_client" ]] && chmod 750 "$R/usr/bin/vaultaire_client"
chmod 700 -R "$CONF/"
find "$CONF/.ssh/" -type f -exec chmod 400 {} +

MODULES=(pam_login_custom_module.so pam_logout_custom_module.so pam_ssh_auth_module.so)
for mod in "${MODULES[@]}"; do
    if [[ -f "$PAM_DIR/$mod" ]]; then
        chmod 755 "$PAM_DIR/$mod"
        essai || chown root:root "$PAM_DIR/$mod"
    fi
done

# ------------------------------------------------------------------------------
# 3. Les modules se chargent-ils sur CETTE machine ?
# ------------------------------------------------------------------------------
#
# Ils sont compilés ailleurs. S'il leur manque une bibliothèque, ou s'ils
# demandent une glibc plus récente que celle du poste, PAM ne pourra pas les
# ouvrir — et une ligne « default=die » sur un module qui ne s'ouvre pas refuse
# TOUT le monde, comptes locaux et root compris. On le découvrirait à la
# première connexion, c'est-à-dire trop tard.
#
# ldd le dit maintenant. Ce qui manque est installé si un paquet le fournit ;
# sinon le script s'arrête ICI, avant d'avoir touché à PAM.
if essai; then LDD="${VAULTAIRE_LDD:-ldd}"; else LDD=ldd; fi

manques_de() {
    # « not found » couvre les deux cas : une bibliothèque absente, et une
    # version de symbole que la glibc du poste ne porte pas.
    "$LDD" "$1" 2>&1 | grep -i 'not found' || true
}

paquet_pour() {
    case "$1" in
        libcurl.so.4*) echo libcurl4 ;;
        libcrypt.so.1*) echo libcrypt1 ;;
        libpam.so.0*) echo libpam0g ;;
        *) echo "" ;;
    esac
}

log_info "Vérification du chargement des modules natifs..."
A_VERIFIER=()
for mod in "${MODULES[@]}"; do
    [[ -f "$PAM_DIR/$mod" ]] && A_VERIFIER+=("$PAM_DIR/$mod")
done
[[ -f "$NSS_DIR/libnss_vaultaire.so.2" ]] && A_VERIFIER+=("$NSS_DIR/libnss_vaultaire.so.2")

if [[ ${#A_VERIFIER[@]} -lt 4 ]]; then
    erreur "Modules natifs incomplets : ${#A_VERIFIER[@]} sur 4 en place (trois modules PAM et la bibliothèque NSS)."
    erreur "Installation interrompue AVANT la configuration de NSS, SSH et PAM."
    exit 1
fi

PAQUETS=()
for f in "${A_VERIFIER[@]}"; do
    while read -r ligne; do
        [[ -z "$ligne" ]] && continue
        lib="$(awk '{print $1}' <<<"$ligne")"
        paquet="$(paquet_pour "$lib")"
        [[ -n "$paquet" ]] && PAQUETS+=("$paquet")
    done < <(manques_de "$f")
done
if [[ ${#PAQUETS[@]} -gt 0 ]]; then
    mapfile -t PAQUETS < <(printf '%s\n' "${PAQUETS[@]}" | sort -u)
    log_info "Bibliothèques manquantes, installation : ${PAQUETS[*]}"
    DEBIAN_FRONTEND=noninteractive systeme apt-get install -y -q "${PAQUETS[@]}"
fi

ECHEC_CHARGEMENT=0
for f in "${A_VERIFIER[@]}"; do
    reste="$(manques_de "$f")"
    if [[ -n "$reste" ]]; then
        erreur "${f#"$R"} ne se charge pas sur cette machine :"
        echo "$reste" | sed 's/^/           /' >&2
        ECHEC_CHARGEMENT=1
    fi
done
if [[ $ECHEC_CHARGEMENT -ne 0 ]]; then
    erreur "Un module qui ne se charge pas fermerait la machine à tous les comptes."
    erreur "Installation interrompue AVANT la configuration de NSS, SSH et PAM : rien n'y a été changé."
    echo "         Les modules doivent être compilés pour une glibc au plus aussi récente que celle de ce poste" >&2
    echo "         ($("$LDD" --version 2>/dev/null | head -n1 || echo 'version inconnue'))." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 4. Configuration JSON du client : la liste des cores
# ------------------------------------------------------------------------------
#
# Le core qui installe dépose client_conf.json à côté des clés : TOUS les cores
# exposés du cluster, dans l'ordre où la découverte (04_04) les servirait.
#
# Repli, si le core n'a rien déposé (aucun core exposé et en ligne) : l'adresse
# du core qui exécute ce script, lue dans SSH_CONNECTION, sur le port Ducky par
# défaut. C'est au moins un nœud joignable depuis cette machine.
log_info "Écriture du fichier de configuration client..."
if [[ -f "$SRC/client_conf.json" ]]; then
    mv -f "$SRC/client_conf.json" "$CONF/client_conf.json"
    log_info "Liste des cores reçue du core : $(grep -c '"ip"' "$CONF/client_conf.json") core(s)."
else
    CORE_IP="${SSH_CONNECTION:-}"
    CORE_IP="${CORE_IP%% *}"
    if [[ -z "$CORE_IP" ]]; then
        erreur "Aucune liste de cores reçue et SSH_CONNECTION vide : adresse du core inconnue."
        exit 1
    fi
    log_warn "Aucune liste de cores reçue : repli sur le core qui installe (${CORE_IP}:6666)."
    cat > "$CONF/client_conf.json" <<EOF
{
    "servers": [
        {
            "ip": "${CORE_IP}",
            "port": 6666
        }
    ]
}
EOF
fi
chmod 600 "$CONF/client_conf.json"

# ------------------------------------------------------------------------------
# 4ter. Contrôle de démarrage, puis unité systemd — TO-DO 112
# ------------------------------------------------------------------------------
#
# AVANT de toucher à NSS, SSH et PAM. « --install-unit » joue d'abord le
# contrôle de démarrage (configuration, identité, clé privée), et n'écrit
# l'unité que s'il passe. S'il échoue, on s'arrête ICI : cette exécution n'a
# alors rien changé aux piles PAM, et la machine reste joignable comme elle
# l'était. L'unité est écrite par le binaire, qui seul sait ce qu'il sait lancer.
log_info "Contrôle de démarrage de l'agent, puis écriture de son unité systemd..."
if ! systeme /usr/bin/vaultaire_client --install-unit; then
    erreur "L'agent ne peut pas démarrer sur cette machine : voir le contrôle ci-dessus."
    echo "         Installation interrompue AVANT la configuration de NSS, SSH et PAM :" >&2
    echo "         cette exécution n'a pas touché aux piles d'authentification." >&2
    exit 1
fi

# 4bis. Ancien répertoire de journaux : retiré s'il est vide, signalé sinon.
if [[ -d "$R/var/log/vaultaire_client" ]]; then
    if rmdir "$R/var/log/vaultaire_client" 2>/dev/null; then
        log_info "Ancien repertoire /var/log/vaultaire_client retire (vide)."
    else
        log_warn "/var/log/vaultaire_client contient des fichiers d'une version anterieure, que rien ne fait tourner."
    fi
fi

# ------------------------------------------------------------------------------
# 5. Les piles PAM : préparées maintenant, posées à la fin
# ------------------------------------------------------------------------------
#
# Les piles de Debian ne sont pas réécrites. Elles tiennent en une ligne,
# « @include common-auth », qui renvoie à ce que pam-auth-update compose pour
# CETTE machine — sssd, fprintd, une politique de mots de passe. Les remplacer
# par un texte figé retirerait tout cela sans le dire.
#
# Ce script y insère donc ses lignes, juste avant « @include common-auth » :
#
#   auth  [success=done ignore=ignore default=die]  pam_…_module.so
#
#   success=done   un compte de l'annuaire accepté par le core entre
#   ignore=ignore  un compte LOCAL (sans @domaine) : le module s'efface, et la
#                  pile de la distribution continue comme avant
#   default=die    un compte de l'annuaire refusé n'est pas rattrapé par son
#                  mot de passe local
#
# Chaque ligne posée porte « # vaultaire » : c'est ce qui permet de rejouer le
# script sans la doubler, et de la retirer à la main.
#
# Les fichiers sont PRÉPARÉS ici, à côté des originaux, et posés d'un coup à
# l'étape 8. Si l'un d'eux ne se laisse pas modifier, aucun n'est touché : une
# pile « login » branchée et une pile « sshd » qui ne l'est pas feraient deux
# vérités sur la même machine.
PAM_PRETS=()

preparer_pile() {
    local fichier="$1" ligne_auth="$2" ligne_session="${3:-}"
    local nouveau="${fichier}.vaultaire-nouveau"

    awk -v auth="$ligne_auth" -v session="$ligne_session" '
        /# vaultaire[[:space:]]*$/ { next }
        !a && /^[[:space:]]*@include[[:space:]]+common-auth([[:space:]]|$)/ {
            print auth "  # vaultaire"; a = 1
        }
        { print }
        session != "" && !s && /^[[:space:]]*@include[[:space:]]+common-session([[:space:]]|$)/ {
            print session "  # vaultaire"; s = 1
        }
        END {
            if (!a) exit 3
            if (session != "" && !s) print session "  # vaultaire"
        }
    ' "$fichier" > "$nouveau" || {
        rm -f "$nouveau"
        return 1
    }
    PAM_PRETS+=("$fichier")
}

abandonner_pam() {
    local f
    for f in "${PAM_PRETS[@]:-}"; do
        [[ -n "$f" ]] && rm -f "${f}.vaultaire-nouveau"
    done
    erreur "$1"
    echo "         « @include common-auth » n'y figure pas : la pile a été personnalisée, et ce script" >&2
    echo "         ne devine pas où s'y brancher. Ajoutez la ligne à la main, avant l'authentification" >&2
    echo "         locale, puis relancez :" >&2
    echo "           $2" >&2
    echo "         Installation interrompue : aucune pile PAM n'a été modifiée." >&2
    exit 1
}

AUTH_LOGIN="auth    [success=done ignore=ignore default=die]    pam_login_custom_module.so"
AUTH_SSHD="auth    [success=done ignore=ignore default=die]    pam_ssh_auth_module.so"
AUTH_GDM="auth    [success=done ignore=ignore default=bad]    pam_login_custom_module.so"
SESSION_FIN="session required    pam_logout_custom_module.so"

log_info "Préparation des piles PAM (login, sshd, gdm)..."
for requis in login sshd; do
    if [[ ! -f "$R/etc/pam.d/$requis" ]]; then
        erreur "/etc/pam.d/$requis absent : $( [[ $requis == sshd ]] && echo 'openssh-server est-il installé ?' || echo 'PAM est-il installé ?')"
        echo "         Installation interrompue : aucune pile PAM n'a été modifiée." >&2
        exit 1
    fi
done
preparer_pile "$R/etc/pam.d/login" "$AUTH_LOGIN" "$SESSION_FIN" \
    || abandonner_pam "/etc/pam.d/login ne peut pas être branché." "$AUTH_LOGIN"
preparer_pile "$R/etc/pam.d/sshd" "$AUTH_SSHD" \
    || abandonner_pam "/etc/pam.d/sshd ne peut pas être branché." "$AUTH_SSHD"
GDM=0
if [[ -f "$R/etc/pam.d/gdm-password" ]]; then
    preparer_pile "$R/etc/pam.d/gdm-password" "$AUTH_GDM" "$SESSION_FIN" \
        || abandonner_pam "/etc/pam.d/gdm-password ne peut pas être branché." "$AUTH_GDM"
    GDM=1
fi

# ------------------------------------------------------------------------------
# 6. Configuration NSS (idempotente)
# ------------------------------------------------------------------------------
log_info "Configuration de NSS..."
for db in passwd group; do
    if ! grep -qE "^${db}:.*\\bvaultaire\\b" "$R/etc/nsswitch.conf"; then
        sed -i "/^${db}:/ s/$/ vaultaire/" "$R/etc/nsswitch.conf"
    fi
done

# ------------------------------------------------------------------------------
# 7. Configuration SSHD, validée avant d'être gardée
# ------------------------------------------------------------------------------
log_info "Configuration sécurisée de SSHD..."
SSHD_CONF="$R/etc/ssh/sshd_config"
if [[ ! -f "$SSHD_CONF" ]]; then
    erreur "/etc/ssh/sshd_config absent : openssh-server est-il installé ?"
    for f in "${PAM_PRETS[@]}"; do rm -f "${f}.vaultaire-nouveau"; done
    exit 1
fi
[[ -f "${SSHD_CONF}.avant-vaultaire" ]] || cp -p "$SSHD_CONF" "${SSHD_CONF}.avant-vaultaire"
cp -p "$SSHD_CONF" "${SSHD_CONF}.vaultaire-precedent"

# Nettoyage des directives existantes pour éviter les conflits
for directive in UsePAM KbdInteractiveAuthentication ChallengeResponseAuthentication AuthenticationMethods PubkeyAuthentication Include AuthorizedKeysCommand AuthorizedKeysCommandUser; do
    sed -i "/^${directive}/d" "$SSHD_CONF"
done

# Ré-injection propre
cat >> "$SSHD_CONF" <<'EOF'
UsePAM yes
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
AuthorizedKeysCommand /usr/bin/vaultaire_client --fetch-key %u
AuthorizedKeysCommandUser root
Include /etc/ssh/sshd_config.d/*.conf
EOF

# Désactivation propre dans les fichiers d'inclusion (.conf)
if [[ -d "$R/etc/ssh/sshd_config.d/" ]]; then
    sed -i 's/^\(KbdInteractiveAuthentication\|PasswordAuthentication\).*/#\0 disabled_by_vaultaire/' "$R"/etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
fi

# Une configuration que sshd refuse l'empêcherait de redémarrer : la machine
# resterait joignable jusqu'au prochain redémarrage, puis plus du tout.
if ! essai && command -v sshd >/dev/null 2>&1; then
    if ! sshd -t 2>/tmp/vaultaire_sshd_t.$$; then
        erreur "sshd refuse la configuration produite :"
        sed 's/^/           /' /tmp/vaultaire_sshd_t.$$ >&2
        rm -f /tmp/vaultaire_sshd_t.$$
        mv -f "${SSHD_CONF}.vaultaire-precedent" "$SSHD_CONF"
        for f in "${PAM_PRETS[@]}"; do rm -f "${f}.vaultaire-nouveau"; done
        erreur "sshd_config remis comme il était. Installation interrompue : aucune pile PAM n'a été modifiée."
        exit 1
    fi
    rm -f /tmp/vaultaire_sshd_t.$$
fi
rm -f "${SSHD_CONF}.vaultaire-precedent"

# ------------------------------------------------------------------------------
# 8. Pose des piles PAM
# ------------------------------------------------------------------------------
#
# Tout ce qui pouvait échouer a échoué avant. Chaque original est gardé une
# fois, sous « .avant-vaultaire » : c'est le fichier à remettre pour sortir la
# machine de Vaultaire.
log_info "Mise en place des piles PAM..."
for f in "${PAM_PRETS[@]}"; do
    [[ -f "${f}.avant-vaultaire" ]] || cp -p "$f" "${f}.avant-vaultaire"
    chmod 644 "${f}.vaultaire-nouveau"
    mv -f "${f}.vaultaire-nouveau" "$f"
done

if [[ $GDM -eq 1 ]]; then
    mkdir -p "$R/etc/dconf/db/gdm.d"
    cat > "$R/etc/dconf/db/gdm.d/10-vaultaire-userlist" <<'EOF'
[org/gnome/login-screen]
disable-user-list=true
EOF
    essai || dconf update 2>/dev/null || true
    log_success "PAM GDM configuré avec succès."
else
    log_info "GDM absent, pile PAM graphique ignorée."
fi

# ------------------------------------------------------------------------------
# 9. Nettoyage des sources d'installation temporaires
# ------------------------------------------------------------------------------
log_info "Nettoyage des fichiers temporaires..."
rm -rf "$SRC"

# ------------------------------------------------------------------------------
# 10. Activation et redémarrage des services
# ------------------------------------------------------------------------------
log_info "Activation du service systemd et rechargement de SSH..."
systeme systemctl daemon-reload
# « enable » puis « restart », et non « enable --now » : sur une machine déjà
# installée le service tourne, « --now » ne ferait donc rien, et l'ancien
# binaire resterait en mémoire.
systeme systemctl enable vaultaire_client.service
systeme systemctl restart vaultaire_client.service
# Le service s'appelle « ssh » sur Debian et Ubuntu. « try- » : sur un poste où
# SSH est activé par socket et n'a pas encore servi, il n'y a rien à recharger —
# la configuration sera lue à la première connexion.
if essai; then
    systeme systemctl try-reload-or-restart ssh
else
    systemctl try-reload-or-restart ssh 2>/dev/null \
        || systemctl try-reload-or-restart sshd 2>/dev/null \
        || log_warn "Service SSH non rechargé : la nouvelle configuration sera lue à son prochain démarrage."
fi

log_success "Installation de Vaultaire Client terminée avec succès !"
