#!/usr/bin/env bash

# ==============================================================================
# 🔧 Installation du client Vaultaire — Rocky Linux et famille RHEL
# ==============================================================================
#
# Le pendant de debian.sh, dont il a repris les précautions (TO-DO 174) :
#
#   - les modules natifs sont éprouvés (ldd) AVANT que PAM ne soit touché. Un
#     module qui ne se charge pas, derrière « default=die », refuse TOUT le
#     monde — root et les comptes locaux compris ;
#   - sshd_config est validé (sshd -t) avant d'être gardé, et remis comme il
#     était sinon ;
#   - les piles PAM sont PRÉPARÉES à côté des originales, puis posées d'un coup
#     à la fin, quand tout ce qui pouvait échouer a échoué ;
#   - chaque original est gardé une fois, sous « .avant-vaultaire » : c'est le
#     fichier à remettre pour sortir la machine de Vaultaire.
#
# Ce qui reste propre à Rocky : les piles login, sshd et gdm-password sont
# ÉCRITES en entier, et non complétées comme sur Debian. Elles s'appuient sur
# system-auth et password-auth, que gère authselect et que ce script ne touche
# pas ; une personnalisation faite directement dans login, sshd ou
# gdm-password est remplacée — sa copie reste dans « .avant-vaultaire ».
#
# ------------------------------------------------------------------------------
# Essai à blanc
# ------------------------------------------------------------------------------
#
#   VAULTAIRE_RACINE=/tmp/essai bash rocky.sh
#
# Tous les chemins sont alors pris sous ce répertoire, et rien n'est demandé au
# système : ni dnf, ni systemctl, ni sshd. C'est ce que jouent les tests, et ce
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

log_info "Début du déploiement de Vaultaire Client (Rocky / RHEL)..."

# ------------------------------------------------------------------------------
# 1. Où cette machine range ses modules
# ------------------------------------------------------------------------------
#
# Là où est pam_unix.so : /usr/lib64/security sur toute Rocky, x86_64 comme
# aarch64. Les bibliothèques NSS sont un cran au-dessus.
PAM_DIR=""
for candidat in "$R/usr/lib64/security" "$R/lib64/security"; do
    if [[ -f "$candidat/pam_unix.so" ]]; then
        PAM_DIR="$candidat"
        break
    fi
done
if [[ -z "$PAM_DIR" ]]; then
    erreur "pam_unix.so introuvable sous /usr/lib64/security : ce script ne sait pas où poser les modules PAM."
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

# Les modules natifs de CETTE famille — TO-DO 173.
#
# Le core envoie un jeu par famille de distributions, chacun compilé sur la
# plus ancienne version prise en charge : vaultaire_client/rocky/ (Rocky 9,
# glibc 2.34, libcrypt.so.2) et vaultaire_client/debian/.
#
# Repli : des modules NON CLASSÉS à la racine — ceux d'un poste de
# développement, compilés sur sa propre machine. Ils ne sont pris que si la
# famille manque, et l'étape 3 refuse ceux qui ne se chargent pas.
MODS="$SRC/vaultaire_client/rocky"
if [[ -f "$MODS/pam_login_custom_module.so" ]]; then
    log_info "Modules natifs de la famille Rocky."
else
    MODS="$SRC/vaultaire_client"
    if [[ -f "$MODS/pam_login_custom_module.so" ]]; then
        log_warn "Modules natifs non classés par famille (compilation de développement) : leur chargement sera vérifié."
    fi
fi

# Déplacement sécurisé (si les fichiers source existent)
[[ -f "$MODS/pam_login_custom_module.so" ]] && mv -f "$MODS"/pam*.so "$PAM_DIR/"
[[ -f "$SRC/vaultaire_client/vaultaire_client" ]] && mv -f "$SRC/vaultaire_client/vaultaire_client" "$R/usr/bin/"
[[ -f "$SRC/client_software.yaml" ]] && mv -f "$SRC/client_software.yaml" "$CONF/.ssh/"
[[ -f "$MODS/libnss_vaultaire.so.2" ]] && mv -f "$MODS/libnss_vaultaire.so.2" "$NSS_DIR/"
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

# Clé du core héritée d'une installation précédente.
#
# Ce script n'efface pas .ssh : une réinstallation sur une machine déjà enrôlée
# y retrouve donc le serveurpublickey.pem d'avant. Si le core a été réinstallé
# entre-temps — base recréée, donc nouvelle paire de clés — ce fichier est
# périmé.
#
# Une clé périmée ne produit pas d'erreur claire : l'agent chiffre sa poignée de
# main avec, le core ne sait pas la déchiffrer, ne répond pas, et l'agent finit
# par signaler « Erreur lors de la lecture du header : EOF ». Rien n'y désigne la
# clé, et le diagnostic peut prendre des heures.
#
# On la supprime donc quand une empreinte vient d'être déposée. L'agent la
# redemandera au core au premier contact, et la comparera à cette empreinte :
# la reprise est sûre, puisqu'une clé qui ne correspond pas sera refusée.
#
# Sans empreinte déposée, on ne touche à rien : on n'aurait alors rien pour
# valider la clé de remplacement.
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
#
# libxcrypt-compat n'est plus installé d'office : les modules de la famille
# Rocky, compilés sur Rocky 9, lient la libcrypt.so.2 du système. Seuls des
# modules compilés ailleurs demandent encore la .so.1 — et ldd le dit.
if essai; then LDD="${VAULTAIRE_LDD:-ldd}"; else LDD=ldd; fi

manques_de() {
    # « not found » couvre les deux cas : une bibliothèque absente, et une
    # version de symbole que la glibc du poste ne porte pas.
    "$LDD" "$1" 2>&1 | grep -i 'not found' || true
}

paquet_pour() {
    case "$1" in
        libcrypt.so.1*) echo libxcrypt-compat ;;
        libcrypt.so.2*) echo libxcrypt ;;
        libpam.so.0*) echo pam ;;
        libcurl.so.4*) echo libcurl ;;   # modules d'avant le TO-DO 173 seulement
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
    systeme dnf install -y -q "${PAQUETS[@]}"
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
# L'agent le complète ensuite lui-même (section « learned ») avec la liste
# qu'il apprend du cluster, et n'en réécrit jamais la section « servers ».
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
# AVANT de toucher à NSS, SSH et PAM, et ce n'est pas un détail d'ordre.
#
# Les piles PAM posées plus bas meurent quand le module ne joint pas l'agent
# (default=die), sans repli : sur une machine où l'agent ne démarre pas, plus
# aucun compte du domaine n'ouvre de session.
#
# « --install-unit » joue d'abord le contrôle de démarrage (configuration,
# identité, clé privée — le même que « --check »), et n'écrit l'unité que s'il
# passe. S'il échoue, on s'arrête ICI : cette exécution n'a alors rien changé
# aux piles PAM, et la machine reste joignable comme elle l'était.
#
# L'unité est écrite par le binaire et non par ce script : elle lance
# « vaultaire_client --check » avant chaque démarrage, ce qu'un binaire plus
# ancien ne connaît pas. Posée à côté de lui, elle l'empêcherait de démarrer.
# Écrite par lui, elle ne peut pas être en avance sur lui.
log_info "Contrôle de démarrage de l'agent, puis écriture de son unité systemd..."
if ! systeme /usr/bin/vaultaire_client --install-unit; then
    erreur "L'agent ne peut pas démarrer sur cette machine : voir le contrôle ci-dessus."
    echo "         Installation interrompue AVANT la configuration de NSS, SSH et PAM :" >&2
    echo "         cette exécution n'a pas touché aux piles d'authentification." >&2
    exit 1
fi

# 4bis. Ancien répertoire de journaux
#
# Une version antérieure du socle écrivait certaines familles dans
# /var/log/vaultaire_client/, en dur, alors que le journal principal va dans
# /var/log/vaultaire/. Retiré s'il est VIDE ; signalé sinon plutôt que
# supprimé — il peut contenir la trace d'un incident qu'on cherche encore.
#
# La rotation, elle, est faite par l'agent lui-même : rien à installer ici.
if [[ -d "$R/var/log/vaultaire_client" ]]; then
    if rmdir "$R/var/log/vaultaire_client" 2>/dev/null; then
        log_info "Ancien répertoire /var/log/vaultaire_client retiré (vide)."
    else
        log_warn "/var/log/vaultaire_client contient des fichiers d'une version antérieure, que rien ne fait tourner."
    fi
fi

# ------------------------------------------------------------------------------
# 5. Les piles PAM : préparées maintenant, posées à la fin
# ------------------------------------------------------------------------------
#
# Écrites à côté des originales, sous « .vaultaire-nouveau », et posées toutes
# ensemble à l'étape 8. Si une étape échoue entre-temps, aucune n'est posée :
# une pile « login » branchée et une pile « sshd » qui ne l'est pas feraient
# deux vérités sur la même machine.
#
# Dans chacune, le module de Vaultaire ouvre l'authentification :
#
#   auth  [success=done ignore=ignore default=die]  pam_…_module.so
#   auth  substack  system-auth | password-auth
#
#   success=done   un compte de l'annuaire accepté par le core entre
#   ignore=ignore  un compte LOCAL (sans @domaine) : le module s'efface, et la
#                  pile de la distribution continue — c'est la porte de secours
#   default=die    un compte de l'annuaire refusé n'est pas rattrapé par son
#                  mot de passe local
log_info "Préparation des piles PAM (login, sshd, gdm)..."
PAM_PRETS=("$R/etc/pam.d/login" "$R/etc/pam.d/sshd")
mkdir -p "$R/etc/pam.d"

cat > "$R/etc/pam.d/login.vaultaire-nouveau" <<'EOF'
#%PAM-1.0
auth        [success=done ignore=ignore default=die]    pam_login_custom_module.so
auth        substack       system-auth
auth        include        postlogin

account     required       pam_nologin.so
account     include        system-auth

password    include        system-auth

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     required       pam_selinux.so open
session     required       pam_logout_custom_module.so
session     required       pam_namespace.so
session     optional       pam_keyinit.so force revoke
session     include        system-auth
session     include        postlogin
-session    optional       pam_ck_connector.so
EOF

cat > "$R/etc/pam.d/sshd.vaultaire-nouveau" <<'EOF'
#%PAM-1.0
auth        [success=done ignore=ignore default=die]    pam_ssh_auth_module.so
auth        substack       password-auth
auth        include        postlogin

account     required       pam_nologin.so
account     include        password-auth

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     required       pam_selinux.so open env_params
session     required       pam_namespace.so
session     optional       pam_keyinit.so force revoke
session     optional       pam_motd.so
session     include        password-auth
session     include        postlogin
EOF

GDM=0
if [[ -f "$R/etc/pam.d/gdm-password" ]]; then
    GDM=1
    PAM_PRETS+=("$R/etc/pam.d/gdm-password")
    cat > "$R/etc/pam.d/gdm-password.vaultaire-nouveau" <<'EOF'
#%PAM-1.0
auth        [success=done ignore=ignore default=bad]    pam_login_custom_module.so
auth        [success=done ignore=ignore default=bad]    pam_selinux_permit.so
auth        substack       password-auth
auth        optional       pam_gnome_keyring.so
auth        include        postlogin

account     required       pam_nologin.so
account     include        password-auth

password    substack       password-auth
-password   optional       pam_gnome_keyring.so use_authtok

session     required       pam_selinux.so close
session     required       pam_loginuid.so
session     optional       pam_console.so
-session    optional       pam_ck_connector.so
session     required       pam_selinux.so open
session     required       pam_logout_custom_module.so
session     optional       pam_keyinit.so force revoke
session     required       pam_namespace.so
session     include        password-auth
session     optional       pam_gnome_keyring.so auto_start
session     include        postlogin
EOF
fi

abandonner_pam() {
    local f
    for f in "${PAM_PRETS[@]}"; do rm -f "${f}.vaultaire-nouveau"; done
}

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
    abandonner_pam
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
        abandonner_pam
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
# fois, sous « .avant-vaultaire » : rejouer le script ne l'écrase pas par une
# pile déjà branchée.
log_info "Mise en place des piles PAM..."
for f in "${PAM_PRETS[@]}"; do
    if [[ -f "$f" && ! -f "${f}.avant-vaultaire" ]]; then
        cp -p "$f" "${f}.avant-vaultaire"
    fi
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
log_info "Activation du service systemd et rechargement de SSHD..."
systeme systemctl daemon-reload
# « enable » puis « restart », et non « enable --now » : sur une machine déjà
# installée le service tourne, « --now » ne ferait donc rien, et l'ancien
# binaire resterait en mémoire. Sur une machine neuve, « restart » vaut « start ».
systeme systemctl enable vaultaire_client.service
systeme systemctl restart vaultaire_client.service
# « try- » : un sshd arrêté n'est pas démarré pour autant, et un sshd qui tourne
# relit sa configuration — déjà validée par sshd -t.
if essai; then
    systeme systemctl try-reload-or-restart sshd
else
    systemctl try-reload-or-restart sshd 2>/dev/null \
        || log_warn "Service SSH non rechargé : la nouvelle configuration sera lue à son prochain démarrage."
fi

log_success "Installation de Vaultaire Client terminée avec succès !"
