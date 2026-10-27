#!/usr/bin/env bash
# Relevé des appels système de l'agent Vaultaire — TO-DO 181.
#
# # Pourquoi
#
# L'unité de l'agent ne porte pas de SystemCallFilter (unite.Exclues) : l'agent
# lance useradd, chage, setfacl, auditctl, nft, grub2-mkconfig… et un filtre
# écrit sans les avoir relevés tuerait l'une d'elles au milieu d'une GPO. Ce
# script fait le relevé, SUR UN POSTE, sans rien bloquer.
#
# # Comment
#
# Un fichier complémentaire de l'unité pose « SystemCallLog=~@system-service »
# (systemd ≥ 247) : chaque appel HORS du groupe @system-service — celui dont un
# filtre partirait — est JOURNALISÉ par le noyau (seccomp, SECCOMP_RET_LOG),
# pour l'agent et pour toutes les commandes qu'il lance. Rien n'est refusé.
#
#   sudo ./releve-appels-agent.sh debut     # pose le relevé, relance l'agent
#   ... appliquer la suite de GPO de la formation, ouvrir des sessions SSH ...
#   sudo ./releve-appels-agent.sh fin       # lit le journal, rend la liste, retire tout
#
#   ./releve-appels-agent.sh analyser <journal>   # la lecture seule, sur un fichier
#
# Le résultat : les appels à AJOUTER à @system-service, avec les programmes qui
# les font. C'est la matière du TO-DO 201 (poser SystemCallFilter).
#
# Pour un systemd < 247 (Rocky 8 : 239), le relevé se fait avec strace :
#   strace -f -c -o /root/releve.txt -p "$(systemctl show -p MainPID --value vaultaire_client)"
# — moins commode : la liste comprend aussi les appels de @system-service.
set -euo pipefail

UNITE=vaultaire_client.service
DOSSIER=/etc/systemd/system/vaultaire_client.service.d
COMPLEMENT=$DOSSIER/90-releve-appels.conf
REPERE=/run/vaultaire/releve-appels.debut

nom_de_l_appel() {
    # ausyscall (paquet audit) traduit un numéro ; sans lui, le numéro reste.
    if command -v ausyscall >/dev/null 2>&1; then
        ausyscall "$1" 2>/dev/null || echo "#$1"
    else
        echo "#$1"
    fi
}

# analyser : lit des lignes d'audit seccomp (journal du noyau ou audit.log) et
# rend « appel  programmes » trié. Les lignes portent type=1326 (noyau) ou
# type=SECCOMP (auditd), exe="…" et syscall=N.
analyser() {
    local source=$1
    # « || true » : aucune ligne n'est un résultat (la liste vide), pas une
    # erreur. Sans lui, set -o pipefail arrêtait « fin » ici, sans retirer le
    # complément (recette du 27/10 ; la liste « vide » du 25/10 venait de là).
    { grep -E 'type=(1326|SECCOMP)' "$source" || true; } |
        sed -nE 's/.*exe="([^"]*)".*syscall=([0-9]+).*/\2 \1/p' |
        sort -u |
        awk '{ p[$1] = (p[$1] ? p[$1] "," : "") $2 } END { for (n in p) print n, p[n] }' |
        sort -n |
        while read -r numero programmes; do
            printf '%-22s %s\n' "$(nom_de_l_appel "$numero")" "$programmes"
        done
}

exiger_root() {
    [ "$(id -u)" = 0 ] || { echo "À lancer en root." >&2; exit 1; }
}

case "${1:-}" in
debut)
    exiger_root
    v=$(systemctl --version | awk 'NR==1 { print $2 }')
    if [ "${v:-0}" -lt 247 ]; then
        echo "systemd $v : SystemCallLog= demande la version 247. Voir l'en-tête du script (strace)." >&2
        exit 1
    fi
    mkdir -p "$DOSSIER" /run/vaultaire
    cat >"$COMPLEMENT" <<'FIN'
# Relevé des appels système (TO-DO 181) — posé par releve-appels-agent.sh,
# retiré par « releve-appels-agent.sh fin ». Ne refuse rien : journalise.
[Service]
SystemCallLog=~@system-service
FIN
    date '+%Y-%m-%d %H:%M:%S' >"$REPERE"
    systemctl daemon-reload
    # Après plusieurs relances rapprochées (install.sh SELinux…), systemd
    # refuse la suivante (« start-limit-hit ») et l'agent reste ARRÊTÉ.
    systemctl reset-failed "$UNITE" 2>/dev/null || true
    systemctl restart "$UNITE"
    echo "Relevé posé, agent relancé. Appliquez maintenant la suite de GPO de la formation"
    echo "(chapitre 6), ouvrez et fermez des sessions SSH, puis : $0 fin"
    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        echo "⚠ auditd ne tourne pas : le noyau limite le débit de ces lignes dans son journal,"
        echo "  et des appels rares peuvent manquer. « systemctl start auditd » de préférence."
    fi
    ;;
fin)
    exiger_root
    [ -f "$REPERE" ] || { echo "Aucun relevé en cours ($REPERE absent)." >&2; exit 1; }
    depuis=$(cat "$REPERE")
    brut=$(mktemp)
    trap 'rm -f "$brut"' EXIT
    if [ -r /var/log/audit/audit.log ] && command -v ausearch >/dev/null 2>&1; then
        ausearch -m SECCOMP --start "${depuis% *}" "${depuis#* }" --raw >"$brut" 2>/dev/null </dev/null || true
    fi
    journalctl -k --since "$depuis" --no-pager >>"$brut" 2>/dev/null || true
    echo "Appels hors de @system-service, depuis le $depuis :"
    resultat=$(analyser "$brut")
    if [ -z "$resultat" ]; then
        echo "  (aucun) — l'agent tiendrait sous « SystemCallFilter=@system-service »"
    else
        echo "$resultat" | sed 's/^/  /'
    fi
    rm -f "$COMPLEMENT" "$REPERE"
    rmdir "$DOSSIER" 2>/dev/null || true
    systemctl daemon-reload
    systemctl reset-failed "$UNITE" 2>/dev/null || true
    systemctl restart "$UNITE"
    echo "Relevé retiré, agent relancé. Reportez la liste dans le TO-DO 201."
    ;;
analyser)
    [ -n "${2:-}" ] && [ -r "$2" ] || { echo "usage : $0 analyser <journal>" >&2; exit 1; }
    analyser "$2"
    ;;
*)
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
