#!/usr/bin/env bash
# =============================================================================
# Vaultaire — jeu d'essai RBAC pour la pre-prod
# =============================================================================
#
# Construit une arborescence de domaines, groupes, permissions et utilisateurs
# conçue pour que CHAQUE compte isole UN comportement du moteur de permissions,
# puis produit la matrice de vérification manuelle.
#
# -----------------------------------------------------------------------------
# CE QUE CE SCRIPT PEUT ET NE PEUT PAS VÉRIFIER — à lire avant de s'en servir
# -----------------------------------------------------------------------------
#
# Le socket local exécute TOUTE commande sous l'identité `vaultaire`, sans
# authentification (voir core/vaultairegoroutine/list_goroutine.go et
# command.HandleClientCLI). Ce socket EST un accès superadmin : sa seule
# protection est le mode 0600 du fichier.
#
# Conséquence directe, et c'est la limite structurante de ce script :
#
#     ON NE PEUT PAS TESTER UN REFUS RBAC DEPUIS LE SOCKET LOCAL.
#     Toute commande y passe, puisqu'elle passe en superadmin.
#
# Ce script fait donc deux choses distinctes :
#
#   1. Il PROVISIONNE et vérifie automatiquement ce qui est vérifiable ici :
#      que les entités existent, et surtout que les actions RBAC sont
#      réellement STOCKÉES avec la valeur voulue. C'est utile — une faute de
#      frappe dans une clé d'action produit une permission qui ne s'applique
#      jamais, sans que rien ne le signale.
#
#   2. Il produit une MATRICE DE VÉRIFICATION MANUELLE : pour chaque compte,
#      son mot de passe et la liste de ce qui doit marcher et de ce qui doit
#      être refusé. L'application effective des droits se vérifie en se
#      connectant à l'interface web, en LDAP, ou via vaultaire_ctl — trois
#      chemins où l'appelant est un vrai utilisateur soumis au RBAC.
#
# Automatiser le volet 2 supposerait de passer par vaultaire_ctl avec une clé
# SSH par compte de test. C'est faisable et c'est la suite logique ; ça n'est
# pas fait ici pour que le script reste sans dépendance et lisible.
#
# -----------------------------------------------------------------------------
# TOTP
# -----------------------------------------------------------------------------
# Aucun second facteur n'est activé : les groupes créés ici ont tous
# mfa_required à FALSE (valeur par défaut). Les comptes se connectent donc avec
# leur seul mot de passe, ce qui est le but pour un jeu d'essai.
#
# =============================================================================

set -uo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

VAULTAIRE_HOME="${VAULTAIRE_HOME:-/opt/vaultaire}"
CLI="${VAULTAIRE_CLI:-${VAULTAIRE_HOME}/bin/vaultaire_cli}"
SOCKET="${VAULTAIRE_SOCKET:-${VAULTAIRE_HOME}/vaultaire.sock}"
REPORT="${VAULTAIRE_REPORT:-${VAULTAIRE_HOME}/rbac_report.md}"

# Préfixe commun à toute entité créée ici.
#
# Il sert à deux choses : repérer le jeu d'essai d'un coup d'œil dans
# l'interface, et permettre à --clean de ne supprimer QUE ce que ce script a
# créé. Sans préfixe, un nettoyage un peu large emporterait des comptes réels.
PREFIX="rbac"

# Racine des domaines de test. Volontairement distincte de vaultaire.fr, le
# domaine d'amorçage, pour qu'aucune manipulation ici ne touche l'identité
# protégée.
ROOT_DOMAIN="rbac-test.fr"
DOM_PARIS="paris.${ROOT_DOMAIN}"
DOM_DEV="dev.paris.${ROOT_DOMAIN}"
DOM_LYON="lyon.${ROOT_DOMAIN}"

BIRTHDATE="01/01/1990"

# Mot de passe : motif fixe et lisible, sans caractère susceptible d'être
# refusé par SanitizeInput ni d'être interprété par le shell. C'est un jeu
# d'essai de pre-prod, la robustesse du mot de passe n'est pas le sujet — sa
# prévisibilité, si.
password_for() { echo "Vlt-${1}-preprod"; }

# -----------------------------------------------------------------------------
# Sortie
# -----------------------------------------------------------------------------

if [ -t 1 ]; then
    C_OK=$'\033[32m'; C_KO=$'\033[31m'; C_WARN=$'\033[33m'
    C_TITLE=$'\033[1;36m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_OK=""; C_KO=""; C_WARN=""; C_TITLE=""; C_DIM=""; C_OFF=""
fi

PASS=0; FAIL=0
FAILURES=()

title()  { printf '\n%s=== %s ===%s\n' "$C_TITLE" "$1" "$C_OFF"; }
info()   { printf '%s  %s%s\n' "$C_DIM" "$1" "$C_OFF"; }
ok()     { PASS=$((PASS+1)); printf '  %s[OK]%s   %s\n' "$C_OK" "$C_OFF" "$1"; }
ko()     { FAIL=$((FAIL+1)); FAILURES+=("$1 — $2"); printf '  %s[ECHEC]%s %s : %s\n' "$C_KO" "$C_OFF" "$1" "$2"; }
warn()   { printf '  %s[!]%s    %s\n' "$C_WARN" "$C_OFF" "$1"; }
fatal()  { printf '\n%s[FATAL]%s %s\n\n' "$C_KO" "$C_OFF" "$1" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Accès au serveur
# -----------------------------------------------------------------------------

# vlt exécute une commande et retourne sa sortie.
#
# Le CLI retourne 0 même sur une erreur métier — il transmet la commande au
# socket et affiche la réponse. Le code de sortie ne dit donc rien : c'est le
# TEXTE de la réponse qu'il faut examiner. Toutes les vérifications ci-dessous
# reposent là-dessus, jamais sur $?.
vlt() {
    "$CLI" "$@" 2>&1
}

# vlt_ok exécute une commande et échoue si la réponse ressemble à une erreur.
vlt_ok() {
    local label="$1"; shift
    local out
    out="$(vlt "$@")"
    if echo "$out" | grep -qiE 'erreur|error|refus|denied|introuvable|invalide'; then
        ko "$label" "$(echo "$out" | head -2 | tr '\n' ' ')"
        return 1
    fi
    ok "$label"
    return 0
}

# vlt_quiet exécute sans rien vérifier : pour les opérations dont l'échec est
# acceptable (suppression d'une entité qui n'existe pas encore).
vlt_quiet() { vlt "$@" >/dev/null 2>&1 || true; }

# -----------------------------------------------------------------------------
# Vérifications préalables
# -----------------------------------------------------------------------------

preflight() {
    title "Vérifications préalables"

    [ -x "$CLI" ] || fatal "CLI introuvable ou non exécutable : $CLI
  Le binaire est monté depuis cmd/vaultaire_server/ — vérifiez le volume du
  service vaultaire-ad dans deployments/pre-prod/docker-compose.yml."
    info "CLI      : $CLI"

    [ -S "$SOCKET" ] || fatal "socket absent : $SOCKET
  Le serveur n'est pas démarré, ou il a échoué avant d'ouvrir son socket.
  Regardez : docker logs vaultaire-ad"
    info "socket   : $SOCKET"

    # Un aller-retour réel : le socket peut exister alors que le serveur ne
    # répond plus, par exemple s'il est bloqué sur la base.
    #
    # On teste le message d'erreur de connexion du CLI, PAS le fait que la
    # réponse soit vide. Une liste vide est une réponse parfaitement valide —
    # sur une base neuve, ou après un --clean — et la traiter comme une panne
    # rendrait le script inutilisable précisément quand on en a besoin.
    local probe
    probe="$(vlt get -u 2>&1)"
    if echo "$probe" | grep -qi 'erreur connexion\|connection refused\|no such file'; then
        fatal "le serveur ne répond pas sur le socket.
  Réponse : $(echo "$probe" | head -1)
  Vérifiez que la base est joignable : docker logs vaultaire-ad | tail -30"
    fi
    if [ -z "$probe" ]; then
        warn "l'annuaire ne contient aucun utilisateur — inhabituel, mais on continue"
    fi
    info "réponse  : serveur joignable"

    info "rapport  : $REPORT"
}

# -----------------------------------------------------------------------------
# Définition du jeu d'essai
# -----------------------------------------------------------------------------
#
# ARBORESCENCE DES DOMAINES
#
#   rbac-test.fr
#   ├── paris.rbac-test.fr
#   │   └── dev.paris.rbac-test.fr      <- deux niveaux : teste la propagation
#   └── lyon.rbac-test.fr
#
# Deux niveaux sous paris ne sont pas décoratifs : c'est le seul moyen de
# distinguer une permission « (1:paris) » d'une permission « (0:paris) ». Avec
# un seul niveau, les deux se comportent pareil et le test ne prouve rien.
#
# DEUX FAMILLES DE COMPTES
#
#   - les CIBLES vivent dans les domaines et n'ont aucun droit. Elles existent
#     pour être vues, ou pas vues.
#   - les ACTEURS portent chacun une permission distincte, dans un groupe qui
#     leur est propre. Un groupe par acteur, parce qu'une permission s'attache
#     à un groupe et vaut pour tous ses membres : les mutualiser mélangerait
#     les droits qu'on cherche justement à isoler.

# Groupes porteurs de domaine, où vivent les cibles.
DOMAIN_GROUPS=(
    "${PREFIX}_dom_root:${ROOT_DOMAIN}"
    "${PREFIX}_dom_paris:${DOM_PARIS}"
    "${PREFIX}_dom_dev:${DOM_DEV}"
    "${PREFIX}_dom_lyon:${DOM_LYON}"
)

# Cibles : nom:groupe
TARGET_USERS=(
    "${PREFIX}_cible_root:${PREFIX}_dom_root"
    "${PREFIX}_cible_paris:${PREFIX}_dom_paris"
    "${PREFIX}_cible_dev:${PREFIX}_dom_dev"
    "${PREFIX}_cible_lyon:${PREFIX}_dom_lyon"
)

# Acteurs.
#
# Format : identifiant|permission|description courte
# Les actions sont posées dans apply_actions(), une fonction par acteur, parce
# qu'elles ne se réduisent pas à une liste plate (certaines prennent un domaine
# et un mode de propagation).
ACTORS=(
    "t01|${PREFIX}_p01_lecture_globale|Lecture de tout, sur tous les domaines"
    "t02|${PREFIX}_p02_paris_strict|Lecture de paris SANS propagation"
    "t03|${PREFIX}_p03_paris_propage|Lecture de paris AVEC propagation"
    "t04|${PREFIX}_p04_ecriture_paris|Ecriture limitee a paris"
    "t05|${PREFIX}_p05_sans_webadmin|Droits RBAC mais PAS de web_admin"
    "t06|${PREFIX}_p06_webadmin_seul|web_admin seul, aucun droit RBAC"
    "t07|${PREFIX}_p07_killswitch|Kill switch sans droit de suppression"
    "t08|${PREFIX}_p08_offboarding|Kill switch AVEC droit de suppression"
    "t09|${PREFIX}_p09_audit|Lecture des journaux uniquement"
    "t10|${PREFIX}_p10_mfa|Reinitialisation du second facteur"
    "t11|${PREFIX}_p11_multi_domaine|Lecture paris OU lyon, ecriture paris"
    "t12|${PREFIX}_p12_piege_global|web_admin restreint a un domaine (doit echouer)"
)

# apply_actions pose les actions RBAC d'une permission.
#
# Chaque bloc est commenté par CE QU'IL PROUVE, pas par ce qu'il fait : la
# commande est déjà lisible, l'intention ne l'est pas.
apply_actions() {
    local id="$1" perm="$2"

    case "$id" in
    t01)
        # Référence positive. Si ce compte échoue quelque part, le problème
        # n'est pas dans le filtrage par domaine mais en amont.
        vlt_ok "  $perm : web_admin=all"          update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:get:user=all"      update -pu "$perm" read:get:user all
        vlt_ok "  $perm : read:get:group=all"     update -pu "$perm" read:get:group all
        vlt_ok "  $perm : read:status:user=all"   update -pu "$perm" read:status:user all
        ;;
    t02)
        # Propagation DÉSACTIVÉE (0). Doit voir paris, PAS dev.paris.
        # C'est la moitié du couple t02/t03 : seule la comparaison des deux
        # prouve que le mode de propagation est réellement pris en compte.
        vlt_ok "  $perm : web_admin=all"                 update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:get:user=(0:$DOM_PARIS)"  update -pu "$perm" read:get:user -a 0 "$DOM_PARIS"
        ;;
    t03)
        # Propagation ACTIVÉE (1). Doit voir paris ET dev.paris.
        vlt_ok "  $perm : web_admin=all"                 update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:get:user=(1:$DOM_PARIS)"  update -pu "$perm" read:get:user -a 1 "$DOM_PARIS"
        ;;
    t04)
        # Écriture bornée à un domaine. La lecture est accordée plus largement
        # que l'écriture, pour qu'un refus d'écriture ne puisse pas être
        # confondu avec un « je ne vois pas la fiche ».
        vlt_ok "  $perm : web_admin=all"                     update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:get:user=all"                 update -pu "$perm" read:get:user all
        vlt_ok "  $perm : write:update:user=(1:$DOM_PARIS)"  update -pu "$perm" write:update:user -a 1 "$DOM_PARIS"
        ;;
    t05)
        # Prouve que web_admin est bien une PORTE distincte des droits RBAC.
        # Ce compte a des droits réels mais ne doit pas franchir /admin.
        vlt_ok "  $perm : read:get:user=all (sans web_admin)" update -pu "$perm" read:get:user all
        vlt_ok "  $perm : read:get:group=all"                 update -pu "$perm" read:get:group all
        ;;
    t06)
        # L'inverse de t05 : franchit la porte, ne doit rien voir derrière.
        vlt_ok "  $perm : web_admin=all uniquement"       update -pu "$perm" web_admin all
        ;;
    t07)
        # write:killswitch SANS write:delete:user : le mode soft doit passer,
        # le mode hard doit être refusé. C'est la séparation voulue entre
        # « couper en urgence » et « supprimer un compte ».
        vlt_ok "  $perm : web_admin=all"            update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:get:user=all"        update -pu "$perm" read:get:user all
        vlt_ok "  $perm : write:killswitch=all"     update -pu "$perm" write:killswitch all
        ;;
    t08)
        # Les deux droits : le mode hard doit passer.
        vlt_ok "  $perm : web_admin=all"            update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:get:user=all"        update -pu "$perm" read:get:user all
        vlt_ok "  $perm : write:killswitch=all"     update -pu "$perm" write:killswitch all
        vlt_ok "  $perm : write:delete:user=all"    update -pu "$perm" write:delete:user all
        ;;
    t09)
        # read:log est une action à portée globale : elle ne se restreint pas
        # par domaine, parce qu'une ligne de journal n'appartient à aucun
        # domaine. Ce compte doit voir les journaux et RIEN d'autre.
        vlt_ok "  $perm : web_admin=all"            update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:log=all"             update -pu "$perm" read:log all
        ;;
    t10)
        # write:mfa séparé de write:update:user : doit pouvoir réinitialiser un
        # second facteur sans pouvoir modifier la fiche du compte.
        vlt_ok "  $perm : web_admin=all"            update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:get:user=all"        update -pu "$perm" read:get:user all
        vlt_ok "  $perm : write:mfa=all"            update -pu "$perm" write:mfa all
        ;;
    t11)
        # Deux domaines sans propagation. Prouve l'asymétrie du moteur :
        # la LECTURE passe si AU MOINS UN domaine est autorisé,
        # l'ÉCRITURE exige TOUS les domaines de la cible.
        vlt_ok "  $perm : web_admin=all"                     update -pu "$perm" web_admin all
        vlt_ok "  $perm : read:get:user=(0:$DOM_PARIS)"      update -pu "$perm" read:get:user -a 0 "$DOM_PARIS"
        vlt_ok "  $perm : read:get:user += (0:$DOM_LYON)"    update -pu "$perm" read:get:user -a 0 "$DOM_LYON"
        vlt_ok "  $perm : write:update:user=(0:$DOM_PARIS)"  update -pu "$perm" write:update:user -a 0 "$DOM_PARIS"
        ;;
    t12)
        # PIÈGE VOLONTAIRE, et le plus utile de la série.
        #
        # web_admin fait partie des actions à portée globale : elle est TOUJOURS
        # évaluée contre « * ». Lui donner une liste de domaines ne la restreint
        # pas, elle la REFUSE — aucun domaine nommé ne correspond à « * ».
        #
        # Ce compte doit donc être incapable d'atteindre l'interface, malgré
        # une configuration qui a l'air permissive. C'est un piège classique
        # sur lequel un administrateur se coupe l'accès à lui-même.
        vlt_ok "  $perm : read:get:user=all"                 update -pu "$perm" read:get:user all
        vlt_ok "  $perm : web_admin=(0:$DOM_PARIS) — piege"  update -pu "$perm" web_admin -a 0 "$DOM_PARIS"
        ;;
    esac
}

# -----------------------------------------------------------------------------
# Nettoyage
# -----------------------------------------------------------------------------

clean_fixture() {
    title "Nettoyage du jeu d'essai précédent"
    info "seules les entités préfixées « ${PREFIX}_ » sont touchées"

    local entry id perm name
    for entry in "${ACTORS[@]}"; do
        IFS='|' read -r id perm _ <<< "$entry"
        vlt_quiet delete -u "${PREFIX}_${id}"
        vlt_quiet delete -p -u "$perm"
        vlt_quiet delete -g "${PREFIX}_g_${id}"
    done
    for entry in "${TARGET_USERS[@]}"; do
        vlt_quiet delete -u "${entry%%:*}"
    done
    for entry in "${DOMAIN_GROUPS[@]}"; do
        vlt_quiet delete -g "${entry%%:*}"
    done
    ok "nettoyage terminé"
}

# -----------------------------------------------------------------------------
# Construction
# -----------------------------------------------------------------------------

build_domains() {
    title "Groupes de domaine"
    info "un groupe porte un domaine : c'est lui qui rattache un compte à une branche de l'arbre"

    local entry name domain
    for entry in "${DOMAIN_GROUPS[@]}"; do
        name="${entry%%:*}"; domain="${entry##*:}"
        vlt_ok "groupe $name ($domain)" create -g "$name" "$domain"
    done
}

build_targets() {
    title "Comptes cibles"
    info "aucun droit : ils existent pour être vus, ou ne pas l'être"

    local entry name group pw
    for entry in "${TARGET_USERS[@]}"; do
        name="${entry%%:*}"; group="${entry##*:}"
        pw="$(password_for "$name")"
        vlt_ok "compte $name" create -u "$name" "$ROOT_DOMAIN" "$pw" "$BIRTHDATE"
        vlt_ok "  $name dans $group" add -u "$name" -g "$group"
    done
}

build_actors() {
    title "Comptes acteurs, groupes et permissions"

    local entry id perm desc user group pw
    for entry in "${ACTORS[@]}"; do
        IFS='|' read -r id perm desc <<< "$entry"
        user="${PREFIX}_${id}"
        group="${PREFIX}_g_${id}"
        pw="$(password_for "$user")"

        printf '\n%s  %s — %s%s\n' "$C_DIM" "$user" "$desc" "$C_OFF"

        # Un groupe par acteur : une permission s'attache à un groupe et vaut
        # pour tous ses membres. Mutualiser les groupes mélangerait les droits
        # que ce jeu d'essai cherche précisément à isoler.
        vlt_ok "  groupe $group" create -g "$group" "$ROOT_DOMAIN"
        vlt_ok "  compte $user"  create -u "$user" "$ROOT_DOMAIN" "$pw" "$BIRTHDATE"
        vlt_ok "  $user dans $group" add -u "$user" -g "$group"

        # La description ne doit pas contenir d'espace : le CLI découpe la
        # commande sur les espaces, et le reste partirait dans un argument
        # suivant qui n'existe pas.
        vlt_ok "  permission $perm" create -p -u "$perm" "${desc// /_}"
        vlt_ok "  $perm sur $group" add -gu "$group" -p "$perm"

        apply_actions "$id" "$perm"
    done
}

# -----------------------------------------------------------------------------
# Vérification de ce qui EST vérifiable depuis le socket
# -----------------------------------------------------------------------------
#
# Rappel : le socket est superadmin, donc aucun refus RBAC ne peut être observé
# ici. Ce qu'on vérifie, c'est que la configuration a bien été ÉCRITE — ce qui
# est loin d'être acquis : une clé d'action mal orthographiée est refusée
# silencieusement par certains chemins, et produit une permission qui ne
# s'appliquera jamais.

verify_storage() {
    title "Vérification du stockage des permissions"
    info "le socket étant superadmin, on vérifie ce qui est ÉCRIT, pas ce qui est REFUSÉ"

    local entry id perm out
    for entry in "${ACTORS[@]}"; do
        IFS='|' read -r id perm _ <<< "$entry"
        out="$(vlt get -p -u "$perm")"

        if [ -z "$out" ]; then
            ko "lecture de $perm" "réponse vide"
            continue
        fi
        if echo "$out" | grep -qiE 'introuvable|erreur'; then
            ko "lecture de $perm" "$(echo "$out" | head -1)"
            continue
        fi
        ok "lecture de $perm"

        # Vérifications ciblées, une par comportement testé.
        case "$id" in
        t02)
            if echo "$out" | grep -q "0:${DOM_PARIS}"; then
                ok "  $perm porte bien (0:${DOM_PARIS}) — sans propagation"
            else
                ko "  $perm" "mode de propagation attendu 0 sur ${DOM_PARIS} — absent de la sortie"
            fi
            ;;
        t03)
            if echo "$out" | grep -q "1:${DOM_PARIS}"; then
                ok "  $perm porte bien (1:${DOM_PARIS}) — avec propagation"
            else
                ko "  $perm" "mode de propagation attendu 1 sur ${DOM_PARIS} — absent de la sortie"
            fi
            ;;
        t07)
            if echo "$out" | grep -q 'write:killswitch'; then
                ok "  $perm porte write:killswitch"
            else
                ko "  $perm" "write:killswitch absent"
            fi
            if echo "$out" | grep -q 'write:delete:user'; then
                ko "  $perm" "write:delete:user présent alors qu'il doit être ABSENT (le mode hard doit être refusé)"
            else
                ok "  $perm n'a PAS write:delete:user — le mode hard doit échouer"
            fi
            ;;
        t09)
            if echo "$out" | grep -q 'read:log'; then
                ok "  $perm porte read:log"
            else
                ko "  $perm" "read:log absent — la permission n'a peut-être pas été reconnue"
            fi
            ;;
        t10)
            if echo "$out" | grep -q 'write:mfa'; then
                ok "  $perm porte write:mfa"
            else
                ko "  $perm" "write:mfa absent — la permission n'a peut-être pas été reconnue"
            fi
            ;;
        esac
    done
}

verify_entities() {
    title "Vérification des entités"

    local out entry name
    out="$(vlt get -u)"
    for entry in "${TARGET_USERS[@]}"; do
        name="${entry%%:*}"
        if echo "$out" | grep -q "$name"; then ok "compte $name présent"
        else ko "compte $name" "absent de get -u"; fi
    done
    for entry in "${ACTORS[@]}"; do
        name="${PREFIX}_${entry%%|*}"
        if echo "$out" | grep -q "$name"; then ok "compte $name présent"
        else ko "compte $name" "absent de get -u"; fi
    done

    out="$(vlt get -g)"
    for entry in "${DOMAIN_GROUPS[@]}"; do
        name="${entry%%:*}"
        if echo "$out" | grep -q "$name"; then ok "groupe $name présent"
        else ko "groupe $name" "absent de get -g"; fi
    done
}

# -----------------------------------------------------------------------------
# Rapport
# -----------------------------------------------------------------------------

write_report() {
    title "Rapport de vérification manuelle"

    {
    cat <<EOF
# Jeu d'essai RBAC — matrice de vérification

Généré le $(date '+%d/%m/%Y à %H:%M:%S') par \`rbac_fixture.sh\`.

**Aucun second facteur n'est activé** sur ces comptes : ils se connectent avec
leur seul mot de passe.

## Pourquoi cette vérification est manuelle

Le socket local exécute tout sous l'identité \`vaultaire\`, sans
authentification : c'est un accès superadmin. **Aucun refus RBAC ne peut donc
être observé depuis le CLI local** — tout y passe.

Les droits ci-dessous se vérifient sur les chemins où l'appelant est un vrai
utilisateur soumis au moteur de permissions :

| Chemin | Comment |
|--------|---------|
| Interface web | https://<hôte>:4443 — connexion avec le compte |
| LDAP | \`ldapsearch -x -D "cn=<compte>,dc=..." -w <mot de passe>\` |
| CLI distant | \`vaultaire_ctl\` avec la clé SSH du compte |

## Arborescence des domaines

\`\`\`
${ROOT_DOMAIN}
├── ${DOM_PARIS}
│   └── ${DOM_DEV}          <- deux niveaux : c'est ce qui rend la propagation observable
└── ${DOM_LYON}
\`\`\`

## Comptes cibles

Aucun droit. Ils existent pour être vus — ou pour ne pas l'être.

| Compte | Domaine | Mot de passe |
|--------|---------|--------------|
EOF

    local entry name group pw
    for entry in "${TARGET_USERS[@]}"; do
        name="${entry%%:*}"; group="${entry##*:}"
        local domain=""
        local d
        for d in "${DOMAIN_GROUPS[@]}"; do
            [ "${d%%:*}" = "$group" ] && domain="${d##*:}"
        done
        printf '| `%s` | %s | `%s` |\n' "$name" "$domain" "$(password_for "$name")"
    done

    cat <<EOF

## Comptes acteurs — ce qui doit marcher, ce qui doit être refusé

EOF

    local id perm desc user
    for entry in "${ACTORS[@]}"; do
        IFS='|' read -r id perm desc <<< "$entry"
        user="${PREFIX}_${id}"
        pw="$(password_for "$user")"

        printf '### `%s` — %s\n\n' "$user" "$desc"
        printf '**Mot de passe :** `%s` · **Permission :** `%s`\n\n' "$pw" "$perm"

        case "$id" in
        t01)
            cat <<'EOF'
| Attendu | Vérification |
|---------|--------------|
| ✅ Accède à `/admin` | Connexion web |
| ✅ Voit les 4 comptes cibles | `/admin/users` |
| ✅ Voit tous les groupes | `/admin/groups` |
| ❌ Ne peut pas créer d'utilisateur | Le formulaire doit refuser (pas de `write:create:user`) |

**Rôle : témoin positif.** Si ce compte échoue quelque part, le problème n'est
pas dans le filtrage par domaine mais en amont.
EOF
            ;;
        t02)
            cat <<EOF
| Attendu | Vérification |
|---------|--------------|
| ✅ Accède à \`/admin\` | Connexion web |
| ✅ Voit \`${PREFIX}_cible_paris\` | \`/admin/users\` |
| ❌ **Ne voit PAS** \`${PREFIX}_cible_dev\` | \`/admin/users\` — c'est le point du test |
| ❌ Ne voit pas \`${PREFIX}_cible_lyon\` | \`/admin/users\` |

**À comparer avec \`${PREFIX}_t03\`.** Les deux comptes ne diffèrent que par le
mode de propagation. Si les deux voient la même chose, le mode n'est pas pris
en compte.
EOF
            ;;
        t03)
            cat <<EOF
| Attendu | Vérification |
|---------|--------------|
| ✅ Accède à \`/admin\` | Connexion web |
| ✅ Voit \`${PREFIX}_cible_paris\` | \`/admin/users\` |
| ✅ **Voit aussi** \`${PREFIX}_cible_dev\` | \`/admin/users\` — la propagation descend le sous-arbre |
| ❌ Ne voit pas \`${PREFIX}_cible_lyon\` | \`/admin/users\` |
EOF
            ;;
        t04)
            cat <<EOF
| Attendu | Vérification |
|---------|--------------|
| ✅ Voit tous les comptes | \`read:get:user=all\` |
| ✅ Modifie \`${PREFIX}_cible_paris\` | \`/admin/users?user=${PREFIX}_cible_paris\` → Enregistrer |
| ✅ Modifie \`${PREFIX}_cible_dev\` | propagation activée sur paris |
| ❌ **Ne modifie PAS** \`${PREFIX}_cible_lyon\` | doit répondre « Permission refusée » |

La lecture est plus large que l'écriture à dessein : un refus d'écriture ne doit
pas pouvoir être confondu avec « je ne vois pas la fiche ».
EOF
            ;;
        t05)
            cat <<'EOF'
| Attendu | Vérification |
|---------|--------------|
| ❌ **Refusé sur `/admin`** | Redirigé vers `/profil` malgré des droits RBAC réels |
| ✅ Accède à son profil | `/profil` |
| ✅ Ses droits existent bien | `vaultaire_ctl get -u` doit fonctionner |

**Prouve que `web_admin` est une porte distincte des droits RBAC.** Avec
`vaultaire_ctl`, ce compte peut lire les utilisateurs — `web_admin` n'entre pas
en jeu en ligne de commande.
EOF
            ;;
        t06)
            cat <<'EOF'
| Attendu | Vérification |
|---------|--------------|
| ✅ Accède à `/admin` | La porte s'ouvre |
| ❌ **Aucune donnée derrière** | `/admin/users` doit être vide ou refusé |
| ❌ `/admin/groups` idem | |

L'inverse exact de `t05` : franchit la porte, ne voit rien derrière.
EOF
            ;;
        t07)
            cat <<EOF
| Attendu | Vérification |
|---------|--------------|
| ✅ Voit la section « Désactivation d'urgence » | \`/admin/users?user=${PREFIX}_cible_lyon\` |
| ✅ **Mode soft accepté** | Verrouiller le compte, puis le déverrouiller |
| ❌ **Mode hard REFUSÉ** | Doit répondre « Permission refusée pour le mode hard » |

**C'est la séparation voulue** entre couper en urgence et supprimer un compte :
le mode destructeur exige \`write:delete:user\` en plus de \`write:killswitch\`.
EOF
            ;;
        t08)
            cat <<EOF
| Attendu | Vérification |
|---------|--------------|
| ✅ Mode soft accepté | |
| ✅ **Mode hard accepté** | Sur \`${PREFIX}_cible_lyon\` — le compte disparaît de l'annuaire |

⚠️ **À faire en dernier** : la cible est réellement supprimée. Relancez le script
pour reconstruire le jeu d'essai.
EOF
            ;;
        t09)
            cat <<'EOF'
| Attendu | Vérification |
|---------|--------------|
| ✅ Accède à `/admin/logs` | La page des journaux s'affiche |
| ❌ Ne voit aucun utilisateur | `/admin/users` refusé |
| ❌ Ne voit aucun groupe | `/admin/groups` refusé |

**`read:log` sépare l'audit de l'administration.** Avant son introduction, la
page des journaux était adossée à `read:get:user` : quiconque consultait
l'annuaire d'un seul domaine lisait l'activité de tout le parc.
EOF
            ;;
        t10)
            cat <<EOF
| Attendu | Vérification |
|---------|--------------|
| ✅ Voit la section « Second facteur » | \`/admin/users?user=${PREFIX}_cible_paris\` |
| ✅ Réinitialise le second facteur | Bouton « Réinitialiser » |
| ❌ **Ne modifie pas la fiche** | Renommer doit être refusé (pas de \`write:update:user\`) |

Pour tester réellement la réinitialisation, activez d'abord un second facteur
sur \`${PREFIX}_cible_paris\` depuis son propre profil.
EOF
            ;;
        t11)
            cat <<EOF
| Attendu | Vérification |
|---------|--------------|
| ✅ Voit \`${PREFIX}_cible_paris\` | lecture : **au moins un** domaine suffit |
| ✅ Voit \`${PREFIX}_cible_lyon\` | |
| ❌ Ne voit pas \`${PREFIX}_cible_dev\` | pas de propagation |
| ✅ Modifie \`${PREFIX}_cible_paris\` | écriture accordée sur paris |
| ❌ **Ne modifie pas** \`${PREFIX}_cible_lyon\` | écriture : **tous** les domaines de la cible sont exigés |

**Prouve l'asymétrie du moteur** : la lecture est un OU, l'écriture un ET. C'est
ce qui empêche un délégué d'un seul domaine de modifier un compte qui détient
des droits ailleurs.
EOF
            ;;
        t12)
            cat <<EOF
| Attendu | Vérification |
|---------|--------------|
| ❌ **Refusé sur \`/admin\`** | malgré \`read:get:user=all\` |

**Piège volontaire, et le plus instructif de la série.**

\`web_admin\` fait partie des actions à portée globale : elle est **toujours**
évaluée contre \`*\`. Lui donner une liste de domaines ne la restreint pas, elle
la **refuse** — aucun domaine nommé ne correspond à \`*\`.

C'est exactement le geste par lequel un administrateur se coupe l'accès à
lui-même. Si ce compte parvient à entrer, la protection ne fonctionne pas.
EOF
            ;;
        esac
        printf '\n'
    done

    cat <<EOF
## Ordre conseillé

1. \`t01\` — témoin positif. S'il échoue, inutile d'aller plus loin.
2. \`t02\` puis \`t03\` — à la suite, la comparaison est le test.
3. \`t05\` et \`t06\` — les deux moitiés de la séparation porte / droits.
4. \`t11\` — l'asymétrie lecture/écriture.
5. \`t12\` — le piège des actions globales.
6. \`t04\`, \`t07\`, \`t09\`, \`t10\` — dans n'importe quel ordre.
7. \`t08\` **en dernier** : il supprime réellement une cible.

## Remise à zéro

\`\`\`bash
${VAULTAIRE_HOME}/scripts/rbac_fixture.sh --clean    # supprime le jeu d'essai
${VAULTAIRE_HOME}/scripts/rbac_fixture.sh            # le reconstruit
\`\`\`

Seules les entités préfixées \`${PREFIX}_\` sont touchées.
EOF
    } > "$REPORT"

    ok "rapport écrit : $REPORT"
}

# -----------------------------------------------------------------------------
# Récapitulatif à l'écran
# -----------------------------------------------------------------------------

print_credentials() {
    title "Comptes créés"
    printf '  %-22s %-30s %s\n' "COMPTE" "MOT DE PASSE" "RÔLE"
    printf '  %-22s %-30s %s\n' "----------------------" "------------------------------" "----"

    local entry name id perm desc
    for entry in "${TARGET_USERS[@]}"; do
        name="${entry%%:*}"
        printf '  %-22s %-30s %s\n' "$name" "$(password_for "$name")" "cible, aucun droit"
    done
    for entry in "${ACTORS[@]}"; do
        IFS='|' read -r id perm desc <<< "$entry"
        name="${PREFIX}_${id}"
        printf '  %-22s %-30s %s\n' "$name" "$(password_for "$name")" "$desc"
    done
}

summary() {
    title "Bilan"
    printf '  %s%d réussite(s)%s, %s%d échec(s)%s\n' "$C_OK" "$PASS" "$C_OFF" \
        "$( [ "$FAIL" -gt 0 ] && echo "$C_KO" || echo "$C_OK" )" "$FAIL" "$C_OFF"

    if [ "$FAIL" -gt 0 ]; then
        printf '\n  Échecs :\n'
        local f
        for f in "${FAILURES[@]}"; do printf '    - %s\n' "$f"; done
    fi

    printf '\n  %sRappel : ces vérifications portent sur la CONFIGURATION, pas sur son application.%s\n' "$C_WARN" "$C_OFF"
    printf '  Le socket local est superadmin : aucun refus RBAC ne peut y être observé.\n'
    printf "  L'application effective se vérifie avec la matrice : %s\n" "$REPORT"

    [ "$FAIL" -eq 0 ] || return 1
    return 0
}

# -----------------------------------------------------------------------------
# Point d'entrée
# -----------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage : $(basename "$0") [OPTION]

  (sans option)   nettoie puis reconstruit le jeu d'essai, et écrit le rapport
  --clean         supprime le jeu d'essai et s'arrête
  --report-only   régénère le rapport sans rien créer ni supprimer
  --keep          construit SANS nettoyer d'abord (échoue si le jeu existe déjà)
  -h, --help      cette aide

Variables d'environnement :
  VAULTAIRE_HOME    répertoire d'installation      (défaut : /opt/vaultaire)
  VAULTAIRE_CLI     chemin du binaire CLI          (défaut : \$VAULTAIRE_HOME/bin/vaultaire_cli)
  VAULTAIRE_SOCKET  chemin du socket               (défaut : \$VAULTAIRE_HOME/vaultaire.sock)
  VAULTAIRE_REPORT  fichier de sortie du rapport   (défaut : \$VAULTAIRE_HOME/rbac_report.md)
EOF
}

main() {
    local mode="rebuild"
    case "${1:-}" in
        --clean)       mode="clean" ;;
        --report-only) mode="report" ;;
        --keep)        mode="keep" ;;
        -h|--help)     usage; exit 0 ;;
        "")            ;;
        *)             usage; exit 1 ;;
    esac

    printf '%s\n' "════════════════════════════════════════════════════════════════"
    printf '  Vaultaire — jeu d'\''essai RBAC (pre-prod)\n'
    printf '%s\n' "════════════════════════════════════════════════════════════════"

    preflight

    case "$mode" in
        clean)
            clean_fixture
            title "Terminé"
            info "jeu d'essai supprimé"
            return 0
            ;;
        report)
            write_report
            print_credentials
            return 0
            ;;
        rebuild)
            clean_fixture
            ;;
    esac

    build_domains
    build_targets
    build_actors
    verify_entities
    verify_storage
    write_report
    print_credentials
    summary
}

main "$@"
