#!/usr/bin/env bash
# ====================================================================
# dev-comp.sh — compiler le dépôt local, puis démarrer la pile de test
# ====================================================================
#
# Usage (depuis n'importe où dans le dépôt) :
#
#   ./deployments/dev-comp/dev-comp.sh                 compile, puis (re)démarre la pile
#   ./deployments/dev-comp/dev-comp.sh --version 2.2.3 impose la version injectée
#   ./deployments/dev-comp/dev-comp.sh --local         compile sur l'hôte (auto-compil.sh), sans conteneur
#   ./deployments/dev-comp/dev-comp.sh --no-build      redémarre sans recompiler
#   ./deployments/dev-comp/dev-comp.sh --proxy         démarre aussi un proxy (relais Ducky)
#   ./deployments/dev-comp/dev-comp.sh --nexus         démarre aussi un Nexus (dépôt de paquets)
#   ./deployments/dev-comp/dev-comp.sh --down          arrête la pile (garde la base)
#   ./deployments/dev-comp/dev-comp.sh --reset         arrête et EFFACE la base, l'identité du proxy et les données Nexus
#   ./deployments/dev-comp/dev-comp.sh --logs          suit les journaux du core
#   ./deployments/dev-comp/dev-comp.sh --status        état des conteneurs et version compilée
#
# Agrandir la pile SANS la relancer (le core doit déjà tourner) :
#
#   ./deployments/dev-comp/dev-comp.sh --add-proxy [nom]  un proxy de plus (clé d'enrôlement créée toute seule)
#   ./deployments/dev-comp/dev-comp.sh --add-core  [nom]  un core de plus, sur la MÊME base
#   ./deployments/dev-comp/dev-comp.sh --noeuds           liste les nœuds ajoutés après coup
#   ./deployments/dev-comp/dev-comp.sh --rm-noeud <nom>   retire un nœud ajouté (et son identité)
#
# « Monter une version » : sans --version, la version injectée est la
# PROCHAINE release de la série en cours — VERSION (2.2) et le plus grand tag
# v2.2.N connu localement donnent 2.2.(N+1), ou 2.2.0 sans tag. Le commit et
# « -dirty » s'y ajoutent : « 2.2.1+g1a2b3c4-dirty (2026-09-22) ». Un binaire de
# dev-comp se reconnaît donc au premier coup d'œil dans `vlt cluster list` et
# `vlt version`, sans se faire passer pour une release.
#
# Les IMAGES du core, du proxy et du Nexus sont (re)construites à chaque
# lancement, que leurs conteneurs démarrent ou non. Une image qu'on ne construit
# qu'au moment d'en avoir besoin casse au pire moment — et ces trois-là sont
# justement celles qu'on démarre en urgence pour reproduire quelque chose.

set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RACINE="$(cd "$ICI/../.." && pwd -P)"
BUILD="$ICI/build"
cd "$ICI"

info() { echo -e "\033[1;34m[dev-comp]\033[0m $*"; }
erreur() { echo -e "\033[1;31m[dev-comp]\033[0m $*" >&2; exit 1; }

command -v docker >/dev/null || erreur "docker introuvable"
docker compose version >/dev/null 2>&1 || erreur "« docker compose » (v2) introuvable"

COMPILER=1
LOCAL=0
PROXY=0
NEXUS=0
VERSION_IMPOSEE=""
ACTION="up"
NOM_NOEUD=""

while [ $# -gt 0 ]; do
    case "$1" in
        # Même garde que les options à nom facultatif plus bas : un « shift »
        # inconditionnel sur « --version » seul vide la pile d'arguments, le
        # shift de fin de boucle échoue, et « set -e » arrête le script sans un
        # mot au lieu de dire ce qui manque.
        --version)  case "${2:-}" in ""|-*) erreur "--version attend un numéro (X.Y.Z)" ;;
                                     *) VERSION_IMPOSEE="$2"; shift ;; esac ;;
        --local)    LOCAL=1 ;;
        --no-build) COMPILER=0 ;;
        --proxy)    PROXY=1 ;;
        --nexus)    NEXUS=1 ;;
        --down)     ACTION="down" ;;
        --reset)    ACTION="reset" ;;
        --logs)     ACTION="logs" ;;
        --status)   ACTION="status" ;;
        # Le nom est FACULTATIF et positionnel. « ${2:-} » seul consommerait
        # l'option suivante comme nom : « --add-proxy --nexus » créerait un
        # proxy nommé « --nexus ». D'où le filtre sur le tiret initial.
        --add-proxy) ACTION="add-proxy"
                     case "${2:-}" in ""|-*) : ;; *) NOM_NOEUD="$2"; shift ;; esac ;;
        --add-core)  ACTION="add-core"
                     case "${2:-}" in ""|-*) : ;; *) NOM_NOEUD="$2"; shift ;; esac ;;
        --noeuds)   ACTION="noeuds" ;;
        # Même garde que ci-dessus, et pour une raison de plus : un « shift »
        # inconditionnel sur « --rm-noeud » seul vide la pile d'arguments, le
        # shift de fin de boucle échoue, et « set -e » arrête le script SANS
        # message — le contraire de ce que doit faire une option mal employée.
        --rm-noeud) ACTION="rm-noeud"
                    case "${2:-}" in ""|-*) : ;; *) NOM_NOEUD="$2"; shift ;; esac ;;
        -h|--help)  sed -n '2,36p' "$0"; exit 0 ;;
        "") erreur "argument vide (voir --help)" ;;
        *) erreur "option inconnue : $1 (voir --help)" ;;
    esac
    shift
done

# Profils des CONTENEURS à démarrer. Les IMAGES, elles, sont toutes
# construites : voir TOUS plus bas.
PROFILS=()
[ "$PROXY" = 1 ] && PROFILS+=(--profile proxy)
[ "$NEXUS" = 1 ] && PROFILS+=(--profile nexus)

# TOUS : tous les profils, pour les opérations qui doivent voir la pile entière
# (arrêt, état, construction des images) quels que soient les conteneurs
# demandés aujourd'hui. Sans cela, « --down » laisserait tourner un proxy
# démarré la veille.
TOUS=(--profile proxy --profile nexus)

# =====================================================================
# Nœuds ajoutés après coup — --add-proxy, --add-core
# =====================================================================
#
# Pourquoi « docker run » et non des services de plus dans le compose : le
# nombre de nœuds n'est pas connu d'avance. Déclarer à l'avance un service par
# nœud possible figerait ce nombre dans un fichier versionné, et éprouver un
# cluster à trois proxies demanderait d'éditer — donc de commiter — le compose
# pour un besoin qui dure dix minutes.
#
# Ces conteneurs portent une ÉTIQUETTE Docker. C'est elle, et rien d'autre, qui
# sert de registre : --down, --reset, --status et --noeuds les retrouvent sans
# qu'aucune liste soit tenue à jour quelque part — donc sans qu'elle puisse
# mentir après un « docker rm » fait à la main.
#
# La réserve : --noeuds ne liste que des CONTENEURS. Un « docker rm » à la main
# laisse derrière lui un volume d'identité que seul --reset reprendra.
#
# L'étiquette ne porte pas le nom du dépôt, et c'est sans conséquence ici : les
# noms de conteneurs du compose sont figés, deux piles dev-comp ne peuvent donc
# pas tourner en même temps sur une machine.
ETIQUETTE="vaultaire.devcomp=1"

noeuds_ajoutes()  { docker ps -aq --filter "label=$ETIQUETTE"; }
volumes_ajoutes() { docker volume ls -q --filter "label=$ETIQUETTE"; }

exiger_core() {
    [ -n "$(docker ps -q -f 'name=^vlt-dev-ad$')" ] || erreur \
"le core ne tourne pas : « --add-… » agrandit une pile DÉJÀ démarrée.
  Lancez d'abord ./deployments/dev-comp/dev-comp.sh"
}

# Le réseau est LU sur le core en marche, pas reconstruit à partir du nom du
# projet. Le compose fixe « name: dev-comp », donc le préfixe est connu — mais
# COMPOSE_PROJECT_NAME l'emporte sur lui, et le déduire reviendrait à recopier
# ici une règle qui vit ailleurs. Le demander au core, c'est brancher le nouveau
# nœud là où le core écoute vraiment, quelle que soit cette règle.
reseau_de_la_pile() {
    local r
    r="$(docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}' vlt-dev-ad | awk '{print $1}')"
    [ -n "$r" ] || erreur "réseau de la pile introuvable sur vlt-dev-ad"
    echo "$r"
}

# Les ports doivent venir du MÊME endroit que pour le compose : l'environnement
# d'abord, puis deployments/dev-comp/.env. Docker compose charge ce fichier tout
# seul ; un script, non. Sans cette lecture, une pile dont .env décale le portail
# sur 8443 verrait « --add-core » calculer ses décalages à partir de 4443 et
# ANNONCER des ports que personne n'écoute.
#
# Lu à la ligne plutôt que sourcé : .env n'est pas du shell, et le sourcer
# exécuterait ce qu'il contient.
lire_env() {
    local cle="$1" defaut="$2" valeur=""
    if [ -n "${!cle:-}" ]; then echo "${!cle}"; return; fi
    if [ -f "$ICI/.env" ]; then
        valeur="$(sed -nE "s/^[[:space:]]*$cle=([^#]*).*/\1/p" "$ICI/.env" | tail -1 | tr -d "[:space:]\"'")"
    fi
    echo "${valeur:-$defaut}"
}

# Un port lu de .env entre dans des « $(( )) ». Non contrôlé, « 8443x » y produit
# une erreur arithmétique — et, dans « for p in $(ports_de …) », une liste VIDE :
# la boucle ne teste plus rien et conclut que tous les ports sont libres. Un
# contrôle muet devient alors un contrôle qui ment.
#
# Le contrôle a lieu ICI, une fois, au niveau du script — et non dans lire_port.
# C'est le point important : lire_port est toujours appelée depuis une
# substitution de commande, où « erreur » ne quitte QUE le sous-shell. Le script
# continuait alors avec une valeur vide, et démarrait un core sur le port 10.
controler_ports_env() {
    local c cle defaut v
    for c in DEVCOMP_PORT_DUCKY:6666 DEVCOMP_PORT_WEB:4443 DEVCOMP_PORT_API:6643 \
             DEVCOMP_PORT_LDAP:389 DEVCOMP_PORT_LDAPS:636 DEVCOMP_PORT_PROXY:6667 \
             DEVCOMP_PORT_DB:3307 DEVCOMP_PORT_NEXUS:8843; do
        cle="${c%%:*}"; defaut="${c##*:}"
        v="$(lire_env "$cle" "$defaut")"
        [[ "$v" =~ ^[0-9]+$ ]] || erreur \
"$cle : « $v » n'est pas un numéro de port.
  Corrigez l'environnement, ou $ICI/.env"
    done
}

lire_port() { lire_env "$1" "$2"; }

# Un port pris se dit AVANT le docker run. « port is already allocated » ne
# nomme ni le port fautif ni qui le tient, et arrive après que le volume a été
# créé et la clé d'enrôlement consommée — c'est-à-dire trop tard.
#
# Deux contrôles, parce qu'aucun des deux ne suffit :
#
#   - Docker connaît les ports qu'il a RÉSERVÉS, y compris publiés sur une autre
#     interface que 127.0.0.1, et y compris quand le conteneur ne répond plus ;
#   - une connexion sur l'hôte voit les services qui ne sont pas dans Docker.
#
# Le délai n'est pas un détail : sur un port filtré en DROP, /dev/tcp attend
# indéfiniment et le script reste pendu sans rien dire.
#
# Il reste un angle mort assumé : un service lié à une SEULE adresse autre que
# 127.0.0.1 et hors Docker n'est pas vu, et la course entre ce contrôle et le
# « docker run » n'est pas fermée. Ce contrôle rend l'échec rare et lisible, il
# ne le rend pas impossible.
port_libre() {
    local p="$1" code=0
    # « []0-9.:[] » et non « [0-9.:[] » : en ERE, seul un « ] » placé EN TÊTE de
    # classe est littéral. Sans lui la classe s'arrête au crochet, et une
    # publication IPv6 seule — « [::]:6668->6666/tcp » — n'est pas vue.
    if docker ps --format '{{.Ports}}' | grep -qE "(^|[,[:space:]])[]0-9.:[]*:$p->"; then
        return 1
    fi
    timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p" 2>/dev/null || code=$?
    case "$code" in
        0)   return 1 ;;  # la connexion aboutit : le port est pris
        124) return 1 ;;  # délai dépassé (port filtré en DROP) : on ne sait pas,
                          # donc on tient pour pris. Sauter un indice ne coûte
                          # rien ; publier sur un port occupé fait échouer le
                          # docker run APRÈS la clé et le volume.
        *)   return 0 ;;  # connexion refusée : libre
    esac
}

# Un nom de nœud sert à trois choses : nommer un conteneur, nommer un volume, et
# nommer le nœud dans cluster_nodes. Les trois ont des exigences différentes ;
# on prend la plus stricte. Non validé, il part tel quel dans « docker ps -f
# name=… », où le filtre est une EXPRESSION RÉGULIÈRE : un point ou une étoile
# y ferait correspondre un tout autre conteneur que celui qu'on créera ensuite.
# Les quatre premiers sont les suffixes des « container_name » du compose ; les
# suivants sont des noms DNS du réseau. « vaultaire-db » est le plus dangereux :
# c'est par lui que TOUT core joint MariaDB (serveur_conf.yaml, ip_database). Un
# nœud qui prendrait ce nom d'hôte se ferait résoudre en alternance avec la base,
# et la connexion du core deviendrait intermittente — la panne la moins lisible
# de toute la pile.
NOMS_RESERVES="ad db proxy nexus vaultaire-ad vaultaire-db vaultaire-nexus vlt-proxy proxy1"
valider_nom() {
    local nom="$1" r
    [[ "$nom" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || erreur \
"nom de nœud invalide : « $nom ».
  Minuscules, chiffres et tirets, 31 caractères au plus, ne commence pas par un tiret."
    for r in $NOMS_RESERVES; do
        if [ "$nom" = "$r" ]; then
            erreur "« $nom » est réservé à la pile de base : conteneur, nom de nœud ou nom DNS du réseau.
  Un nœud qui reprendrait ce nom écraserait la ligne d'un autre dans cluster_nodes,
  ou se ferait résoudre à sa place sur le réseau."
        fi
    done
}

# Table des ports publiés sur l'hôte, régulière pour être retrouvée de tête :
#
#   proxy N : 6667 + (N-1)      le proxy du compose est le n° 1
#   core  N : Ducky, web et API décalés de 10 par indice ; LDAP et LDAPS de
#             1000, ce qui donne 389 → 1389, lisible — un 399 se confondrait
#             avec un port voisin.
#
# Les ports INTERNES ne bougent pas : chaque conteneur a son adresse sur le
# réseau, deux cores peuvent donc écouter 6666 tous les deux.
#
# Au-delà de NEUF proxies, la suite des proxies rattrape le Ducky des cores
# (proxy n° 10 → 6676 = core n° 2). Le contrôle de port l'attrape, mais la table
# cesse d'être « régulière » : c'est un cas de laboratoire, pas une garantie.
ports_de() {
    local role="$1" n="$2"
    case "$role" in
        proxy) echo $(( $(lire_port DEVCOMP_PORT_PROXY 6667) + n - 1 )) ;;
        core)  echo $(( $(lire_port DEVCOMP_PORT_DUCKY 6666) + 10 * (n - 1) )) \
                    $(( $(lire_port DEVCOMP_PORT_WEB   4443) + 10 * (n - 1) )) \
                    $(( $(lire_port DEVCOMP_PORT_API   6643) + 10 * (n - 1) )) \
                    $(( $(lire_port DEVCOMP_PORT_LDAP   389) + 1000 * (n - 1) )) \
                    $(( $(lire_port DEVCOMP_PORT_LDAPS  636) + 1000 * (n - 1) )) ;;
    esac
}

ports_libres_pour() {
    local p
    for p in $(ports_de "$1" "$2"); do
        port_libre "$p" || return 1
    done
    return 0
}

# Premier indice dont NI le nom par défaut NI aucun des ports ne sont pris.
indice_libre() {
    local prefixe="$1" n=2
    while [ "$n" -le 20 ]; do
        if [ -z "$(docker ps -aq -f "name=^vlt-dev-${prefixe}${n}\$")" ] \
           && ports_libres_pour "$prefixe" "$n"; then
            echo "$n"; return 0
        fi
        n=$((n + 1))
    done
    erreur "aucun indice libre entre 2 et 20 pour un $prefixe"
}

# Un volume peut exister SANS porter d'identité : « docker volume create » a lieu
# avant le « docker run », donc tout démarrage qui échoue en laisse un vide
# derrière lui. Tenir l'existence du volume pour une identité reviendrait alors à
# ne PAS passer de clé à un proxy qui doit s'enrôler : il s'arrête sur « aucune
# clé d'enrôlement dans la configuration », « --restart unless-stopped » le fait
# boucler, et le script annonce pendant ce temps un démarrage réussi.
#
# On teste donc le FICHIER que l'enrôlement écrit, pas le volume qui le contient.
identite_presente() {
    docker volume inspect "$1" >/dev/null 2>&1 || return 1
    docker run --rm --entrypoint /bin/sh -v "$1:/identite:ro" \
        vlt-proxy-devcomp:latest -c '[ -s /identite/client_software.yaml ]' >/dev/null 2>&1
}

exiger_nom_libre() {
    valider_nom "$1"
    [ -z "$(docker ps -aq -f "name=^vlt-dev-$1\$")" ] \
        || erreur "un conteneur vlt-dev-$1 existe déjà (« --rm-noeud $1 » pour le retirer)"
}

ajouter_proxy() {
    exiger_core
    [ -x "$BUILD/vaultaire_proxy/vaultaire_proxy" ] \
        || erreur "binaire du proxy absent ($BUILD/vaultaire_proxy) : relancez ./deployments/dev-comp/dev-comp.sh"
    docker image inspect vlt-proxy-devcomp:latest >/dev/null 2>&1 \
        || erreur "image vlt-proxy-devcomp:latest absente : relancez ./deployments/dev-comp/dev-comp.sh"

    local n nom port reseau volume cle sortie
    n="$(indice_libre proxy)"
    nom="${NOM_NOEUD:-proxy$n}"
    port="$(ports_de proxy "$n")"
    exiger_nom_libre "$nom"
    reseau="$(reseau_de_la_pile)"
    volume="devcomp_keys_$nom"

    # Une clé n'est émise QUE s'il n'y a pas déjà une identité à reprendre.
    # Après un --down, le volume a survécu : le proxy se rattache sans rien
    # réenrôler, et une clé émise ici ne serait jamais consommée — elle resterait
    # valide vingt-quatre heures et s'accumulerait dans « enroll list ».
    local -a ENV_CLE=()
    if identite_presente "$volume"; then
        info "identité déjà présente ($volume) : aucun enrôlement, aucune clé émise"
    else
        # La clé est créée ICI, à la demande, et pour ce proxy SEUL (--uses 1).
        # C'est tout l'intérêt de la commande : la créer à la main puis la
        # recopier dans .env était l'essentiel de la corvée. Et une clé
        # réutilisée par deux proxies ne dirait plus lequel s'est enrôlé avec
        # quoi — « enroll show » liste les services entrés avec une clé, et
        # cette trace ne vaut que si la clé n'a servi qu'une fois.
        info "création d'une clé d'enrôlement pour « $nom »"

        # « || true » des deux côtés, et ce n'est pas de la négligence :
        #
        #   - vaultaire_cli ne rend JAMAIS de code non nul — ses erreurs sont des
        #     phrases imprimées sur la sortie standard. Un « || erreur » ici ne se
        #     déclencherait que si docker exec lui-même échouait, jamais sur un
        #     refus du core ;
        #   - sous « pipefail », un grep sans correspondance fait rendre 1 à
        #     l'affectation, et « set -e » arrêterait le script AVANT le message
        #     qui explique quoi faire.
        #
        # C'est donc l'absence de clé, et elle seule, qui sert de test.
        sortie="$(docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli \
                      enroll create --type vaultaire_proxy --uses 1 --label "$nom" 2>&1 || true)"

        # Extraction par la FORME (VLT-ENR- + 32 hexadécimaux), pas par la
        # position : le message qui précède la clé s'allonge selon les options
        # (« sans limite », « naîtront dans : … »), et découper sur un numéro de
        # ligne casserait le jour où il change.
        cle="$(printf '%s\n' "$sortie" | grep -oE 'VLT-ENR-[0-9a-f]{32}' | head -1 || true)"

        if [ -z "$cle" ]; then
            # La sortie est recopiée, MASQUÉE : cette branche est aussi prise
            # quand le core a répondu correctement mais que le motif a changé, et
            # elle recopierait alors un secret valide sur la sortie d'erreur.
            erreur "aucune clé d'enrôlement dans la réponse du core.
  Le CLI n'a pas de code de retour : c'est sa sortie qui dit ce qui s'est passé.
$(printf '%s\n' "$sortie" | sed -E 's/VLT-ENR-[0-9a-f]{32}/VLT-ENR-…(masquée)/' | sed 's/^/    /')"
        fi

        docker volume create --label "$ETIQUETTE" --label "vaultaire.devcomp.role=proxy" \
            "$volume" >/dev/null
        # La clé reste lisible dans « docker inspect » tant que le conteneur
        # existe. C'est admis ici — même registre que le mot de passe de la base
        # dans le compose : une pile de développement, des valeurs visibles que
        # personne ne peut prendre pour un secret. À ne pas recopier en préprod.
        ENV_CLE=(-e "VAULTAIRE_ENROLL_KEY=$cle")
    fi

    docker run -d \
        --name "vlt-dev-$nom" \
        --hostname "$nom" \
        --network "$reseau" \
        --restart unless-stopped \
        --label "$ETIQUETTE" \
        --label "vaultaire.devcomp.role=proxy" \
        -e TZ=Europe/Paris \
        -e VAULTAIRE_IP_CORE=vaultaire-ad:6666 \
        ${ENV_CLE[@]+"${ENV_CLE[@]}"} \
        -e VAULTAIRE_ENROLL_LABEL="$nom" \
        -e VAULTAIRE_LISTEN_PORT=6666 \
        -v "$BUILD/vaultaire_proxy:/opt/vaultaire/bin:ro" \
        -v "$volume:/var/lib/vaultaire_proxy/keys" \
        -p "$port:6666" \
        vlt-proxy-devcomp:latest >/dev/null

    info "proxy « $nom » démarré — port $port, identité dans le volume $volume"
    # Le proxy annonce au core le port qu'il écoute DANS le conteneur (6666) ;
    # les agents, eux, joignent le port publié sur l'hôte. Sans cette
    # déclaration, ils reçoivent une adresse sur laquelle personne ne répond.
    info "  joignable par des agents seulement après :"
    info "    docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli cluster expose $nom <adresse-hôte> $port"
    info "  journaux : docker logs -f vlt-dev-$nom"
}

ajouter_core() {
    exiger_core
    [ -x "$BUILD/vaultaire_server/vaultaire_serveur" ] \
        || erreur "binaires du serveur absents ($BUILD/vaultaire_server) : relancez ./deployments/dev-comp/dev-comp.sh"
    docker image inspect vaultaire-devcomp:latest >/dev/null 2>&1 \
        || erreur "image vaultaire-devcomp:latest absente : relancez ./deployments/dev-comp/dev-comp.sh"

    local n nom reseau p_ducky p_web p_api p_ldap p_ldaps
    n="$(indice_libre core)"
    nom="${NOM_NOEUD:-core$n}"
    exiger_nom_libre "$nom"
    reseau="$(reseau_de_la_pile)"
    read -r p_ducky p_web p_api p_ldap p_ldaps <<<"$(ports_de core "$n")"

    # Un core ne s'enrôle pas et ne « rejoint » rien : il n'existe aucune
    # procédure de jonction, et « enroll create » refuse d'ailleurs le type.
    # Un second core, c'est un second processus sur la MÊME base — il s'inscrit
    # tout seul dans cluster_nodes sous « @core:<hostname> », et relit les clés
    # du core déjà en base, donc il porte la même empreinte que le premier.
    # C'est cette empreinte identique qui fait que les agents l'acceptent sans
    # rien réapprendre.
    #
    # --hostname est donc porteur de sens : c'est le nom du nœud dans
    # « vlt cluster list » ET la moitié de son propriétaire en base. Laissé au
    # hasard, chaque recréation du conteneur naîtrait sous un nouvel identifiant
    # et laisserait la ligne précédente derrière elle.
    docker run -d \
        --name "vlt-dev-$nom" \
        --hostname "$nom" \
        --network "$reseau" \
        --restart unless-stopped \
        --label "$ETIQUETTE" \
        --label "vaultaire.devcomp.role=core" \
        -e TZ=Europe/Paris \
        -e VAULTAIRE_ENV=dev-comp \
        -e VAULTAIRE_DB_PASSWORD=root \
        -e VAULTAIRE_ADMIN_PASSWORD="$(lire_env VAULTAIRE_ADMIN_PASSWORD 'correcte agrafe batterie')" \
        -v "$BUILD/vaultaire_server:/opt/vaultaire/bin:ro" \
        -v "$BUILD/vaultaire_client:/opt/vaultaire/vaultaire_client:ro" \
        -v "$RACINE/web_packet:/opt/vaultaire/web_packet:ro" \
        -v "$ICI/../pre-prod/scripts:/opt/vaultaire/scripts:ro" \
        -p "$p_ducky:6666" \
        -p "$p_web:4443" \
        -p "$p_api:6643" \
        -p "$p_ldap:389" \
        -p "$p_ldaps:636" \
        vaultaire-devcomp:latest >/dev/null

    info "core « $nom » démarré sur la base de la pile :"
    info "  portail  https://localhost:$p_web/login   Ducky $p_ducky   API $p_api   LDAP $p_ldap / $p_ldaps"
    info "  vu du cluster : docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli cluster list"
    info "  journaux : docker logs -f vlt-dev-$nom"
    # Dit ici plutôt que dans un document que personne n'ouvre au moment utile.
    info "  ⚠ deux cores sur une même base ne sont PAS encore éprouvés"
    info "    (docs/Developement/DO/2.2/2.2.md, docs/exploitation/A_TESTER.md § 21)."
}

controler_ports_env

case "$ACTION" in
    down)
        # D'ABORD les nœuds ajoutés, ENSUITE le compose. L'ordre inverse
        # paraissait naturel et ne marche pas : ces conteneurs sont attachés au
        # réseau de la pile, donc « compose down » ne peut pas le retirer
        # (« has active endpoints »), sort en erreur, et « set -e » arrête le
        # script AVANT la ligne qui devait justement les retirer.
        AJOUTES="$(noeuds_ajoutes)"
        if [ -n "$AJOUTES" ]; then
            docker rm -f $AJOUTES >/dev/null
            info "nœuds ajoutés retirés (leurs identités restent dans leurs volumes)"
        fi
        docker compose "${TOUS[@]}" down
        exit 0 ;;
    reset)
        AJOUTES="$(noeuds_ajoutes)"
        if [ -n "$AJOUTES" ]; then docker rm -f $AJOUTES >/dev/null; fi
        docker compose "${TOUS[@]}" down -v
        # Les volumes d'identité partent avec la base : les garder ferait
        # revenir des proxies qui se croient enrôlés auprès d'un core qui ne
        # connaît plus personne.
        VOLS="$(volumes_ajoutes)"
        if [ -n "$VOLS" ]; then docker volume rm $VOLS >/dev/null; fi
        rm -rf "$BUILD"
        info "pile, base, nœuds ajoutés et binaires effacés"
        exit 0 ;;
    logs)   docker compose logs -f vaultaire-ad; exit 0 ;;
    status)
        docker compose "${TOUS[@]}" ps
        if [ -n "$(noeuds_ajoutes)" ]; then
            info "nœuds ajoutés :"
            docker ps -a --filter "label=$ETIQUETTE" \
                --format 'table {{.Names}}\t{{.Label "vaultaire.devcomp.role"}}\t{{.Status}}\t{{.Ports}}'
        fi
        if [ -x "$BUILD/vaultaire_server/vaultaire_serveur" ]; then
            info "binaires compilés le $(date -r "$BUILD/vaultaire_server/vaultaire_serveur" '+%d/%m/%Y %H:%M')"
        else
            info "aucun binaire compilé ($BUILD)"
        fi
        exit 0 ;;
    noeuds)
        if [ -z "$(noeuds_ajoutes)" ]; then
            info "aucun nœud ajouté (voir --add-proxy, --add-core)"
        else
            docker ps -a --filter "label=$ETIQUETTE" \
                --format 'table {{.Names}}\t{{.Label "vaultaire.devcomp.role"}}\t{{.Status}}\t{{.Ports}}'
        fi
        exit 0 ;;
    rm-noeud)
        [ -n "$NOM_NOEUD" ] || erreur "quel nœud ? Exemple : --rm-noeud proxy2 (voir --noeuds)"
        # Le filtre par ÉTIQUETTE n'est pas un raffinement : sans lui, le nom est
        # simplement concaténé à « vlt-dev- », et « --rm-noeud db » détruirait
        # vlt-dev-db — la base de la pile — en annonçant « nœud retiré ».
        valider_nom "$NOM_NOEUD"
        CIBLE="$(docker ps -aq --filter "label=$ETIQUETTE" --filter "name=^vlt-dev-$NOM_NOEUD\$")"
        [ -n "$CIBLE" ] || erreur \
"« $NOM_NOEUD » n'est pas un nœud ajouté (voir --noeuds).
  Les conteneurs de la pile de base — vlt-dev-ad, vlt-dev-db, vlt-dev-proxy,
  vlt-dev-nexus — ne se retirent pas ainsi : --down."
        # Détruire l'IDENTIFIANT trouvé, pas le nom reconstruit : le contrôle
        # porte sur une expression régulière, la destruction sur un littéral, et
        # les faire diverger est la façon ordinaire de détruire autre chose que
        # ce qu'on a vérifié.
        docker rm -f $CIBLE >/dev/null
        # L'identité part avec le conteneur : la garder ferait revenir un proxy
        # qui se croit enrôlé alors que sa ligne a pu être purgée côté core.
        # Un core n'a pas de volume — d'où le message qui suit, qui ne promet
        # que ce qui a vraiment été fait.
        if docker volume rm "devcomp_keys_$NOM_NOEUD" >/dev/null 2>&1; then
            info "nœud « $NOM_NOEUD » retiré : conteneur et identité enrôlée"
        else
            info "nœud « $NOM_NOEUD » retiré (conteneur ; il n'avait pas de volume d'identité)"
        fi
        # Ce n'est pas une remarque de confort : sa ligne détient le NOM du nœud,
        # et un nœud recréé sous ce nom avec une identité neuve se voit refuser
        # l'enregistrement — « ce nom de nœud appartient déjà à un autre client ».
        # Il tourne alors sans jamais apparaître dans « cluster list ».
        info "  sa ligne reste dans cluster_nodes jusqu'à la purge (vlt cluster purge-delay) :"
        info "  ne reprenez pas ce nom d'ici là, ou purgez-la d'abord."
        exit 0 ;;
    add-proxy) ajouter_proxy; exit 0 ;;
    add-core)  ajouter_core;  exit 0 ;;
esac

# --- version à injecter ---------------------------------------------
prochaine_version() {
    local serie dernier
    serie="$(tr -d '[:space:]' < "$RACINE/VERSION")"
    [[ "$serie" =~ ^[0-9]+\.[0-9]+$ ]] || erreur "VERSION illisible : « $serie » (attendu X.Y)"
    dernier="$(git -C "$RACINE" tag --list "v${serie}.*" 2>/dev/null \
        | sed -nE "s/^v${serie//./\\.}\.([0-9]+)$/\1/p" | sort -n | tail -1)"
    if [ -z "$dernier" ]; then
        echo "${serie}.0"
    else
        echo "${serie}.$((dernier + 1))"
    fi
}

if [ "$COMPILER" = 1 ]; then
    VERSION_DEV="${VERSION_IMPOSEE:-$(prochaine_version)}"
    [[ "$VERSION_DEV" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || erreur "--version doit être de la forme X.Y.Z (reçu : $VERSION_DEV)"
    info "compilation de la version $VERSION_DEV depuis $RACINE"
    mkdir -p "$BUILD"

    if [ "$LOCAL" = 1 ]; then
        # Sur l'hôte : plus rapide, mais les binaires suivent la glibc de
        # l'hôte. À réserver à un hôte Rocky 9 / RHEL 9.
        VAULTAIRE_ROOT="$RACINE" VAULTAIRE_BUILD_DIR="$BUILD" VAULTAIRE_VERSION="$VERSION_DEV" \
            "$RACINE/auto-compil.sh"
    else
        # Dans le conteneur Rocky 9 : même recette que la CI de release.
        HOST_UID="$(id -u)" HOST_GID="$(id -g)" VAULTAIRE_VERSION="$VERSION_DEV" \
            docker compose --profile build run --rm --build builder
    fi
fi

# --- contrôle de ce qui va être monté ------------------------------------
for f in vaultaire_server/vaultaire_serveur vaultaire_server/vaultaire_cli vaultaire_client/vaultaire_client vaultaire_ctl/vaultaire_ctl; do
    [ -x "$BUILD/$f" ] || erreur "$BUILD/$f absent : lancez sans --no-build"
done
# Le binaire du Nexus n'est exigé que si son conteneur démarre : son IMAGE, elle,
# se construit sans lui (elle ne contient aucun binaire).
if [ "$NEXUS" = 1 ]; then
    [ -x "$BUILD/vaultaire_nexus/vaultaire_nexus" ] || erreur "binaire du Nexus absent : lancez sans --no-build"
fi
if [ "$PROXY" = 1 ]; then
    [ -x "$BUILD/vaultaire_proxy/vaultaire_proxy" ] || erreur "binaire du proxy absent : lancez sans --no-build"
    # lire_env plutôt qu'un grep/cut de plus : celui-ci ne gardait pas la
    # DERNIÈRE occurrence et ne nettoyait pas le « \r » d'un .env en CRLF — copié
    # depuis Windows, une clé VIDE y valait « \r », donc non vide, et ce contrôle
    # laissait démarrer un proxy sans clé.
    if ! docker volume inspect dev-comp_devcomp_proxy_keys >/dev/null 2>&1 \
       && [ -z "$(lire_env DEVCOMP_PROXY_ENROLL_KEY '')" ]; then
        erreur "premier démarrage du proxy : il lui faut une clé d'enrôlement.
  Démarrez d'abord le core (sans --proxy), puis :
    docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli enroll create --type vaultaire_proxy
  et mettez la clé dans deployments/dev-comp/.env : DEVCOMP_PROXY_ENROLL_KEY=VLT-ENR-…"
    fi
fi

# --- images ----------------------------------------------------------------
# Les TROIS images sont construites, même si seul le core démarre : une image
# qui n'existe pas se découvre au moment où l'on veut s'en servir. Elles ne
# contiennent aucun binaire (tout est monté), donc c'est rapide et le cache
# Docker fait le reste.
info "construction des images (core, proxy, nexus)"
docker compose "${TOUS[@]}" build vaultaire-ad vlt-proxy vaultaire-nexus

# --- démarrage -------------------------------------------------------------
# Les binaires étant montés, un redémarrage suffit à prendre en compte une
# recompilation.
docker compose "${PROFILS[@]}" up -d
A_REDEMARRER=(vaultaire-ad)
[ "$PROXY" = 1 ] && A_REDEMARRER+=(vlt-proxy)
[ "$NEXUS" = 1 ] && A_REDEMARRER+=(vaultaire-nexus)
docker compose "${PROFILS[@]}" restart "${A_REDEMARRER[@]}" >/dev/null

info "pile démarrée :"
# Le mot de passe d'amorçage n'est plus « admin123 » : le core refuse de
# démarrer sur les valeurs du dépôt (TO-DO 99). Il vient de l'environnement, et
# il est PROVISOIRE — le portail demandera de le changer à la première
# connexion, ce qui est le comportement à éprouver ici aussi.
info "  portail    https://localhost:$(lire_port DEVCOMP_PORT_WEB 4443)/login   (admin / $(lire_env VAULTAIRE_ADMIN_PASSWORD 'correcte agrafe batterie'))"
info "             ce mot de passe est PROVISOIRE : le portail en demandera un autre."
info "  CLI        docker exec -it vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli"
info "  agent      $BUILD/vaultaire_client/  (servi aux machines par « create -c … -join »)"
[ "$NEXUS" = 1 ] && info "  nexus      https://localhost:$(lire_port DEVCOMP_PORT_NEXUS 8843)/   (admin ; mot de passe initial : docker exec vlt-dev-nexus cat /var/lib/vaultaire_nexus/admin.initial)"
info "  journaux   ./deployments/dev-comp/dev-comp.sh --logs"
