#!/usr/bin/env bash
# Test de bout en bout de Vaultaire Nexus.
#
# Démarre un Nexus jetable (répertoire temporaire, port libre), puis le fait
# utiliser par les vrais clients : curl, dnf, apt, docker. Un client absent de
# la machine est signalé et son bloc ignoré — jamais compté comme réussi.
#
#   test/e2e.sh                  tout ce qui est disponible
#   E2E_KEEP=1 test/e2e.sh       garder le serveur et le répertoire à la fin
#   E2E_PORT=9443 test/e2e.sh    port imposé
#
# Docker : le démon doit approuver le certificat. Le script le dépose dans
# /etc/docker/certs.d/localhost:<port>/ si /etc/docker est inscriptible, sinon
# il saute le bloc.
set -uo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d -t nexus-e2e.XXXXXX)"
PORT="${E2E_PORT:-$(( 20000 + RANDOM % 20000 ))}"
BASE="https://localhost:$PORT"
PW="e2e-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
BIN="$TMP/vaultaire_nexus"
PID=""
OK=0; KO=0; SKIP=0

export NO_PROXY="localhost,127.0.0.1${NO_PROXY:+,$NO_PROXY}" no_proxy="localhost,127.0.0.1${no_proxy:+,$no_proxy}"

fin() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
    if [ "${E2E_KEEP:-0}" = 1 ]; then echo "(conservé : $TMP)"; else rm -rf "$TMP"; fi
    [ -n "${CERTDIR:-}" ] && rm -rf "$CERTDIR"
}
trap fin EXIT

ok()   { OK=$((OK+1));  printf '  \033[32m✔\033[0m %s\n' "$1"; }
ko()   { KO=$((KO+1));  printf '  \033[31m✘\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '      %s\n' "$2"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m–\033[0m %s (ignoré : %s)\n' "$1" "$2"; }
titre(){ printf '\n\033[1m%s\033[0m\n' "$1"; }
a()    { command -v "$1" >/dev/null 2>&1; }

c()    { curl -sk --noproxy '*' "$@"; }
code() { c -o /dev/null -w '%{http_code}' "$@"; }
egal() { # egal <libellé> <attendu> <obtenu>
    if [ "$2" = "$3" ]; then ok "$1"; else ko "$1" "attendu « $2 », obtenu « $3 »"; fi
}

# --------------------------------------------------------------------------
titre "Préparation"
(cd "$ICI" && CGO_ENABLED=0 go build -o "$BIN" .) || { echo "compilation impossible"; exit 1; }
cat > "$TMP/config.yaml" <<EOF
listen: "127.0.0.1:$PORT"
public_url: "$BASE"
data_dir: $TMP/data
log_path: $TMP/log
tls: { enable: true, self_signed: true }
auth:
  mode: local
  local_admin: { enable: true, username: admin }
repositories:
  - { name: rpmpub,  type: rpm, public: true, keep_versions: 2 }
  - { name: rpmpriv, type: rpm }
  - { name: debpub,  type: deb, public: true, distribution: bookworm }
  - { name: images,  type: docker }
  - { name: releases, type: vaultaire, public: true }
  - { name: outils,  type: generic }
EOF
NEXUS_ADMIN_PASSWORD="$PW" "$BIN" -config "$TMP/config.yaml" >"$TMP/nexus.log" 2>&1 &
PID=$!
for _ in $(seq 50); do c "$BASE/healthz" >/dev/null && break; sleep 0.2; done
egal "le service répond" "ok" "$(c "$BASE/healthz")"
A=(-u "admin:$PW")

# --------------------------------------------------------------------------
titre "Authentification"
egal "sans compte : 401 sur l'API" 401 "$(code "$BASE/api/v1/whoami")"
egal "mauvais mot de passe : 401" 401 "$(code -u admin:faux "$BASE/api/v1/whoami")"
egal "compte local : rôle admin" '"admin"' "$(c "${A[@]}" "$BASE/api/v1/whoami" | sed -nE 's/.*"role": *("[a-z]+").*/\1/p' | head -1)"
creer_jeton() { c "${A[@]}" -H 'Content-Type: application/json' -d "{\"label\":\"$1\",\"scope\":\"$2\"}" "$BASE/api/v1/tokens" | sed -nE 's/.*"token": *"([^"]+)".*/\1/p'; }
LECTEUR="$(creer_jeton e2e-lecteur reader)"
EDITEUR="$(creer_jeton e2e-editeur publisher)"
[ -n "$LECTEUR" ] && [ -n "$EDITEUR" ] && ok "jetons créés" || ko "création des jetons"

# --------------------------------------------------------------------------
titre "RPM / dnf"
if a rpmbuild; then
    mkdir -p "$TMP/rpm"
    for v in 1.0.0 1.1.0 1.2.0; do
        cat > "$TMP/rpm/e2e.spec" <<EOF
Name: nexus-e2e
Version: $v
Release: 1
Summary: paquet de test
License: MIT
BuildArch: noarch
%description
test
%install
mkdir -p %{buildroot}/usr/share/nexus-e2e
echo $v > %{buildroot}/usr/share/nexus-e2e/version
%files
/usr/share/nexus-e2e/version
EOF
        rpmbuild -bb --quiet --define "_topdir $TMP/rpm/top" "$TMP/rpm/e2e.spec" >/dev/null 2>&1
    done
    RPMS=("$TMP"/rpm/top/RPMS/noarch/nexus-e2e-*.rpm)
    for f in "${RPMS[@]}"; do c -o /dev/null -H "Authorization: Bearer $EDITEUR" -T "$f" "$BASE/api/v1/repos/rpmpub/upload"; done
    egal "republier une version : 409" 409 "$(code -H "Authorization: Bearer $EDITEUR" -T "${RPMS[-1]}" "$BASE/api/v1/repos/rpmpub/upload")"
    egal "jeton lecteur ne publie pas : 403" 403 "$(code -H "Authorization: Bearer $LECTEUR" -T "${RPMS[0]}" "$BASE/api/v1/repos/rpmpriv/upload")"
    egal "un non-RPM est refusé : 422" 422 "$(code "${A[@]}" -T "$TMP/config.yaml" "$BASE/api/v1/repos/rpmpriv/upload")"
    c -o /dev/null -H "Authorization: Bearer $EDITEUR" -T "${RPMS[0]}" "$BASE/api/v1/repos/rpmpriv/upload"
    sleep 2.5   # régénération différée des index
    egal "rétention : 2 versions gardées" 2 "$(c "${A[@]}" "$BASE/api/v1/repos/rpmpub/packages" | grep -c '"version"')"
    egal "dépôt privé sans compte : 401" 401 "$(code "$BASE/repo/rpm/rpmpriv/repodata/repomd.xml")"
    egal "dépôt privé avec jeton : 200" 200 "$(code -u "x:$LECTEUR" "$BASE/repo/rpm/rpmpriv/repodata/repomd.xml")"
    DNF="$(command -v dnf || true)"; [ -x /opt/wrap/dnf ] && DNF=/opt/wrap/dnf
    if [ -n "$DNF" ]; then
        RQ=("$DNF" -q --installroot="$TMP/dnfroot" --releasever=9 --disablerepo='*' --setopt=cachedir="$TMP/dnfcache")
        vus="$("${RQ[@]}" --repofrompath=p,"$BASE/repo/rpm/rpmpub/" --setopt=p.sslverify=0 --setopt=p.gpgcheck=0 --setopt=p.proxy= --enablerepo=p repoquery --available nexus-e2e 2>/dev/null | sort | tr '\n' ' ')"
        egal "dnf voit les versions retenues" "nexus-e2e-0:1.1.0-1.noarch nexus-e2e-0:1.2.0-1.noarch " "$vus"
        vus="$("${RQ[@]}" --repofrompath=q,"$BASE/repo/rpm/rpmpriv/" --setopt=q.sslverify=0 --setopt=q.gpgcheck=0 --setopt=q.proxy= --setopt=q.username=ci --setopt=q.password="$LECTEUR" --enablerepo=q repoquery --available nexus-e2e 2>/dev/null | tr -d '\n')"
        egal "dnf lit le dépôt privé avec un jeton" "nexus-e2e-0:1.0.0-1.noarch" "$vus"
    else
        skip "dnf" "dnf absent"
    fi
else
    skip "bloc RPM" "rpmbuild absent"
fi

# --------------------------------------------------------------------------
titre "Debian / apt"
if a dpkg-deb; then
    mkdir -p "$TMP/deb/pkg/DEBIAN" "$TMP/deb/pkg/usr/share/nexus-e2e"
    for v in 1.0.0 2.0.0; do
        echo "$v" > "$TMP/deb/pkg/usr/share/nexus-e2e/version"
        printf 'Package: nexus-e2e\nVersion: %s\nArchitecture: all\nMaintainer: e2e <e2e@local>\nDescription: paquet de test\n' "$v" > "$TMP/deb/pkg/DEBIAN/control"
        dpkg-deb -Zxz --build "$TMP/deb/pkg" "$TMP/deb/nexus-e2e_${v}_all.deb" >/dev/null
        egal "publication .deb $v" 201 "$(code "${A[@]}" -T "$TMP/deb/nexus-e2e_${v}_all.deb" "$BASE/api/v1/repos/debpub/upload")"
    done
    sleep 2.5
    if a apt-get; then
        R="$TMP/apt"; mkdir -p "$R/etc/apt/sources.list.d" "$R/etc/apt/preferences.d" "$R/var/lib/apt/lists/partial" "$R/var/cache/apt/archives/partial" "$R/var/lib/dpkg"
        touch "$R/var/lib/dpkg/status"
        echo "deb [trusted=yes] $BASE/repo/deb/debpub bookworm main" > "$R/etc/apt/sources.list"
        O=(-o "Dir=$R" -o "Dir::State::status=$R/var/lib/dpkg/status" -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false -o Acquire::https::Proxy=false -o Debug::NoLocking=1 -o APT::Architecture=amd64)
        apt-get "${O[@]}" update >/dev/null 2>&1
        egal "apt choisit la plus haute version" "2.0.0" "$(apt-cache "${O[@]}" policy nexus-e2e 2>/dev/null | sed -nE 's/ *Candidate: *//p')"
    else
        skip "apt" "apt-get absent"
    fi
else
    skip "bloc Debian" "dpkg-deb absent"
fi

# --------------------------------------------------------------------------
titre "Docker"
if a docker && docker info >/dev/null 2>&1 && [ -w /etc/docker ] 2>/dev/null; then
    CERTDIR="/etc/docker/certs.d/localhost:$PORT"
    mkdir -p "$CERTDIR" && c -o "$CERTDIR/ca.crt" "$BASE/repo/keys/nexus.crt"
    IMG="localhost:$PORT/images/e2e/app"
    mkdir -p "$TMP/img" && echo e2e > "$TMP/img/fichier" && tar -C "$TMP/img" -cf "$TMP/img.tar" fichier
    docker import "$TMP/img.tar" "$IMG:1.0" >/dev/null
    if echo "$EDITEUR" | docker login "localhost:$PORT" -u ci --password-stdin >/dev/null 2>&1; then ok "docker login (jeton)"; else ko "docker login"; fi
    if docker push -q "$IMG:1.0" >/dev/null 2>&1; then ok "docker push"; else ko "docker push"; fi
    docker rmi "$IMG:1.0" >/dev/null 2>&1
    if docker pull -q "$IMG:1.0" >/dev/null 2>&1; then ok "docker pull"; else ko "docker pull"; fi
    egal "tags listés" '{"name":"images/e2e/app","tags":["1.0"]}' "$(c "${A[@]}" "$BASE/v2/images/e2e/app/tags/list")"
    egal "registre sans compte : 401" 401 "$(code "$BASE/v2/images/e2e/app/tags/list")"
    sleep 2.5
    egal "pull compté dans le suivi" 1 "$(grep -h '"a":"pull"' "$TMP"/data/usage/*.jsonl | grep -c 'e2e/app')"
    docker logout "localhost:$PORT" >/dev/null 2>&1; docker rmi "$IMG:1.0" >/dev/null 2>&1
else
    skip "bloc Docker" "démon absent ou /etc/docker non inscriptible"
fi

# --------------------------------------------------------------------------
titre "Releases Vaultaire (compatibilité docker-update.sh)"
mkdir -p "$TMP/rel"
COMPOSANTS="vaultaire_server vaultaire_client vaultaire_ctl vaultaire_proxy"
for v in 2.0.0 2.1.0; do
    for n in $COMPOSANTS; do
        mkdir -p "$TMP/rel/$n" && echo "$n $v" > "$TMP/rel/$n/bin"
        tar -C "$TMP/rel" -czf "$TMP/rel/$n-v$v-linux-amd64.tar.gz" "$n"
        c -o /dev/null "${A[@]}" -T "$TMP/rel/$n-v$v-linux-amd64.tar.gz" "$BASE/api/v1/repos/releases/upload/"
    done
done
API="$BASE/repo/vaultaire/releases/api"; DL="$BASE/repo/vaultaire/releases/download"
tags_de() { tr ',' '\n' | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p'; }   # repris de docker-update.sh
egal "liste des releases" "v2.1.0 v2.0.0" "$(c "$API/releases?per_page=20" | tags_de | tr '\n' ' ' | sed 's/ $//')"
egal "dernière release" "v2.1.0" "$(c "$API/releases/latest" | tags_de | head -1)"
V="$TMP/verif"; mkdir -p "$V"
c -f -o "$V/SHA256SUMS" "$DL/v2.0.0/SHA256SUMS"
for n in $COMPOSANTS; do c -f -o "$V/$n-v2.0.0-linux-amd64.tar.gz" "$DL/v2.0.0/$n-v2.0.0-linux-amd64.tar.gz"; done
if (cd "$V" && sha256sum --quiet -c SHA256SUMS); then ok "sha256sum -c SHA256SUMS"; else ko "sha256sum -c SHA256SUMS"; fi
egal "tag inconnu : 404" 404 "$(code "$API/releases/tags/v9.9.9")"

# --------------------------------------------------------------------------
titre "Fichiers génériques"
echo un > "$TMP/outil.sh"
egal "publication 1.9.0" 201 "$(code "${A[@]}" -T "$TMP/outil.sh" "$BASE/api/v1/repos/outils/upload/outil.sh?name=outil&version=1.9.0")"
echo deux > "$TMP/outil.sh"
egal "publication 1.10.0" 201 "$(code "${A[@]}" -T "$TMP/outil.sh" "$BASE/api/v1/repos/outils/upload/outil.sh?name=outil&version=1.10.0")"
egal "latest = 1.10.0 (ordre des versions)" "deux" "$(c -u "x:$LECTEUR" "$BASE/repo/files/outils/outil/latest/outil.sh")"
egal "dépôt privé sans compte : 401" 401 "$(code "$BASE/repo/files/outils/outil/latest/outil.sh")"
egal "empreinte annoncée" "$(sha256sum "$TMP/outil.sh" | cut -d' ' -f1)" \
    "$(c -u "x:$LECTEUR" -D - -o /dev/null "$BASE/repo/files/outils/outil/1.10.0/outil.sh" | tr -d '\r' | sed -nE 's/^[Xx]-[Cc]hecksum-[Ss]ha256: *//p')"

# --------------------------------------------------------------------------
titre "Interface web"
J="$TMP/cookies"
egal "page de connexion" 200 "$(code -c "$J" "$BASE/login")"
egal "connexion refusée" 401 "$(code -b "$J" -c "$J" -d username=admin -d password=faux "$BASE/login")"
egal "connexion acceptée" 303 "$(code -b "$J" -c "$J" -d username=admin --data-urlencode "password=$PW" "$BASE/login")"
for p in / /ui/repos /ui/repos/rpmpub /ui/repos/releases /ui/repos/outils /ui/usage /ui/tokens /ui/admin "/ui/search?q=e2e"; do
    egal "page $p" 200 "$(code -b "$J" "$BASE$p")"
done
CSRF="$(c -b "$J" "$BASE/ui/admin" | sed -nE 's/.*name="csrf" value="([^"]+)".*/\1/p' | head -1)"
egal "formulaire sans CSRF : 403" 403 "$(code -b "$J" -d name=x -d type=rpm "$BASE/ui/repos")"
egal "création de dépôt avec CSRF" 303 "$(code -b "$J" -d "csrf=$CSRF" -d name=cree-e2e -d type=generic "$BASE/ui/repos")"
egal "déconnexion" 303 "$(code -b "$J" -c "$J" -d "csrf=$CSRF" "$BASE/logout")"
egal "session fermée" 303 "$(code -b "$J" "$BASE/ui/repos")"

# --------------------------------------------------------------------------
titre "Suivi et administration"
egal "statistiques disponibles" 200 "$(code "${A[@]}" "$BASE/api/v1/usage?days=7")"
egal "export réservé aux admins" 403 "$(code -H "Authorization: Bearer $LECTEUR" "$BASE/api/v1/usage/export")"
ID="$(c "${A[@]}" "$BASE/api/v1/tokens" | sed -nE 's/.*"id": *"([^"]+)".*/\1/p' | head -1)"
egal "révocation d'un jeton" 204 "$(code "${A[@]}" -X DELETE "$BASE/api/v1/tokens/$ID")"
egal "GC à blanc" 200 "$(code "${A[@]}" -X POST "$BASE/api/v1/admin/gc?dry_run=1")"
if grep -q "$PW" "$TMP/nexus.log" "$TMP"/log/* 2>/dev/null; then ko "le mot de passe n'apparaît dans aucun journal"; else ok "le mot de passe n'apparaît dans aucun journal"; fi

# --------------------------------------------------------------------------
printf '\n\033[1mRésultat : %d réussi(s), %d échec(s), %d ignoré(s)\033[0m\n' "$OK" "$KO" "$SKIP"
[ "$KO" -eq 0 ] || { echo "journal : $TMP/nexus.log"; E2E_KEEP=1; exit 1; }
