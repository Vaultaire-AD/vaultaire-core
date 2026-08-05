# ====================================================================
# vaultaire_proxy — image d'exécution minimale
# ====================================================================
#
# Contrairement à l'image du serveur, celle-ci COMPILE et embarque son binaire.
#
# La raison est le lieu d'exécution : le serveur tourne sur le poste de
# développement, où cmd/ est monté et où recompiler est immédiat. Un proxy
# tourne ailleurs — en périphérie, chez un client, dans un réseau qu'on ne
# maîtrise pas. Une image qui dépend d'un volume monté depuis l'hôte n'y est pas
# déployable.
#
# Résultat : ~15 Mo, un seul binaire statique, aucun outil de compilation.

# --------------------------------------------------------------------
# Étage 1 — compilation
# --------------------------------------------------------------------
FROM golang:1.23-alpine AS builder

# bash pour install.sh, git pour -buildvcs.
RUN apk add --no-cache bash git

WORKDIR /build

# Le SDK est copié À CÔTÉ des sources du proxy, et install.sh est rejoué ici.
#
# On ne se contente pas du duckynetwork/ présent dans le dépôt : le binaire
# livré doit être compilé sur la version du protocole présente dans
# ducky-network-sdk au moment du build, pas sur une copie que quelqu'un aurait
# oublié de rafraîchir. C'est exactement ce qui avait laissé l'ancien proxy sur
# PKCS#1 v1.5 quand le core est passé à OAEP : un binaire parfaitement compilé
# qui ne parlait plus au serveur.
COPY src/ducky-network-sdk/ ./ducky-network-sdk/
COPY src/vaultaire_proxy/   ./vaultaire_proxy/

RUN ./ducky-network-sdk/install.sh /build/vaultaire_proxy

WORKDIR /build/vaultaire_proxy

# CGO_ENABLED=0 produit un binaire sans dépendance à la libc : c'est ce qui
# permet à l'étage suivant d'être quasi vide. Le proxy n'utilise ni cgo ni
# résolution NSS.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -buildvcs=false \
        -ldflags="-s -w" \
        -o /out/vaultaire_proxy .

# --------------------------------------------------------------------
# Étage 2 — exécution
# --------------------------------------------------------------------
#
# alpine plutôt que scratch, sciemment.
#
# scratch gagnerait 7 Mo, mais retirerait tout moyen de diagnostiquer un proxy
# déployé loin : pas de shell, pas de ping, pas de cat sur le fichier de
# configuration. Sur une machine qu'on ne peut pas atteindre autrement, ces
# 7 Mo achètent la possibilité d'un `docker exec`.
FROM alpine:3.20

LABEL maintainer="adm-lviguie"
LABEL description="Vaultaire proxy - client de service du cluster"
LABEL env="preprod"

# ca-certificates n'est pas requis par le protocole Ducky, qui chiffre lui-même,
# mais évite une surprise le jour où le proxy appellera un service en HTTPS.
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S vaultaire \
    && adduser -S -G vaultaire -h /var/lib/vaultaire_proxy vaultaire \
    && mkdir -p /etc/vaultaire_proxy /var/lib/vaultaire_proxy/keys \
    && chown -R vaultaire:vaultaire /var/lib/vaultaire_proxy \
    && chmod 700 /var/lib/vaultaire_proxy/keys

COPY --from=builder /out/vaultaire_proxy /usr/local/bin/vaultaire_proxy
COPY --chown=vaultaire:vaultaire src/vaultaire_proxy/config.example.yaml \
     /etc/vaultaire_proxy/config.example.yaml

# Le proxy n'a besoin d'aucun privilège : il ouvre une connexion SORTANTE vers
# le core et n'écrit que dans son répertoire de clés. Tourner en root lui
# donnerait un pouvoir dont il ne fait rien, sur une machine exposée.
USER vaultaire

WORKDIR /var/lib/vaultaire_proxy

# 389 et 8443 pour la répartition de charge à venir. La v1 n'écoute rien : elle
# ne fait que se connecter au core.
EXPOSE 389 8443

ENTRYPOINT ["/usr/local/bin/vaultaire_proxy"]
CMD ["--config", "/etc/vaultaire_proxy/config.yaml"]
