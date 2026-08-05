# Déploiement du proxy Vaultaire

Pile autonome. **Rien n'est compilé ici** : le binaire vient de
`cmd/vaultaire_proxy/`, produit par `auto-compil.sh` — même principe que l'image
du serveur.

## Mise en service

```bash
# 1. Sur le CORE : créer une clé d'enrôlement typée
vlt enroll create --type vaultaire_proxy --uses 5 --expires 24h

# 2. Compiler
./auto-compil.sh

# 3. Ici : renseigner l'environnement
cp .env.example .env
$EDITOR .env          # VAULTAIRE_IP_CORE, VAULTAIRE_ENROLL_KEY, VAULTAIRE_PROXY_ENDPOINT

# 4. Démarrer
docker compose up -d

# 5. Vérifier
docker compose logs -f vlt-proxy
vlt cluster list      # sur le core : le proxy doit être « online »
```

## Mise à jour

```bash
./auto-compil.sh && docker compose restart vlt-proxy
```

L'image ne se reconstruit que si le `Dockerfile` change. Le binaire étant monté,
un `docker compose build` ne sert à rien après une recompilation.

## L'image

`debian:12-slim`, un utilisateur non privilégié, aucun outil de compilation.

Debian et non alpine : `auto-compil.sh` compile le proxy en `CGO_ENABLED=0`, donc
un binaire statique tournerait sur les deux. Mais si quelqu'un le recompile un
jour sans ce réglage, le binaire sera lié à la glibc et refusera de démarrer sur
la musl d'alpine — avec un `no such file or directory` qui désigne le binaire et
non la bibliothèque manquante. Debian évite ce piège.

## Le volume `vlt_proxy_keys`

Il porte l'identité du proxy : clé privée, clé publique du core, identifiant
attribué.

**`docker compose down -v` force un réenrôlement** et consomme une place de la
clé d'enrôlement. Répété, il épuise le quota et laisse le proxy dehors — avec un
message qui ne dit pas que la cause est là.

Pour un réenrôlement volontaire, préférez l'option explicite :

```bash
docker compose run --rm vlt-proxy --reset-identity
```

Elle conserve la clé publique du core, ce que la suppression du volume ne fait
pas.

## Réseau

Par défaut, le compose rejoint le réseau du core sur la même machine
(`pre-prod_Ducky-network`).

Sur une machine distincte — le cas normal pour un proxy —, commentez le bloc
`external`, décommentez `proxy-network`, et donnez à `VAULTAIRE_IP_CORE`
l'adresse routable du core.

## Diagnostic

```bash
docker compose logs -f vlt-proxy
docker compose exec vlt-proxy ls -l /var/lib/vaultaire_proxy/keys
```

| Message | Cause |
|---------|-------|
| `no such file or directory` sur l'entrypoint | `cmd/vaultaire_proxy/` vide : lancez `./auto-compil.sh` |
| `core_address requis` | `.env` absent ou `VAULTAIRE_IP_CORE` vide |
| `enrôlement refusé : expired` | clé expirée |
| `enrôlement refusé : exhausted` | quota épuisé — `--uses 0` pour l'illimité |
| `identité refusée par le core` | proxy supprimé côté core, ou base réinstallée |
| `service inconnu du cluster` | ligne purgée ; le proxy rejoue 04_09 seul |
