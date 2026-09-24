# Déploiement du proxy Vaultaire

Pile autonome. **Rien n'est compilé ici** : le binaire vient de
`cmd/vaultaire_proxy/`, installé depuis la **dernière release GitHub** par
`../docker-update.sh` — même principe que l'image du serveur.

## Ce que fait ce proxy

```
enrôlement au premier démarrage   (01_05 → 01_08)
authentification auprès du core   (01_01 → 01_02, 02_01 → 02_11)
déclaration au cluster et battement (04_01, 04_07)
relais Ducky : agents → cores     (TCP, octets transportés sans être lus)
```

Il apparaît dans `vlt client list` (son identité) **et** dans `vlt cluster list`
(le nœud de rôle `proxy`). Le relais est décrit dans
[`docs/proxy/relais.md`](../../../docs/proxy/relais.md).

## Mise en service

```bash
# 1. Sur le CORE : créer une clé d'enrôlement typée
vlt enroll create --type vaultaire_proxy --uses 5 --expires 24h

# 2. Sur l'hôte, à la racine du dépôt : installer la release
./deployments/pre-prod/docker-update.sh            # ou --version 2.1.3

# 3. Ici : deux valeurs dans docker-compose.yml
#      VAULTAIRE_IP_CORE=vaultaire-ad:6666
#      VAULTAIRE_ENROLL_KEY=<la clé de l'étape 1>
$EDITOR docker-compose.yml

# 4. Démarrer
docker compose up -d
docker compose logs -f vlt-proxy

# 5. Sur le core : vérifier
vlt client list            # le proxy doit apparaître
vlt enroll list            # le compteur d'utilisations doit avoir bougé
```

## Configuration

Deux valeurs suffisent, et elles se donnent en variables dans le
`docker-compose.yml` :

| Variable | Rôle |
|----------|------|
| `VAULTAIRE_IP_CORE` | `ip:port` du core. Port **6666 par défaut**, donc `vaultaire-ad` suffit. Plusieurs cores séparés par des virgules, essayés dans l'ordre. |
| `VAULTAIRE_ENROLL_KEY` | la clé créée sur le core. Lue au **premier démarrage seulement**. |
| `VAULTAIRE_ENROLL_LABEL` | nom lisible côté core. Facultatif, aucune valeur de sécurité. |
| `VAULTAIRE_LISTEN_PORT` | port du relais Ducky dans le conteneur, annoncé au cluster. `6666` par défaut ; publié sur `6667` de l'hôte (`VLT_PROXY_PORT`). |

> **Relais (2.2).** Le proxy transporte les connexions Ducky des agents vers les
> cores. Déclarez sur le core l'adresse par laquelle les agents le joignent :
> `vlt cluster expose <proxy> <adresse-de-l-hôte> 6667`. Détail :
> [`docs/proxy/`](../../../docs/proxy/README.md).

Un `config.yaml` reste possible pour une configuration plus fournie — voir
`config.example.yaml` — mais **il n'est pas nécessaire**. Quand les deux sont
présents, les variables l'emportent : en conteneur, le fichier est figé dans un
volume alors que l'environnement est ce qu'on ajuste au déploiement.

## Mise à jour

```bash
./deployments/pre-prod/docker-update.sh            # ou --version 2.1.3
```

Le script redémarre `vlt-proxy` s'il tourne sur le même hôte.

L'image ne se reconstruit que si le `Dockerfile` ou l'`entrypoint.sh` change. Le
binaire étant monté, un `docker compose build` ne sert à rien après une
recompilation.

## Privilèges

Le conteneur **démarre en root** et **finit en UID 10001**.

L'entrypoint fait une seule chose avec ses privilèges : reprendre la propriété du
volume d'identité, puis les abandonner avec `setpriv` avant d'exécuter le proxy.
Le processus qui parle au réseau tourne donc sans privilège — il écoute le port
du relais (6666 dans le conteneur, non privilégié), ouvre des connexions vers les
cores et n'écrit que dans son répertoire de clés.

**Pourquoi pas simplement `USER` dans le Dockerfile.** Docker crée un volume
nommé avec la propriété qu'avait le répertoire dans l'image *au moment de la
création*, et ne la remet jamais à jour. Un volume plus ancien que l'image
courante appartient donc à un autre UID, et un conteneur non privilégié ne peut
rien y faire — sans autre issue que de détruire le volume, donc de réenrôler et
de consommer un jeton.

Reprendre le volume au démarrage rend le conteneur remplaçable : l'identité du
proxy survit aux reconstructions d'image.

**Relais HTTPS et LDAPS.** Même contrainte pour eux : UID 10001, donc pas de
port sous 1024 dans le conteneur. Déclarez-les dans la section `relais:` sur un
port haut (`:8843`, `:1636`) et publiez 443 ou 636 sur l'hôte dans le
`docker-compose.yml` — voir [`docs/proxy/https-et-ldaps.md`](../../../docs/proxy/https-et-ldaps.md).

**Le binaire monté doit rester en 0755.** `docker-update.sh` le pose à
l'installation. Symptôme sinon :

```
exec: "/opt/vaultaire/bin/vaultaire_proxy": permission denied
```

Correction : `./deployments/pre-prod/docker-update.sh --force` sur l'hôte.

## Le volume `vlt_proxy_keys`

Il porte l'identité du proxy :

| Fichier | Écrit par |
|---------|-----------|
| `client_software.yaml` | l'enrôlement — identifiant et type attribués par le core |
| `private_key.pem` | l'enrôlement — ne quitte jamais l'hôte |
| `public.pem` | l'enrôlement |
| `serveurpublickey.pem` | `askkey` au premier contact |

**`docker compose down -v` force un réenrôlement** et consomme une utilisation de
la clé d'enrôlement. Répété, il épuise le quota et laisse le proxy dehors — avec
un message qui ne dit pas que la cause est là. Préférez `down` seul.

## Réseau

Par défaut, le compose rejoint le réseau du core sur la même machine
(`pre-prod_Ducky-network`).

Sur une machine distincte — le cas normal pour un proxy —, commentez le bloc
`external`, décommentez `proxy-network`, et mettez l'adresse routable du core
dans `config.yaml`.

## Diagnostic

```bash
docker compose logs -f vlt-proxy
docker compose exec vlt-proxy ls -l /var/lib/vaultaire_proxy/keys
```

| Message | Cause |
|---------|-------|
| `binaire absent de /opt/vaultaire/bin/…` | aucune release installée : `docker-update.sh` |
| `binaire non exécutable` | `docker-update.sh --force` |
| `aucune configuration` | ni `VAULTAIRE_IP_CORE` ni `config.yaml` |
| `aucun serveur déclaré` | `VAULTAIRE_IP_CORE` vide ou mal formé |
| `VAULTAIRE_IP_CORE : port invalide dans …` | port hors 1-65535, ou non numérique |
| `aucune clé d'enrôlement dans la configuration` | `VAULTAIRE_ENROLL_KEY` vide |
| `enrôlement refusé (invalid_key)` | clé inconnue, expirée, épuisée ou révoquée — le motif exact est dans le journal du **core**, jamais renvoyé au client |
| `aucune session authentifiée après 30s` | core injoignable, ou clé publique enregistrée côté core ≠ celle du proxy |
| `relais Ducky … alors que le port annoncé aux agents est …` | la section `relais:` du `config.yaml` écoute ailleurs que `VAULTAIRE_LISTEN_PORT` |
| `aucune cible joignable pour … — connexion refusée` | aucun core joignable depuis le proxy : voir [`docs/proxy/depannage.md`](../../../docs/proxy/depannage.md) |
| `répertoire des clés … non inscriptible` | un `user:` a été ajouté au compose : l'entrypoint ne peut plus reprendre le volume |
