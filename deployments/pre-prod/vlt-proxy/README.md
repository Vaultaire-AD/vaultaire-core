# Déploiement du proxy Vaultaire

Pile autonome. **Rien n'est compilé ici** : le binaire vient de
`cmd/vaultaire_proxy/`, produit par `auto-compil.sh` — même principe que l'image
du serveur.

## Ce que fait ce proxy

Trois choses, et rien d'autre :

```
enrôlement au premier démarrage   (01_05 → 01_08)
authentification du serveur       (01_01 → 01_02)
authentification du client        (02_01 → 02_11)
```

Pas de cluster, pas de répartition de charge. Il apparaît dans `vlt client list`,
pas dans `vlt cluster list`.

## Mise en service

```bash
# 1. Sur le CORE : créer une clé d'enrôlement typée
vlt enroll create --type vaultaire_proxy --uses 5 --expires 24h

# 2. Sur l'hôte : compiler
./auto-compil.sh

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

Un `config.yaml` reste possible pour une configuration plus fournie — voir
`config.example.yaml` — mais **il n'est pas nécessaire**. Quand les deux sont
présents, les variables l'emportent : en conteneur, le fichier est figé dans un
volume alors que l'environnement est ce qu'on ajuste au déploiement.

## Mise à jour

```bash
./auto-compil.sh && docker compose restart vlt-proxy
```

L'image ne se reconstruit que si le `Dockerfile` ou l'`entrypoint.sh` change. Le
binaire étant monté, un `docker compose build` ne sert à rien après une
recompilation.

## Privilèges

Le conteneur **démarre en root** et **finit en UID 10001**.

L'entrypoint fait une seule chose avec ses privilèges : reprendre la propriété du
volume d'identité, puis les abandonner avec `setpriv` avant d'exécuter le proxy.
Le processus qui parle au réseau tourne donc sans privilège — il n'ouvre que des
connexions sortantes et n'écrit que dans son répertoire de clés.

**Pourquoi pas simplement `USER` dans le Dockerfile.** Docker crée un volume
nommé avec la propriété qu'avait le répertoire dans l'image *au moment de la
création*, et ne la remet jamais à jour. Un volume plus ancien que l'image
courante appartient donc à un autre UID, et un conteneur non privilégié ne peut
rien y faire — sans autre issue que de détruire le volume, donc de réenrôler et
de consommer un jeton.

Reprendre le volume au démarrage rend le conteneur remplaçable : l'identité du
proxy survit aux reconstructions d'image.

**Le binaire monté doit rester en 0755.** `auto-compil.sh` le pose, et le mode est
enregistré dans git. Symptôme sinon :

```
exec: "/opt/vaultaire/bin/vaultaire_proxy": permission denied
```

Correction : `chmod 755 cmd/vaultaire_proxy/vaultaire_proxy` sur l'hôte, et
`git update-index --chmod=+x` pour que ça ne revienne pas au prochain `pull`.

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
| `binaire absent de /opt/vaultaire/bin/…` | `./auto-compil.sh` n'a pas tourné |
| `binaire non exécutable` | `chmod 755 cmd/vaultaire_proxy/vaultaire_proxy` |
| `aucune configuration` | ni `VAULTAIRE_IP_CORE` ni `config.yaml` |
| `aucun serveur déclaré` | `VAULTAIRE_IP_CORE` vide ou mal formé |
| `VAULTAIRE_IP_CORE : port invalide dans …` | port hors 1-65535, ou non numérique |
| `aucune clé d'enrôlement dans la configuration` | `VAULTAIRE_ENROLL_KEY` vide |
| `enrôlement refusé (invalid_key)` | clé inconnue, expirée, épuisée ou révoquée — le motif exact est dans le journal du **core**, jamais renvoyé au client |
| `aucune session authentifiée après 30s` | core injoignable, ou clé publique enregistrée côté core ≠ celle du proxy |
| `répertoire des clés … non inscriptible` | un `user:` a été ajouté au compose : l'entrypoint ne peut plus reprendre le volume |
