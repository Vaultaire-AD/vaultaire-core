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

# 3. Ici : la configuration
cp config.example.yaml config.yaml
$EDITOR config.yaml        # servers, enrollment.key

# 4. Démarrer
docker compose up -d
docker compose logs -f vlt-proxy

# 5. Sur le core : vérifier
vlt client list            # le proxy doit apparaître
vlt enroll list            # le compteur d'utilisations doit avoir bougé
```

## Mise à jour

```bash
./auto-compil.sh && docker compose restart vlt-proxy
```

L'image ne se reconstruit que si le `Dockerfile` ou l'`entrypoint.sh` change. Le
binaire étant monté, un `docker compose build` ne sert à rien après une
recompilation.

## Le conteneur tourne en utilisateur non privilégié

UID **10001**, fixé dans le Dockerfile. Le proxy n'ouvre que des connexions
sortantes et n'écrit que dans son répertoire de clés : root ne lui apporterait
qu'un pouvoir dont il ne fait rien.

Deux conséquences :

**Le binaire doit être en 0755.** `auto-compil.sh` le pose désormais lui-même.
Sur un binaire hérité d'une compilation antérieure, le symptôme est :

```
exec: "/opt/vaultaire/bin/vaultaire_proxy": permission denied
```

Correction sur l'hôte : `chmod 755 cmd/vaultaire_proxy/vaultaire_proxy`.
L'entrypoint vérifie et le dit avant que le runtime ne s'en mêle.

**L'UID est fixé, pas attribué.** Le volume des clés appartient au compte qui y
écrit en premier. Un UID variable d'une reconstruction à l'autre rendrait le
volume inaccessible à son successeur — donc réenrôlement, donc jeton consommé.

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
| `configuration absente` | `config.yaml` pas créé depuis l'exemple |
| `aucun serveur configuré` | section `servers` vide ou mal indentée |
| `aucune clé d'enrôlement dans la configuration` | `enrollment.key` vide |
| `enrôlement refusé (invalid_key)` | clé inconnue, expirée, épuisée ou révoquée — le motif exact est dans le journal du **core**, jamais renvoyé au client |
| `aucune session authentifiée après 30s` | core injoignable, ou clé publique enregistrée côté core ≠ celle du proxy |
