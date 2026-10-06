[⌂ Documentation](../README.md) › [Proxy](./README.md) › Déploiement

# Déployer un proxy

[Relais →](./relais.md)

---

## Les quatre étapes

```bash
# 1. Sur le core : une clé d'enrôlement typée (option : groupes d'affinité)
vlt enroll create --type vaultaire_proxy --uses 1 --expires 24h --groups lyon

# 2. Sur l'hôte du proxy : démarrer vlt-proxy avec la clé (voir plus bas)

# 3. Sur le core : dire par où les AGENTS joignent le proxy
vlt cluster expose <proxy> <adresse-vue-des-agents> <port>

# 4. Vérifier
vlt cluster list          # rôle proxy, en ligne, adresse exposée
```

L'étape 3 est celle qu'on oublie. Le proxy annonce l'adresse qu'il voit de
lui-même — dans un conteneur, une adresse du réseau Docker que personne ne
joint. `cluster expose` la remplace, pour les agents seulement, par l'adresse de
l'hôte et le port publié.

## Le binaire et ses options

| Option | Rôle |
|---|---|
| `-config` | fichier YAML (`/etc/vaultaire_proxy/config.yaml`) : cores, enrôlement, relais |
| `-keys` | répertoire de l'identité (clé privée, clé du core, identifiant) |
| `-listen-port` | **obligatoire.** Port du relais Ducky, annoncé au cluster en `04_01` |
| `-no-enroll` | refuser l'enrôlement automatique : sans identité en place, le proxy s'arrête |
| `-domain` | domaine de rattachement du nœud |
| `-debug` | journalise le niveau DEBUG, dont une ligne par connexion relayée |

Sans `-listen-port`, le proxy refuse de démarrer : il annoncerait aux agents un
port où rien n'écoute.

Au démarrage, dans cet ordre : enrôlement si besoin, session authentifiée avec
un core, déclaration au cluster (`04_01`), puis **ouverture des relais**. Si un
relais ne peut pas écouter (port pris, configuration invalide), le proxy
s'arrête : un proxy annoncé mais muet serait un trou noir pour les agents.

## En conteneur (préprod)

`deployments/pre-prod/vlt-proxy/` — le binaire vient de la release installée par
`docker-update.sh`. Variables :

| Variable | Défaut | Rôle |
|---|---|---|
| `VAULTAIRE_IP_CORE` | — | `hôte:port` du ou des cores, séparés par des virgules |
| `VAULTAIRE_ENROLL_KEY` | — | clé d'enrôlement, lue au premier démarrage seulement |
| `VAULTAIRE_ENROLL_LABEL` | — | nom lisible côté core |
| `VAULTAIRE_LISTEN_PORT` | `6666` | port du relais **dans** le conteneur, passé en `--listen-port` |
| `VLT_PROXY_PORT` | `6667` | port publié sur l'hôte |

Le port publié diffère du port annoncé (6667 sur l'hôte, 6666 dans le
conteneur) : c'est précisément ce que `cluster expose` corrige.

```bash
vlt cluster expose proxy-preprod-01 192.0.2.10 6667
```

Détail, privilèges et volume d'identité :
[`deployments/pre-prod/vlt-proxy/README.md`](../../deployments/pre-prod/vlt-proxy/README.md).

## Avec la version en cours de développement (dev-comp)

`deployments/dev-comp/` compile le dépôt local et démarre core + base + proxy,
sans release :

```bash
./deployments/dev-comp/dev-comp.sh                          # core d'abord
docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli enroll create --type vaultaire_proxy
echo 'DEVCOMP_PROXY_ENROLL_KEY=VLT-ENR-…' >> deployments/dev-comp/.env
./deployments/dev-comp/dev-comp.sh --no-build --proxy
docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli cluster expose <proxy> <IP-de-l-hôte> 6667
```

Voir [`deployments/dev-comp/README.md`](../../deployments/dev-comp/README.md).

## Sur une machine (sans conteneur)

```bash
vaultaire_proxy -config /etc/vaultaire_proxy/config.yaml \
                -keys /etc/vaultaire_proxy/.ssh -listen-port 6666
```

Modèle de configuration : `src/vaultaire_proxy/config.example.yaml`. Le port
6666 n'est pas privilégié : le proxy tourne sans root. Le pare-feu de l'hôte
doit laisser entrer ce port depuis les agents, et sortir vers le 6666 des cores.

## Placer le proxy dans l'ordre des agents

Les agents reçoivent en `04_04` une liste **ordonnée** : proxies affins, autres
proxies, cores affins, autres cores. Les réglages :

| Commande | Effet |
|---|---|
| `vlt cluster affinity <proxy> <groupe…>` | le proxy passe en tête pour les machines de ces groupes |
| `vlt cluster priority <proxy> <n>` | départage entre pairs (plus petit = plus tôt) |
| `vlt cluster rotation <proxy> out` | le proxy n'est plus distribué aux agents (il continue de relayer ceux qui l'ont déjà) |

Les cores restent toujours en queue de liste : un proxy tombé est contourné.
Voir la [formation, jalon 10.3](../training/10-cluster-et-proxy/03-topologie.md).

---

[Relais →](./relais.md)
