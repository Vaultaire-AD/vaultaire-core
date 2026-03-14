# vaultaire_proxy

Layer 7 Load Balancer pour les protocoles **LDAP** et **Ducky-Network** dans l’infrastructure VaultAire.

## Prérequis

- Un **Core** VaultAire accessible sur le ducky-network.
- Une identité **proxy** créée sur le Core (logiciel enregistré avec clé publique), utilisée pour l’auth 01_01/01_02.

## Usage

```bash
# Avec config par défaut (/opt/vaultaire_proxy/config.yaml)
./vaultaire_proxy --add-host

# Fichier de config et override Core
./vaultaire_proxy --config=./config.yaml --core=10.0.0.1:6666 --add-host
```

- **`--add-host`** : enregistre le proxy comme Host sur le Core (table `cluster_nodes` + création du groupe/domaine si besoin). À utiliser au démarrage.
- **`--core`** : override l’adresse du Core (host:port).
- **`--config`** : chemin vers le fichier YAML de configuration.

## Configuration

Voir `config.example.yaml`. Champs principaux :

- **core_address** : host:port du Core (ducky).
- **identity** : `computeur_id`, `private_key_pem`, `server_pub_key` (ou chemins fichiers).
- **proxy** : `hostname`, `fqdn`, `domain`, `role` pour l’enregistrement cluster.

## Protocole (trames 04_xx)

- **04_01** (register_host) : enregistrement dans `cluster_nodes` + création groupe/domaine.
- **04_03** / **04_04** : liste des Cores en ligne (service discovery).
- **04_05** / **04_06** : envoi des métriques vers le Core (table `proxy_metrics`).
- **04_07** / **04_08** : heartbeat pour rester « online » dans le cluster.

Toute la communication inter-services passe par le **ducky-network** (handshake 01_01/01_02 puis trames 04_xx).

## Structure

- **ducky/** : client ducky (connexion, 01_01/01_02, 04_01/04_03/04_07).
- **balancer/** : liste des Cores, sélection round-robin (extensible par charge/stress).
- **config/** : chargement de la config YAML.

Les listeners LDAP et Ducky (écoute et renvoi vers un Core choisi par le balancer) sont à brancher dans `main.go`.
