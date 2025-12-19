# 📖 Vaultairectl -- Client CLI pour Vaultaire API

`vaultairectl` est un client en ligne de commande (analogue à `kubectl`)
permettant d'interagir avec l'API sécurisée de Vaultaire.\
Il utilise une **authentification par signature de clé privée** : chaque
requête est signée localement et vérifiée par le serveur via la clé
publique enregistrée en base.

------------------------------------------------------------------------

## ⚙️ Installation

1.   :

``` bash

```

2.  **Déplacer le binaire dans ton PATH** :

``` bash
sudo mv vaultairectl /usr/local/bin/
```

------------------------------------------------------------------------

## 📂 Configuration

Par défaut, `vaultairectl` lit sa configuration dans :

    ~/.vaultaire/config.json

Exemple de configuration :

``` json
{
  "server": "https://127.0.0.1:6643",
  "username": "alice",
  "private_key": "/home/alice/.vaultaire/id_rsa"
}
```

-   **server** : URL de l'API Vaultaire (https + port)\
-   **username** : identifiant de l'utilisateur tel qu'enregistré sur le
    serveur\
-   **private_key** : chemin vers la clé privée RSA de l'utilisateur

👉 Pour changer le chemin du fichier de configuration, définir la
variable d'environnement :

``` bash
export VAULTAIRE_CONFIG=/path/to/config.json
```

------------------------------------------------------------------------

## 🚀 Utilisation

### 1. Lister les commandes disponibles (exemple)

``` bash
vaultairectl get -u
```

### 2. Exécuter une commande personnalisée

``` bash
vaultairectl "create_zone example.com"
```

### 3. Exemple de réponse

    ✅ Résultat: Zone 'example.com' créée avec succès

------------------------------------------------------------------------

## 🔐 Sécurité

-   Chaque requête est **signée localement** avec la clé privée RSA.\
-   Le serveur valide la signature avec la clé publique stockée en DB.\
-   Le transport se fait en **HTTPS (TLS)**.\
-   Par défaut, le client ignore la validation TLS (certificat
    autosigné). Pour activer la vérification stricte → modifier le code
    et fournir un certificat valide.

------------------------------------------------------------------------

## 🔄 Contextes (optionnel)

Comme `kubectl`, tu pourras gérer plusieurs environnements (prod, dev,
test) via plusieurs fichiers de config et une commande `switch-context`
(TODO).\
Exemple futur :

``` bash
vaultairectl switch-context dev
vaultairectl switch-context prod
```

------------------------------------------------------------------------

## 🛠️ Débogage

-   Vérifier que le serveur Vaultaire est lancé sur le bon port (`6643`
    par défaut).\
-   Vérifier que l'utilisateur et la clé publique sont bien enregistrés
    côté serveur.\
-   Pour voir la requête brute envoyée : utiliser `curl -v` avec les
    mêmes headers.
