# vaultaire_proxy

Proxy de service Vaultaire. **Version 1** : présence dans le cluster.

## Ce que fait la v1

Enrôlement au premier démarrage, connexion chiffrée au core, enregistrement dans
le cluster, battement de cœur, sortie propre à l'arrêt, reconnexion et
réenrôlement automatiques. Le proxy est visible dans `vlt cluster list` et passe
hors ligne quand il s'arrête.

La répartition de charge LDAP/Ducky viendra ensuite, sur une base dont on sait
qu'elle tient.

## Ce que le proxy n'écrit pas

Aucune trame. Le protocole vient du dossier `duckynetwork/`, copié depuis
`src/ducky-network-sdk` et partagé avec les autres clients :

```bash
cd src/ducky-network-sdk && ./install.sh ../vaultaire_proxy
```

Relancer cette commande met le protocole à jour — le dossier est entièrement
remplacé. Ne mettez donc jamais de code du proxy dedans.

## Mise en service

```bash
# 1. Sur le core : une clé d'enrôlement typée
vlt enroll create --type vaultaire_proxy --uses 5 --expires 24h

# 2. Sur l'hôte du proxy
install -d -m 0700 /var/lib/vaultaire_proxy/keys
cp config.example.yaml /etc/vaultaire_proxy/config.yaml
$EDITOR /etc/vaultaire_proxy/config.yaml   # core_address, enrollment.key, proxy.endpoint

# 3. Démarrage
vaultaire_proxy --config /etc/vaultaire_proxy/config.yaml
```

Vérification côté core :

```
vlt cluster list      # le proxy doit être « online »
vlt enroll list       # le compteur d'utilisations doit avoir bougé
```

## Options

| Option | Effet |
|--------|-------|
| `--config` | chemin du fichier de configuration |
| `--reset-identity` | efface les clés locales et force un réenrôlement |

`--reset-identity` conserve la clé publique du core : ce n'est pas elle qui est
en cause, et la redemander rouvrirait la fenêtre du `askkey` en clair.

## `key_dir` doit persister

| Fichier | Perte = |
|---------|---------|
| `private_key.pem` | réenrôlement |
| `public_key.pem` | réenrôlement |
| `server_public.pem` | `askkey` en clair au démarrage |
| `identity.json` | réenrôlement |

Un conteneur sans volume se réenrôle à chaque lancement et épuise le quota de la
clé d'enrôlement — jusqu'à rester bloqué dehors. Le `docker-compose.yml` de
`deployments/pre-prod/vlt-proxy/` monte ce volume ; ne le retirez pas.

## Diagnostic

| Symptôme | Cause probable |
|----------|----------------|
| « clé d'enrôlement absente » | `enrollment.key` vide et aucune identité en cache |
| « enrôlement refusé : expired » | clé expirée — `vlt enroll create` |
| « enrôlement refusé : exhausted » | quota épuisé — `--uses 0` pour l'illimité |
| « identité refusée par le core » | proxy supprimé côté core, ou base réinstallée ; `allow_re_enroll: true` ou `--reset-identity` |
| « service inconnu du cluster » | ligne purgée ; le proxy rejoue 04_09 tout seul |
| en ligne dans le cluster alors qu'il est éteint | arrêt sans SIGTERM : la sortie 04_14 n'est pas partie ; il basculera hors ligne en trois minutes |
