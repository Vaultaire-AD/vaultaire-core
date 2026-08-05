# Déploiement du proxy Vaultaire

Pile autonome, à déployer sur la machine qui portera le proxy — pas
nécessairement celle du core.

## Mise en service

```bash
# 1. Sur le CORE : créer une clé d'enrôlement typée
vlt enroll create --type vaultaire_proxy --uses 5 --expires 24h

# 2. Ici : renseigner la configuration
cp config.example.yaml config.yaml
$EDITOR config.yaml     # core_address, enrollment.key, proxy.endpoint

# 3. Construire et démarrer
docker compose up -d --build

# 4. Vérifier
docker compose logs -f vaultaire-proxy
vlt cluster list        # sur le core : le proxy doit être « online »
```

## L'image

Multi-étages, ~15 Mo à l'arrivée : un binaire statique sur alpine, sans outil de
compilation. Elle **compile** le proxy, contrairement à l'image du serveur qui
monte des binaires depuis `cmd/` — un proxy tourne loin du poste de
développement, une image qui dépend d'un volume de l'hôte n'y est pas
déployable.

Le build rejoue `install.sh` : le binaire est compilé sur la version du
protocole présente dans `src/ducky-network-sdk` au moment du build, et non sur
la copie éventuellement périmée du dépôt.

## Le volume `vaultaire_proxy_keys`

Il porte l'identité du proxy : clé privée, clé publique du core, identifiant
attribué.

**`docker compose down -v` force un réenrôlement** et consomme une place de la
clé d'enrôlement. Répété, il épuise le quota et laisse le proxy dehors — avec un
message qui ne dit pas que la cause est là.

Pour un réenrôlement volontaire, préférez l'option explicite :

```bash
docker compose run --rm vaultaire-proxy --reset-identity --config /etc/vaultaire_proxy/config.yaml
```

Elle conserve la clé publique du core, ce que la suppression du volume ne fait
pas.

## Réseau

Le `docker-compose.yml` suppose par défaut que le core tourne sur la même
machine et rejoint son réseau `pre-prod_Ducky-network`.

Sur une machine distincte — le cas normal —, commentez le bloc `external`,
décommentez `proxy-network`, et donnez à `core_address` l'adresse routable du
core.

## Diagnostic

```bash
docker compose logs -f vaultaire-proxy
docker compose exec vaultaire-proxy ls -l /var/lib/vaultaire_proxy/keys
```

| Message | Cause |
|---------|-------|
| `enrôlement refusé : expired` | clé expirée |
| `enrôlement refusé : exhausted` | quota épuisé — `--uses 0` pour l'illimité |
| `identité refusée par le core` | proxy supprimé côté core, ou base réinstallée |
| `service inconnu du cluster` | ligne purgée ; le proxy rejoue 04_09 seul |
| aucun log | `logs.SetWriter` n'a pas été appelé — anomalie, ouvrir un ticket |
