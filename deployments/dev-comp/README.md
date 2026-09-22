# dev-comp — tester la version en cours de développement

La préprod installe une **release** GitHub (`docker-update.sh`). Pour tester ce
qui n'est pas encore publié — une branche, des modifications non commitées —,
`dev-comp` **compile le dépôt local** et démarre la même pile avec ces binaires.
C'est ce que faisait la préprod avant les releases automatiques.

```bash
./deployments/dev-comp/dev-comp.sh            # compile, puis (re)démarre
```

| Ce qui est compilé | Où | Monté dans |
|---|---|---|
| serveur + CLI locale | `build/vaultaire_server/` | `vlt-dev-ad:/opt/vaultaire/bin` |
| agent + modules PAM + NSS | `build/vaultaire_client/` | `vlt-dev-ad:/opt/vaultaire/vaultaire_client` (servi par `create -c … -join`) |
| `vaultaire_ctl` (vlt distant) | `build/vaultaire_ctl/` | — à installer sur le poste |
| proxy | `build/vaultaire_proxy/` | `vlt-dev-proxy` (avec `--proxy`) |
| Nexus | `build/vaultaire_nexus/` | — |

`build/` est ignoré par git et **distinct de `cmd/`** : les binaires de la
release installée par la préprod ne sont pas touchés.

---

## Options

| Option | Effet |
|---|---|
| *(aucune)* | compile dans un conteneur Rocky 9, puis `up -d` et redémarrage du core |
| `--version X.Y.Z` | impose la version injectée dans les binaires |
| `--local` | compile sur l'hôte avec `auto-compil.sh` (plus rapide ; hôte Rocky/RHEL 9 seulement, sinon glibc différente) |
| `--no-build` | redémarre sans recompiler |
| `--proxy` | démarre aussi un proxy (relais Ducky) |
| `--down` | arrête la pile, garde la base |
| `--reset` | arrête et **efface** la base, l'identité du proxy et `build/` |
| `--logs` | suit le journal du core |
| `--status` | conteneurs et date de la dernière compilation |

## La version affichée

Sans `--version`, les binaires portent la **prochaine** release de la série :
`VERSION` vaut `2.2` et le plus grand tag local est `v2.2.3`, donc `2.2.4`, suivi
du commit — `2.2.4+g1a2b3c4-dirty (2026-09-22)`. `-dirty` signale des
modifications non commitées. Un binaire de dev-comp se reconnaît ainsi dans
`vlt version` et `vlt cluster list`. (Lancez `git fetch --tags` pour que le
calcul voie les dernières releases.)

## La compilation

Dans un conteneur `rockylinux:9` (`Dockerfile.build`) avec la recette de la CI de
release : gcc, `pam-devel`, `libcurl-devel`, `libxcrypt-devel`, Go épinglé
(`GO_VERSION`, 1.26.5). Le serveur (cgo) et les modules PAM sont ainsi liés à la
glibc de Rocky 9, celle de l'image d'exécution et du parc. Le cache Go vit dans
le volume `devcomp_gocache` : seule la première compilation est longue.

La sortie est rendue à votre utilisateur (`chown` en fin de compilation).

## La pile

| Conteneur | Rôle | Ports publiés (défaut) |
|---|---|---|
| `vlt-dev-db` | MariaDB (volume `devcomp_db`) | 3307 |
| `vlt-dev-ad` | core — **même image** que la préprod | 6666, 4443, 6643, 389, 636 |
| `vlt-dev-proxy` | proxy, avec `--proxy` | 6667 → relais Ducky |

Les ports se changent dans `.env` (copier `.env.example`). Les valeurs par
défaut sont celles de la préprod : ne lancez pas les deux sur la même machine
sans en décaler une. Les templates du portail sont montés depuis le dépôt : une
page modifiée se voit au rechargement, sans recompiler.

## Le proxy

Au premier démarrage, il lui faut une clé d'enrôlement :

```bash
./deployments/dev-comp/dev-comp.sh                          # core d'abord
docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli enroll create --type vaultaire_proxy
echo 'DEVCOMP_PROXY_ENROLL_KEY=VLT-ENR-…' >> deployments/dev-comp/.env
./deployments/dev-comp/dev-comp.sh --no-build --proxy
docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli cluster expose <proxy> <IP-de-l-hôte> 6667
```

Voir [`docs/proxy/`](../../docs/proxy/README.md).
