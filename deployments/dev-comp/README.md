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
| Nexus | `build/vaultaire_nexus/` | `vlt-dev-nexus` (avec `--nexus`) |

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
| `--nexus` | démarre aussi un Nexus (dépôt de paquets) |
| `--down` | arrête la pile, garde la base |
| `--reset` | arrête et **efface** la base, l'identité du proxy, les données Nexus et `build/` |
| `--logs` | suit le journal du core |
| `--status` | conteneurs et date de la dernière compilation |
| `--add-proxy [nom]` | **un proxy de plus**, sur une pile déjà démarrée — clé d'enrôlement créée toute seule |
| `--add-core [nom]` | **un core de plus**, sur la même base |
| `--noeuds` | liste les nœuds ajoutés après coup |
| `--rm-noeud <nom>` | retire un nœud ajouté : son conteneur, et son identité enrôlée s'il en a une |

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
| `vlt-dev-nexus` | Nexus, avec `--nexus` | 8843 |

### Les images sont toujours construites

À chaque lancement, les **trois** images (core, proxy, Nexus) sont
(re)construites, que leurs conteneurs démarrent ou non. Une image qu'on ne
construit qu'au moment d'en avoir besoin casse au pire moment, et on ne sait
plus alors si c'est le `Dockerfile` ou le binaire du jour. Aucune ne contient de
binaire — tout est monté — donc la construction est courte et le cache Docker
fait le reste.

L'image du Nexus (`Dockerfile.nexus`) est **propre à dev-comp** : celle de
`src/vaultaire_nexus/deploy/` recompile le Nexus depuis Docker Hub, ce qui ne
testerait pas le binaire du dépôt. Ici le binaire est monté, comme pour le core
et le proxy.

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

## Agrandir la pile sans la relancer

`--proxy` et `--nexus` démarrent les conteneurs déclarés dans le compose : un
proxy, un Nexus, pas deux. Pour éprouver un cluster — plusieurs relais, un
second core — il fallait jusqu'ici éditer le compose, donc commiter un fichier
versionné pour un besoin qui dure dix minutes.

`--add-proxy` et `--add-core` ajoutent un nœud à la pile **déjà démarrée**, par
un `docker run` sur son réseau. Ces conteneurs portent l'étiquette Docker
`vaultaire.devcomp=1`, et c'est elle qui sert de registre : `--down`, `--reset`,
`--status` et `--noeuds` les retrouvent sans qu'aucune liste soit tenue à jour
quelque part, donc sans qu'elle puisse mentir après un `docker rm` fait à la
main. Une réserve : `--noeuds` ne liste que des **conteneurs**, et un `docker
rm` manuel laisse derrière lui un volume d'identité que seul `--reset` reprend.

`--rm-noeud` ne touche **que** les conteneurs qui portent cette étiquette : les
conteneurs de la pile de base (`vlt-dev-ad`, `vlt-dev-db`, `vlt-dev-proxy`,
`vlt-dev-nexus`) ne se retirent pas ainsi. Les noms correspondants sont
d'ailleurs refusés à la création.

```bash
./deployments/dev-comp/dev-comp.sh              # la pile de base
./deployments/dev-comp/dev-comp.sh --add-proxy  # proxy2, port 6668
./deployments/dev-comp/dev-comp.sh --add-proxy lyon
./deployments/dev-comp/dev-comp.sh --add-core   # core2, portail sur 4453
./deployments/dev-comp/dev-comp.sh --noeuds
./deployments/dev-comp/dev-comp.sh --rm-noeud lyon
```

### Ce que fait `--add-proxy`

La clé d'enrôlement est créée à la demande, **pour ce proxy seul** (`--uses 1`),
et posée dans son environnement. C'était l'essentiel de la corvée : la créer à
la main, la recopier dans `.env`, relancer. Une clé par proxy n'est pas un détail
— `enroll show <id>` liste les services entrés avec une clé, et cette trace ne
vaut que si la clé n'a servi qu'une fois.

Chaque proxy reçoit son propre volume d'identité, `devcomp_keys_<nom>`. Tant
qu'il **porte une identité**, le proxy se rattache sans rien réenrôler — et le
script n'émet alors **aucune** clé, une clé non consommée restant valide
vingt-quatre heures.

La nuance a son importance : c'est le fichier d'identité qui est contrôlé, pas
l'existence du volume. Un volume vide — laissé par un démarrage qui a échoué —
donnerait sinon un proxy privé de clé, qui s'arrête aussitôt et que
`--restart unless-stopped` fait boucler, pendant que le script annonce un
démarrage réussi.

Un nom retiré par `--rm-noeud` ne se reprend pas tout de suite : le conteneur et
le volume partent, mais la ligne du nœud reste dans `cluster_nodes` jusqu'à la
purge (`vlt cluster purge-delay`, 24 h par défaut). Un nœud recréé sous ce nom
avec une identité neuve se voit refuser l'enregistrement — il tourne, sans
jamais apparaître dans `cluster list`.

La clé reste lisible dans `docker inspect` tant que le conteneur existe. C'est
du même registre que le mot de passe de la base dans le compose : une pile de
développement, des valeurs visibles que personne ne peut prendre pour un secret.
À ne pas recopier en préprod.

Le port publié n'est pas celui que le proxy annonce (il écoute 6666 *dans* le
conteneur). Des agents ne le joindront qu'après :

```bash
docker exec vlt-dev-ad /opt/vaultaire/bin/vaultaire_cli cluster expose proxy2 <IP-de-l-hôte> 6668
```

### Ce que fait `--add-core`

**Rien à enrôler, rien à joindre.** Il n'existe aucune procédure de jonction
pour un core — `enroll create` refuse d'ailleurs le type, un core n'étant pas au
catalogue des clients. Un second core est un second processus pointé sur la
**même base** : il s'inscrit seul dans `cluster_nodes` sous `@core:<hostname>`,
et relit en base les clés du premier, donc il porte la **même empreinte**. C'est
cette empreinte identique qui fait que les agents l'acceptent sans rien
réapprendre.

Seuls les ports **publiés** sont décalés ; les ports internes ne bougent pas,
chaque conteneur ayant son adresse sur le réseau.

| Nœud | Ducky | Portail | API | LDAP / LDAPS |
|---|---|---|---|---|
| `vlt-dev-ad` (n° 1) | 6666 | 4443 | 6643 | 389 / 636 |
| `core2` | 6676 | 4453 | 6653 | 1389 / 1636 |
| `core3` | 6686 | 4463 | 6663 | 2389 / 2636 |

Les valeurs de `.env` sont prises en compte : le décalage s'applique à **vos**
ports, pas aux valeurs par défaut. Au-delà de neuf proxies, la suite des proxies
rattrape le Ducky des cores (proxy n° 10 → 6676 = `core2`) : le contrôle de port
l'attrape, mais la table cesse d'être régulière.

> ⚠ **Deux cores sur une même base ne sont pas encore éprouvés** — voir
> `docs/Developement/DO/2.2/2.2.md` et `docs/exploitation/A_TESTER.md` § 21.
> La commande existe justement pour que ce test devienne facile à faire.

### Les noms d'hôte sont figés

`vaultaire-ad` et `proxy1` dans le compose, le nom du nœud pour ceux qu'on
ajoute. Ce n'est pas cosmétique : le nom d'hôte est ce qu'affiche
`vlt cluster list`, ce que prennent `cluster expose | priority | affinity`, et,
pour un core, la moitié de son propriétaire en base. Laissé au hasard il vaut
l'identifiant du conteneur — une valeur neuve à chaque recréation, donc un nœud
qui renaît sous une autre identité en abandonnant ses réglages.

## Le Nexus

```bash
./deployments/dev-comp/dev-comp.sh --nexus
docker exec vlt-dev-nexus cat /var/lib/vaultaire_nexus/admin.initial   # mot de passe initial
```

Portail sur <https://localhost:8843/> (certificat auto-signé), compte `admin`.
Configuration : `nexus/config.yaml` — volontairement minimale (mode local, trois
dépôts). L'adresse publique et le mot de passe se règlent dans `.env`
(`DEVCOMP_NEXUS_PUBLIC_URL`, `DEVCOMP_NEXUS_ADMIN_PASSWORD`). L'état vit dans le
volume `devcomp_nexus`, effacé par `--reset`.

Le raccordement au cluster (mode `ducky`) n'est pas câblé ici : il demande une
clé d'enrôlement `vaultaire_nexus` et un `ducky.yaml`, comme en production —
voir [`src/vaultaire_nexus/README.md`](../../src/vaultaire_nexus/README.md).
