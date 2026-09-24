# De quoi Vaultaire dépend — `docs/Developement/dependances.roles`

> **Public : développeurs.** Ce que le produit tire de l'extérieur, à quoi
> chaque chose sert, et ce qui se passe quand deux modules ne sont pas d'accord
> sur une version.

---

## 1. La règle

> **Les versions se lisent dans les fichiers. Le « à quoi ça sert » s'écrit à la
> main. Un test refuse que l'un des deux dérive.**

Neuf `go.mod`, deux images de base, des listes de paquets dans les Dockerfiles :
rien ne disait, en un seul endroit, de quoi le produit dépend. Et surtout rien
ne disait **pourquoi**. Savoir qu'on tire `github.com/pkg/sftp` n'apprend rien ;
savoir qu'elle porte `create -c … --join` dit tout de suite si on peut s'en
passer.

Une page tenue entièrement à la main aurait divergé — c'est exactement ce qui
avait produit la liste de modules fausse de `dev.yaml`, qui citait un
`vaultaire_api` inexistant et en oubliait quatre. Une page entièrement générée,
elle, n'aurait eu aucun endroit où expliquer quoi que ce soit.

D'où le partage :

| | Où | Qui l'écrit |
|---|---|---|
| Versions, modules qui les tirent, images, paquets | le tableau ci-dessous | `automatisation/dependances.sh` |
| À quoi chaque dépendance sert | [`dependances.roles`](../dependances.roles) | vous |

## 2. Régénérer

```bash
./automatisation/dependances.sh
```

Le reste du temps, `go test` s'en charge : le paquet `core/dependances` échoue
quand la page ne décrit plus le dépôt, quand une dépendance arrive sans
explication, quand une explication survit à la dépendance qu'elle décrivait, ou
quand deux modules divergent sans raison écrite.

C'est le même arbitrage qu'au point 75 : **un contrôle qui ne peut pas dire non
ne contrôle rien.** Un rapport qu'on lance à la main finit par ne plus être
lancé.

## 3. Les divergences de version

Une dépendance tirée en plusieurs versions par plusieurs modules n'est pas
interdite : aligner n'est pas toujours possible tout de suite. Elle doit être
**écrite**, avec sa raison, dans `dependances.roles` :

```
!github.com/exemple/truc = pourquoi les versions diffèrent
```

Sans cette ligne, le test échoue. Une divergence qu'on a décidé d'accepter et
une divergence qu'on n'a pas vue se ressemblent beaucoup, et c'est la seule
chose qui les sépare.

> Trois divergences dormaient dans le dépôt au 24/09, dont
> **`golang.org/x/crypto` en trois versions** — la bibliothèque de crypto. Un
> correctif de sécurité appliqué dans un module et pas dans les deux autres
> n'aurait alerté personne. Le **TO-DO 93** les a résolues : il n'y a plus
> aucune divergence déclarée. La prochaine qui apparaîtra fera échouer le test
> tant que sa raison n'est pas écrite.

## 4. Ce que l'inventaire ne garantit pas

Un `go.mod` est une source de vérité : c'est le fichier que l'outil de
construction lit. Une ligne `dnf install` est du **shell** — elle peut venir
d'une variable, d'une boucle, d'un script appelé. Le tableau des paquets système
relève donc ce qui est écrit en clair dans les Dockerfiles, et rien de plus.

Mieux vaut un inventaire honnête sur ses limites qu'un inventaire qui se croit
complet.

---

## 5. L'inventaire

<!-- INVENTAIRE:DEBUT — produit par automatisation/dependances.sh, ne pas éditer à la main -->

### Bibliothèques Go — 13

| Dépendance | Version | Lien | À quoi elle sert |
|---|---|---|---|
| `filippo.io/edwards25519` | v1.1.0 | indirecte | indirecte, tirée par go-sql-driver/mysql pour l'authentification caching_sha2_password. Jamais importée par nous. |
| `github.com/fatih/color` | v1.18.0 | directe | la couleur des tableaux de « vlt », et surtout la détection d'un terminal : la sortie redirigée dans un fichier ne doit pas porter de codes d'échappement. |
| `github.com/go-asn1-ber/asn1-ber` | v1.5.8 | directe | l'encodage BER/DER des messages LDAP. Le core l'emploie pour servir LDAP, Nexus pour interroger un annuaire — sans passer par go-ldap, dont ni l'un ni l'autre n'a besoin. Le core était épinglé sur un commit antérieur à v1.5.8 : c'était l'exigence de go-ldap v3.4.12, et l'épinglage est parti avec elle (TO-DO 93). |
| `github.com/go-sql-driver/mysql` | v1.8.1 | directe | le pilote MySQL/MariaDB, importé pour son seul effet d'enregistrement (« _ »). Toute la base du core passe par lui. |
| `github.com/klauspost/compress` | v1.20.0 | directe | la décompression zstd des paquets Debian, que Nexus doit ouvrir pour en lire les métadonnées. |
| `github.com/kr/fs` | v0.1.0 | indirecte | indirecte, tirée par pkg/sftp pour parcourir une arborescence distante. |
| `github.com/mattn/go-colorable` | v0.1.13 | indirecte | indirecte, tirée par fatih/color pour la console Windows. |
| `github.com/mattn/go-isatty` | v0.0.20 | indirecte | indirecte, tirée par fatih/color : c'est elle qui sait si la sortie est un terminal. |
| `github.com/pkg/sftp` | v1.13.10 | directe | le dépôt de l'agent et de sa configuration sur une machine distante par « create -c … --join ». C'est le seul chemin qui écrit sur une machine qui n'a pas encore d'agent. |
| `github.com/ulikunitz/xz` | v0.5.16 | directe | la décompression xz, pour la même raison : un .deb est en xz ou en zstd selon son âge. |
| `golang.org/x/crypto` | v0.54.0 | directe | argon2id pour les empreintes de mot de passe (core/global/security), ed25519 pour les clés de machine et de core, et le client SSH de « create -c … -join ». Elle a été explicitement remontée en dépendance DIRECTE au passage à argon2id : elle était tirée par go-ldap et sftp, et l'aurait suivie si l'un des deux disparaissait — go-ldap est partie (TO-DO 93), elle est restée. Une seule version dans tout le dépôt depuis le TO-DO 93 : c'est la bibliothèque qui porte la cryptographie, un correctif doit protéger tous les modules à la fois. |
| `golang.org/x/sys` | v0.47.0 | directe | les API Windows de l'agent : netapi32 pour les comptes locaux, wtsapi32 pour les sessions, le registre, et l'enveloppe de service. Pas d'équivalent en bibliothèque standard. Ailleurs, indirecte, tirée par x/crypto et le socle Ducky. |
| `gopkg.in/yaml.v3` | v3.0.1 | directe | la lecture et l'écriture des fichiers de configuration du core, de l'agent, du proxy, du Nexus et du socle Ducky. Une seule version depuis le TO-DO 93 : v2 n'est plus maintenue, et deux bibliothèques pour le même format faisaient diverger le core et l'agent sur un même fichier (clés en double, indentation). |

### Images de base

| Image | Dockerfiles | À quoi elle sert |
|---|---|---|
| `debian:12-slim` | `deployments/dev-comp/Dockerfile.nexus`, `deployments/pre-prod/vlt-proxy/Dockerfile` | l'image de l'environnement de compilation croisée et des essais Debian, pour vérifier que l'agent ne suppose pas une Rocky. |
| `rockylinux:9` | `deployments/dev-comp/Dockerfile.build`, `deployments/dev/Dockerfile.rocky-ssh`, `deployments/dev/dockerfile`, `deployments/pre-prod/Dockerfile` | l'image des conteneurs de production et de préproduction. Choisie pour coller à la distribution du parc visé : ce que l'image contient est ce que l'agent trouvera sur une vraie machine. |

### Paquets système installés dans les images

Relevé dans les commandes d'installation écrites en clair. Un `go.mod` est lu par l'outil qui construit ; une ligne `dnf install` est du shell, et ce tableau ne prétend donc pas à l'exhaustivité.

| Dockerfile | Paquets |
|---|---|
| `deployments/dev-comp/Dockerfile.build` | `findutils`, `gcc`, `git`, `gzip`, `libcurl-devel`, `libxcrypt-devel`, `pam-devel`, `tar`, `which` |
| `deployments/dev-comp/Dockerfile.nexus` | `ca-certificates`, `curl`, `gnupg`, `tzdata` |
| `deployments/dev/Dockerfile.rocky-ssh` | `epel-release`, `gcc`, `libcurl-devel`, `make`, `openssh-clients`, `openssh-server`, `pam-devel`, `pamtester`, `passwd` |
| `deployments/dev/dockerfile` | `ca-certificates`, `git`, `gzip`, `openssh-clients`, `openssh-server`, `sudo`, `tar` |
| `deployments/pre-prod/Dockerfile` | `openssh-clients`, `openssh-server`, `sudo` |
| `deployments/pre-prod/vlt-proxy/Dockerfile` | `ca-certificates`, `tzdata`, `util-linux` |

### Modules internes

Nos propres modules, liés par `replace` vers un chemin local. Ils ne se mettent pas à jour et ne sont pas des dépendances à suivre.

- `duckynetworkclient/V1`
- `vaultaire_client`

<!-- INVENTAIRE:FIN -->

---

## Voir aussi

| | |
|---|---|
| Lancer les tests | [`Tests.md`](./Tests.md) |
| Les étapes d'une tâche | [`Pense-bete_developpement.md`](./Pense-bete_developpement.md) |
| Ce que fait l'intégration continue | [`Tests.md`](./Tests.md) § intégration continue |
