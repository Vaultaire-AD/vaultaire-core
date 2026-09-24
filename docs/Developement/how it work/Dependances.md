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

> ⚠️ Trois divergences dormaient dans le dépôt au 24/09, dont
> **`golang.org/x/crypto` en trois versions** — la bibliothèque de crypto. Un
> correctif de sécurité appliqué dans un module et pas dans les deux autres
> n'aurait alerté personne. Elles sont déclarées et renvoyées au **TO-DO 93**.

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

### Bibliothèques Go — 17

| Dépendance | Version | Lien | À quoi elle sert |
|---|---|---|---|
| `filippo.io/edwards25519` | v1.1.0 | indirecte | indirecte, tirée par go-sql-driver/mysql pour l'authentification caching_sha2_password. Jamais importée par nous. |
| `github.com/Azure/go-ntlmssp` | v0.0.0-20221128193559-754e69321358 | indirecte | indirecte, tirée par go-ldap pour l'authentification NTLM. Jamais importée par nous, et elle partira avec go-ldap. |
| `github.com/fatih/color` | v1.18.0 | directe | la couleur des tableaux de « vlt », et surtout la détection d'un terminal : la sortie redirigée dans un fichier ne doit pas porter de codes d'échappement. |
| `github.com/go-asn1-ber/asn1-ber` | **≠** v1.5.8<br>**≠** v1.5.8-0.20250403174932-29230038a667 | directe | l'encodage BER/DER des messages LDAP. Le core l'emploie pour servir LDAP, Nexus pour interroger un annuaire — sans passer par go-ldap, dont Nexus n'a besoin ni du NTLM ni du GSSAPI. |
| `github.com/go-ldap/ldap/v3` | v3.4.12 | directe | PLUS IMPORTÉE NULLE PART (constaté le 24/09). Déclarée directe dans vaultaire_serveur, elle n'apparaît dans aucun fichier : elle tire go-ntlmssp, uuid et golang.org/x/crypto pour rien. Retrait à traiter — voir TO-DO 93. |
| `github.com/go-sql-driver/mysql` | v1.8.1 | directe | le pilote MySQL/MariaDB, importé pour son seul effet d'enregistrement (« _ »). Toute la base du core passe par lui. |
| `github.com/google/uuid` | v1.6.0 | indirecte | indirecte, tirée par go-ldap. Jamais importée par nous. |
| `github.com/klauspost/compress` | v1.20.0 | directe | la décompression zstd des paquets Debian, que Nexus doit ouvrir pour en lire les métadonnées. |
| `github.com/kr/fs` | v0.1.0 | indirecte | indirecte, tirée par pkg/sftp pour parcourir une arborescence distante. |
| `github.com/mattn/go-colorable` | v0.1.13 | indirecte | indirecte, tirée par fatih/color pour la console Windows. |
| `github.com/mattn/go-isatty` | v0.0.20 | indirecte | indirecte, tirée par fatih/color : c'est elle qui sait si la sortie est un terminal. |
| `github.com/pkg/sftp` | v1.13.10 | directe | le dépôt de l'agent et de sa configuration sur une machine distante par « create -c … --join ». C'est le seul chemin qui écrit sur une machine qui n'a pas encore d'agent. |
| `github.com/ulikunitz/xz` | v0.5.16 | directe | la décompression xz, pour la même raison : un .deb est en xz ou en zstd selon son âge. |
| `golang.org/x/crypto` | **≠** v0.47.0<br>**≠** v0.52.0<br>**≠** v0.54.0 | directe | argon2id pour les empreintes de mot de passe (core/global/security), ed25519 pour les clés de machine et de core, et le client SSH de « create -c … -join ». Elle a été explicitement remontée en dépendance DIRECTE au passage à argon2id : elle était tirée par go-ldap et sftp, et l'aurait suivie si l'un des deux disparaissait. |
| `golang.org/x/sys` | **≠** v0.40.0<br>**≠** v0.45.0<br>**≠** v0.47.0 | directe | les API Windows de l'agent : netapi32 pour les comptes locaux, wtsapi32 pour les sessions, le registre, et l'enveloppe de service. Pas d'équivalent en bibliothèque standard. |
| `gopkg.in/yaml.v2` | v2.4.0 | directe | la lecture des fichiers de configuration de l'agent, du proxy, du Nexus et du socle Ducky. |
| `gopkg.in/yaml.v3` | v3.0.1 | directe | la même chose côté core. Deux versions de la MÊME bibliothèque cohabitent donc dans le produit — voir TO-DO 93. |

### Versions divergentes

Une dépendance tirée en plusieurs versions. Un correctif appliqué à l'une ne protège pas les autres.

| Dépendance | Versions et modules | Pourquoi c'est accepté |
|---|---|---|
| `github.com/go-asn1-ber/asn1-ber` | `v1.5.8` — vaultaire_nexus<br>`v1.5.8-0.20250403174932-29230038a667` — vaultaire_serveur | le core est épinglé sur un commit (v1.5.8-0.20250403…) et Nexus sur la version publiée v1.5.8. La raison de l'épinglage n'est écrite nulle part ; à retrouver avant d'aligner, voir TO-DO 93. |
| `golang.org/x/crypto` | `v0.47.0` — vaultaire_ctl<br>`v0.52.0` — vaultaire_serveur<br>`v0.54.0` — api_client_package | RELEVÉE LE 24/09, PAS ENCORE RÉSOLUE. Trois versions : v0.47.0 (vaultaire_ctl), v0.52.0 (vaultaire_serveur), v0.54.0 (api_client_package). C'est la divergence la plus gênante du dépôt — un correctif de sécurité appliqué à l'une ne protège pas les autres. Alignement à traiter, voir TO-DO 93. |
| `golang.org/x/sys` | `v0.40.0` — vaultaire_ctl<br>`v0.45.0` — ducky-network-sdk-service, vaultaire_client_windows, vaultaire_serveur<br>`v0.47.0` — api_client_package | suit la précédente : les trois mêmes modules, tirée indirectement par x/crypto. Elle s'alignera d'elle-même quand x/crypto le sera. |

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
