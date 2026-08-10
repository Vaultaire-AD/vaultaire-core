# Prérequis

## Systèmes d'exploitation

Vaultaire est un produit **Linux**. L'agent installe des modules PAM et NSS
écrits en C, chargés par `sshd` et par la libc : il n'existe pas d'équivalent
portable sur les autres systèmes.

| | |
| --- | --- |
| **Serveur central** | Debian 11+, Ubuntu 20.04+, Rocky/CentOS/RHEL 8+ |
| **Agent client** | idem. Politique SELinux fournie pour les distributions RHEL — voir [`../exploitation/selinux.md`](../exploitation/selinux.md) |
| **Windows / macOS** | non supportés, ni prévus |

Le développement depuis Windows se fait par **WSL** : `auto-compil.sh` compile
sous Linux à partir du dépôt monté.

## Dépendances de compilation

| | |
| --- | --- |
| **Go** | **1.26** pour les sept modules, `toolchain go1.26.5`. Un Go local plus ancien suffit : `GOTOOLCHAIN=auto`, le défaut, télécharge le toolchain réclamé. La CI compile avec 1.26.5 |
| **GCC + `libpam0g-dev`** | modules PAM et NSS de `src/vaultaire_client/pam_module/` |
| **Git** | ≥ 2.30 |

> Il n'y a **pas de Makefile** : la compilation passe par
> [`auto-compil.sh`](../../auto-compil.sh), qui construit les sept modules Go
> puis les modules C.

## Dépendances d'exécution

| | |
| --- | --- |
| **MariaDB** | ≥ 10.6. Fournie par les fichiers Compose, sinon instance accessible |
| **Docker / Docker Compose** | ≥ 24.x, pour les environnements `dev` et `pre-prod` |
| **OpenSSH** | côté client, pour l'authentification par les modules PAM |

## Ressources minimales — serveur central

| | |
| --- | --- |
| CPU | 2 cœurs |
| RAM | 2 Go, 4 Go recommandés |
| Stockage | 2 Go libres, hors journaux et base |

## Ports à ouvrir

| Port | Service |
| --- | --- |
| 6666 | Ducky Network — agents, proxies |
| 4443 | Portail web (HTTPS) |
| 6643 | API REST (HTTPS) |
| 389 / 636 | LDAP / LDAPS |
| 53 | DNS, si `dns_enable` est actif |

Détail dans [`Setup.md`](./Setup.md).
