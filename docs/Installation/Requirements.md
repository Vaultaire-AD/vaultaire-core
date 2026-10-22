# Prérequis

## Systèmes d'exploitation

Vaultaire est un produit **Linux**. L'agent installe des modules PAM et NSS
écrits en C, chargés par `sshd` et par la libc : il n'existe pas d'équivalent
portable sur les autres systèmes.

| | |
| --- | --- |
| **Serveur central** | Debian 11+, Ubuntu 20.04+, Rocky/CentOS/RHEL 8+ |
| **Agent client** | voir [ci-dessous](#systèmes-pris-en-charge-pour-lagent) |
| **Windows / macOS** | non supportés, ni prévus |

### Systèmes pris en charge pour l'agent

Un système est **pris en charge** quand l'installation (`vlt create -c … -join`),
les GPO machine et de compte et la connexion SSH d'un compte de l'annuaire y ont
passé une recette complète. Liste arrêtée le 22/10/2026 :

| Système | Script | Modules |
| --- | --- | --- |
| **Debian 13** | `debian.sh` | `debian/` |
| **Rocky Linux 9** | `rocky.sh` | `rocky/` |
| **Rocky Linux 10** | `rocky.sh` | `rocky/` |

Les scripts acceptent aussi **Debian 12** et **Ubuntu 22.04 / 24.04** (même
famille de modules que Debian 13), mais ils n'ont pas passé de recette : à
essayer sur une machine qu'on peut perdre, `A_TESTER.md` § 70 en main. Toute
autre distribution est refusée par `-join`, qui nomme celles qu'il connaît.

La politique SELinux de l'agent vise les distributions RHEL — voir
[`../exploitation/selinux.md`](../exploitation/selinux.md) ; elle ne compile pas
encore sur le poste de recette (TO-DO 212).

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
