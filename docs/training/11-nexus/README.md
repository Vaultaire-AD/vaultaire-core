[⌂ Formation](../README.md) › Chapitre 11

# Chapitre 11 — Nexus : dépôts et mises à jour du parc

[← Chapitre 10 — Cluster et proxy](../10-cluster-et-proxy/README.md) · [Sommaire de la formation ⌂](../README.md)

---

Déployer **Vaultaire Nexus**, le dépôt de paquets du cluster, y ranger les
paquets du site, s'en servir pour **changer la version d'un agent**, puis le
rendre joignable d'un site distant **par un proxy**.

Nexus sert quatre familles de dépôts — RPM (`dnf`), Debian (`apt`), registre
Docker, releases Vaultaire — et des fichiers génériques. Pour Vaultaire, c'est
surtout **le dépôt du parc** : les agents y prennent les paquets de mise à jour
que votre core a signés.

## Prérequis

- chapitres [1](../01-installation-serveur/README.md) à
  [5](../05-ajouter-un-client/README.md) terminés : la pile tourne, `web01` est
  intégrée et en ligne ;
- le jalon [9.3](../09-securite-et-exploitation/03-reglages-et-mises-a-jour.md)
  lu (cibles de version, clé des paquets) ;
- pour le jalon 11.4, le proxy du [chapitre 10](../10-cluster-et-proxy/README.md) ;
- le dépôt Vaultaire cloné sur l'hôte Docker (Nexus est construit depuis
  `src/`).

## Le laboratoire

| Élément | Adresse | Nouveau dans ce chapitre |
|---|---|---|
| Hôte Docker | `<IP-serveur>` | Nexus (projet compose `vaultaire-nexus`), port **8843** |
| `web01` (Rocky 9) | `<IP-web01>` | lit le dépôt du parc, change de version |
| Proxy `proxy-lab` | `<IP-proxy>` | relais **HTTPS** vers Nexus (11.4) |

## Jalons

| # | Jalon | Fait |
|---|---|---|
| 11.1 | [Déployer et raccorder un Nexus](./01-deployer-et-raccorder.md) | ☐ |
| 11.2 | [Les dépôts : créer, publier, consommer](./02-depots.md) | ☐ |
| 11.3 | [Changer la version d'un agent par Nexus](./03-mettre-a-jour-un-agent.md) | ☐ |
| 11.4 | [Exposer Nexus par un proxy](./04-exposer-par-un-proxy.md) | ☐ |

Chaque jalon suit le même plan : **objectif**, **étapes**, **vous avez réussi
si**, puis un **exercice** avec sa solution repliée.

**Commencer : [Déployer et raccorder un Nexus](./01-deployer-et-raccorder.md)**

---

[← Chapitre 10 — Cluster et proxy](../10-cluster-et-proxy/README.md) · [Sommaire de la formation ⌂](../README.md)
