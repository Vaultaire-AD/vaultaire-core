[⌂ Formation](../README.md) › Chapitre 12

# Chapitre 12 — Vaultaire en production : image rootless et Kubernetes

[← Chapitre 11 — Nexus](../11-nexus/README.md) · [Sommaire de la formation ⌂](../README.md)

---

Faire tourner le core comme en production : l'**image publiée**, sans root ni
shell, en lecture seule ; puis le déployer dans **Kubernetes** avec la chart
Helm, ses secrets tenus hors du dépôt, et le confier à un outil **GitOps**.

Les chapitres précédents utilisaient la pile de préproduction (`docker compose`,
binaires montés, compte root, clé de démonstration). Ici, rien de tout cela.

## Prérequis

- chapitres [1](../01-installation-serveur/README.md) à
  [5](../05-ajouter-un-client/README.md) et [8](../08-ldap-et-liaison/README.md)
  faits au moins une fois : vous savez créer un domaine, un compte, intégrer une
  machine et interroger l'annuaire ;
- un hôte avec Docker (12.1) ;
- un cluster Kubernetes ≥ 1.25 (12.2, 12.3). Pour un labo, **k3s** sur une VM de
  4 Go de RAM suffit :
  `curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik" sh -` ;
- `helm` ≥ 3.14, `kubectl`, et `cosign` pour vérifier les signatures.

## Le laboratoire

| Élément | Rôle |
|---|---|
| Hôte Docker | le core en conteneur rootless (12.1) |
| Cluster k3s `<IP-k8s>` | le core et sa base, par la chart (12.2) |
| `web01` (Rocky 9) | intégrée au core du cluster (12.2) |

## Jalons

| # | Jalon | Fait |
|---|---|---|
| 12.1 | [L'image rootless : vérifier, lancer, interroger](./01-image-rootless.md) | ☐ |
| 12.2 | [Installer dans Kubernetes avec Helm](./02-installer-avec-helm.md) | ☐ |
| 12.3 | [GitOps et secrets](./03-gitops-et-secrets.md) | ☐ |

## Référence

[`docs/Installation/Kubernetes.md`](../../Installation/Kubernetes.md) ·
[`docs/Installation/Variables_environnement.md`](../../Installation/Variables_environnement.md) ·
[`deployments/k8s/`](../../../deployments/k8s/)
