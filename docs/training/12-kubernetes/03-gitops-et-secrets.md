[⌂ Formation](../README.md) › [Chapitre 12](./README.md) › Jalon 12.3

# Jalon 12.3 — GitOps et secrets

[← Jalon 12.2](./02-installer-avec-helm.md) · [Sommaire du chapitre](./README.md)

---

## Objectif

Confier le déploiement à un outil GitOps : tout ce qui décrit l'installation vit
dans un dépôt Git, **sauf** les secrets, qui viennent d'un gestionnaire de
secrets. Changer une valeur, c'est faire un commit.

## Étapes

1. **Le dépôt GitOps** — une arborescence par environnement :

   ```
   clusters/lab/vaultaire/
   ├── values.yaml                 # copié de deployments/k8s/examples/values-production.yaml, adapté
   └── manifests/
       └── externalsecret.yaml     # deployments/k8s/gitops/secrets/externalsecret.yaml
   ```

   Relisez `values.yaml` : aucun mot de passe, aucune clé. Il peut être lu par
   toute l'équipe.

2. **Les secrets hors du dépôt** — au choix :

   - **External Secrets Operator** : le Secret `vaultaire-secrets` est tiré de
     Vault, d'un coffre cloud ou de 1Password
     ([`externalsecret.yaml`](../../../deployments/k8s/gitops/secrets/externalsecret.yaml)) ;
   - **SOPS** : le Secret est versionné **chiffré**
     ([`sops-secret.example.yaml`](../../../deployments/k8s/gitops/secrets/sops-secret.example.yaml)) ;
   - à défaut, pour le labo : le `kubectl create secret` du jalon 12.2.

   Quel que soit le moyen, il doit porter `db-password`, `admin-password` et,
   avec la base embarquée, `db-root-password`.

3. **Argo CD** :

   ```bash
   kubectl apply -f deployments/k8s/gitops/argocd/application.yaml   # après y avoir mis l'URL de votre dépôt
   argocd app get vaultaire
   ```

   **ou Flux** — qui vérifie en plus la signature cosign de la chart avant de
   l'installer :

   ```bash
   kubectl apply -f deployments/k8s/gitops/flux/helmrelease.yaml
   flux get helmreleases -n vaultaire
   ```

4. **Un changement par commit** — passez `config.ldap.mfaBypass` à `true` dans
   `values.yaml`, commitez, poussez. L'outil GitOps rend la ConfigMap ; son
   empreinte change (`checksum/config`), et le core redémarre avec la nouvelle
   configuration. Remettez `false` de la même façon.

5. **Une mise à jour** — changez `targetRevision` (Argo CD) ou la contrainte
   `semver` (Flux) vers la version suivante. Le core migre le schéma de la base
   à son démarrage : sauvegardez-la avant (`mariadb-dump`).

## ✅ Vous avez réussi si

- l'application est `Synced` / `Healthy` (Argo CD) ou `Ready` (Flux) ;
- `git grep -i password clusters/` ne trouve aucune valeur, seulement des noms
  de clés ;
- un commit sur `values.yaml` redémarre le core sans aucune commande `kubectl`.

## 🧪 Exercice — l'empreinte et non le tag

Pourquoi la chart publiée par la CI désigne-t-elle l'image par
`image.digest` (`sha256:…`) plutôt que par son tag `2.3.0` ?

<details><summary>Solution</summary>

Un tag peut être republié : `2.3.0` désignerait alors une autre image, sans que
rien ne change dans le dépôt GitOps — ni commit, ni différence, ni revue.
L'empreinte désigne un contenu : c'est exactement l'image que cosign a vérifiée
et que Trivy a scannée avant publication. C'est aussi ce que demande une
politique d'admission (Kyverno, Sigstore policy-controller) qui n'autorise que
des images signées.
</details>

## 📚 Référence

[`docs/Installation/Kubernetes.md` § GitOps](../../Installation/Kubernetes.md) ·
[`deployments/k8s/gitops/`](../../../deployments/k8s/gitops/)

---

[← Jalon 12.2](./02-installer-avec-helm.md) · [Sommaire du chapitre](./README.md)
