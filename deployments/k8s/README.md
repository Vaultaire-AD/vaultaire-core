# Déploiement Kubernetes

| Chemin | Contenu |
|---|---|
| [`helm/vaultaire/`](./helm/vaultaire/) | la chart (publiée en OCI : `oci://ghcr.io/vaultaire-ad/charts/vaultaire`) |
| [`examples/`](./examples/) | valeurs d'essai et de production |
| [`gitops/argocd/`](./gitops/argocd/) | `Application` Argo CD (chart OCI + valeurs de votre dépôt) |
| [`gitops/flux/`](./gitops/flux/) | `OCIRepository` vérifié par cosign + `HelmRelease` |
| [`gitops/secrets/`](./gitops/secrets/) | le Secret par External Secrets, ou chiffré par SOPS |

```bash
kubectl create namespace vaultaire
kubectl -n vaultaire create secret generic vaultaire-secrets \
  --from-literal=db-password="$(openssl rand -base64 24)" \
  --from-literal=db-root-password="$(openssl rand -base64 24)" \
  --from-literal=admin-password='Un-mot-de-passe-de-12-caracteres'
helm install vaultaire oci://ghcr.io/vaultaire-ad/charts/vaultaire --version 2.3.0 \
  -n vaultaire -f examples/values-quickstart.yaml

# Depuis le dépôt, sans registre :
helm install vaultaire ./helm/vaultaire -n vaultaire -f examples/values-quickstart.yaml
```

Documentation : [`docs/Installation/Kubernetes.md`](../../docs/Installation/Kubernetes.md).
Formation : [chapitre 12](../../docs/training/12-kubernetes/README.md).
