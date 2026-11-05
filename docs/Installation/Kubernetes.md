[⌂ Accueil du dépôt](../../README.md) · [Index de la documentation](../README.md) · [Variables d'environnement](./Variables_environnement.md)

# Déployer Vaultaire en production : image rootless et Kubernetes

*(2.3.)* Le core est publié comme une **image conteneur minimale et signée**, et
déployé dans Kubernetes par une **chart Helm** pensée pour le GitOps (Argo CD,
Flux). Ce document dit ce que l'image garantit, comment installer la chart, et
comment brancher les secrets.

| | |
|---|---|
| Image | `ghcr.io/vaultaire-ad/vaultaire-server:<version>` |
| Chart | `oci://ghcr.io/vaultaire-ad/charts/vaultaire` |
| Sources | [`deployments/docker/`](../../deployments/docker/), [`deployments/k8s/`](../../deployments/k8s/) |
| Périmètre | le **core** et sa base ; les agents Linux et les proxies restent installés sur leurs machines |

---

## 1. L'image

Construite depuis les sources par [`deployments/docker/Dockerfile`](../../deployments/docker/Dockerfile),
publiée par la CI à chaque release (`release.yaml`, job « Image et chart »).

| Propriété | Comment |
|---|---|
| **Aucun shell, aucun gestionnaire de paquets** | base `gcr.io/distroless/static-debian12:nonroot` : certificats CA, fuseaux horaires, `/etc/passwd`. Rien d'autre. |
| **Binaires statiques** | core et CLI compilés `CGO_ENABLED=0` ; le core ne lance plus aucun programme externe — l'installation à distance (`-join`) parle SSH elle-même depuis la 2.3. |
| **Non root** | UID/GID **65532**, numériques : `runAsNonRoot` se vérifie sans lire `/etc/passwd`. Le code appartient à root et ne s'écrit pas. |
| **Aucune capacité** | ports au-dessus de 1024 (LDAP **3389**, LDAPS **3636**, DNS **5353/udp**) ; le Service republie 389/636/53. `--cap-drop ALL` sans exception. |
| **Racine en lecture seule** | le core n'écrit que dans `/var/lib/vaultaire` (données), `/var/log/vaultaire` (journaux), `/run/vaultaire` (socket du CLI). |
| **Aucun secret dans l'image** | mots de passe par variable ou par fichier (`VAULTAIRE_*_FILE`) ; aucune clé SSH par défaut sur le compte d'amorçage. |
| **Bases épinglées par empreinte** | les `FROM` portent un `@sha256:` : un tag republié ne change pas l'image. |
| **Chaîne d'approvisionnement** | scan Trivy **avant** publication (échec sur CRITICAL/HIGH corrigeable), provenance SLSA (`mode=max`) et SBOM attachés, signature **cosign sans clé**. |
| **Paquet d'agent embarqué** | binaire de l'agent et modules PAM/NSS des familles Rocky (glibc 2.34) et Debian (glibc 2.35), copiés sur un poste par `vlt create -c … -join`. |

### Vérifier une image avant de la déployer

```bash
IMAGE=ghcr.io/vaultaire-ad/vaultaire-server
cosign verify "$IMAGE:2.3.0" \
  --certificate-identity-regexp '^https://github.com/Vaultaire-AD/vaultaire-core/.github/workflows/release.yaml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Provenance et SBOM
docker buildx imagetools inspect "$IMAGE:2.3.0" --format '{{ json .Provenance }}'
docker buildx imagetools inspect "$IMAGE:2.3.0" --format '{{ json .SBOM }}'
```

En production, déployez par **empreinte** (`image.digest` dans la chart) : la
chart publiée la porte déjà.

### Construire l'image soi-même

```bash
docker build -f deployments/docker/Dockerfile \
  --build-arg VAULTAIRE_VERSION=2.3.0 \
  --build-arg VCS_COMMIT=$(git rev-parse --short HEAD) \
  -t vaultaire-server:2.3.0 .
```

Prévoir ~6 Go de disque pour les étages de compilation (Go, Rocky 9, Ubuntu
22.04), jetés à la fin : l'image finale pèse environ 100 Mo.

---

## 2. La chart Helm

### Prérequis

- Kubernetes ≥ 1.25, une `StorageClass` par défaut (ou `persistence.storageClass`) ;
- un moyen d'exposer des ports **TCP** hors du cluster : agents, proxies et
  applications LDAP sont le plus souvent dehors. `LoadBalancer` (MetalLB,
  cloud) ou `NodePort`. Un Ingress HTTP ne suffit pas : Ducky et LDAP ne sont
  pas du HTTP.

### Installation en trois commandes

```bash
kubectl create namespace vaultaire
kubectl -n vaultaire create secret generic vaultaire-secrets \
  --from-literal=db-password="$(openssl rand -base64 24)" \
  --from-literal=db-root-password="$(openssl rand -base64 24)" \
  --from-literal=admin-password='Un-mot-de-passe-de-12-caracteres'
helm install vaultaire oci://ghcr.io/vaultaire-ad/charts/vaultaire --version 2.3.0 \
  -n vaultaire --set auth.existingSecret=vaultaire-secrets --set service.type=LoadBalancer
```

La chart **refuse de s'installer** sans secret : jamais de mot de passe par
défaut.

### Ce qui est déployé

| Objet | Rôle |
|---|---|
| `StatefulSet` `<release>-vaultaire` | le core. StatefulSet et non Deployment : le nom du pod est le **nom du nœud** dans le cluster de cores, il doit rester stable. |
| `Service` `<release>-vaultaire` | Ducky 6666, LDAP 389, LDAPS 636, portail 443, API 6643 (et DNS 53/udp si activé). `externalTrafficPolicy: Local` : garde l'adresse réelle des clients (limitation des tentatives, journal). |
| `Service` `…-headless` | un nom DNS stable par pod |
| `ConfigMap` `…-config` | `serveur_conf.yaml`, **sans secret** |
| `Secret` | seulement sans `auth.existingSecret` (essai) |
| `NetworkPolicy` | n'ouvre que les ports du core ; la base n'est joignable que par lui ; sorties restreignables (`networkPolicy.restrictEgress`) |
| `PodDisruptionBudget` | à partir de deux répliques |
| `StatefulSet` `…-mariadb` | base embarquée (`mariadb.enabled`, par défaut) — **une** instance, sans réplication |

Sondes : démarrage et disponibilité sur **`/healthz`** (le portail répond et la
base aussi — un core sans base sort du Service), vivacité par le CLI dans le pod
(le socket d'administration répond). `curl -k https://<core>:4443/healthz`.

Le pod : `runAsNonRoot`, UID 65532, `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, seccomp
`RuntimeDefault`, aucun jeton de ServiceAccount monté,
`enableServiceLinks: false`. Il passe le profil **restricted** des Pod Security
Standards : `kubectl label ns vaultaire pod-security.kubernetes.io/enforce=restricted`.

### Les secrets

Le core lit ses secrets dans des **fichiers** montés depuis le Secret
(`VAULTAIRE_DB_PASSWORD_FILE`…), pas dans des variables : ils n'apparaissent ni
dans `kubectl describe pod`, ni dans l'environnement du processus.

| Clé du Secret | Usage |
|---|---|
| `db-password` | compte base du core |
| `admin-password` | compte d'amorçage (provisoire : changé à la première connexion au portail) |
| `db-root-password` | root de la base embarquée (`mariadb.enabled`) |
| `admin-public-key` | facultative : clé SSH du compte d'amorçage, pour `vlt` à distance |

Les noms des clés se changent (`auth.secretKeys`). Le Secret vient de
n'importe où — [External Secrets](../../deployments/k8s/gitops/secrets/externalsecret.yaml),
Sealed Secrets, [SOPS](../../deployments/k8s/gitops/secrets/sops-secret.example.yaml),
Vault Agent — tant qu'il porte ces clés.

### GitOps

Tout `values.yaml` est versionnable : il ne contient aucun secret. La chart
valide ses valeurs (`values.schema.json`) et n'utilise **pas** `lookup` : son
rendu ne dépend que des valeurs, ce qu'Argo CD et Flux exigent.

- **Argo CD** : [`gitops/argocd/application.yaml`](../../deployments/k8s/gitops/argocd/application.yaml)
  — chart OCI + valeurs dans votre dépôt (sources multiples).
- **Flux** : [`gitops/flux/helmrelease.yaml`](../../deployments/k8s/gitops/flux/helmrelease.yaml)
  — `OCIRepository` avec **vérification cosign** avant installation.

Un changement de ConfigMap redémarre le core (annotation `checksum/config`).

### Après l'installation

```bash
# Le CLI parle au core par son socket, dans le pod
kubectl -n vaultaire exec -it vaultaire-0 -- /opt/vaultaire/bin/vaultaire_cli

# Rendre le core joignable des agents, à l'adresse publique du Service
vlt cluster expose vaultaire-0 <adresse-du-LoadBalancer> 6666
```

Puis, comme sur une installation classique : domaines, groupes, comptes
(chapitres 2 à 4 de la formation), postes (`vlt create -c … -join`, chapitre 5)
— la NetworkPolicy doit alors laisser sortir le core en SSH (port 22) vers les
postes.

### LDAP en production

`config.ldap.requireTlsForBind: true` par défaut : un bind avec mot de passe sur
389 est refusé (`strongerAuthRequired`). Les applications se lient en **LDAPS
sur 636**. Déclarez dans `config.ldap.tlsDnsNames` le nom par lequel elles
joignent l'annuaire : les clients Java (Keycloak) exigent un SAN qui correspond.
Le nom du Service (`<release>-vaultaire`, `….svc`, `….svc.cluster.local`) est
ajouté d'office.

### Plusieurs cores

`replicaCount: 2` (ou plus) forme un cluster de cores sur la même base. Deux
conditions :

1. une base **hautement disponible** (`mariadb.enabled: false`, base gérée ou
   opérateur) — la base embarquée n'est pas répliquée ;
2. chaque core **exposé séparément** aux agents (`vlt cluster expose
   vaultaire-<n> <adresse> <port>`) : un agent garde sa session Ducky sur un
   core, et bascule sur un autre quand il tombe. Un Service par pod
   (`statefulset.kubernetes.io/pod-name` en sélecteur) ou un `NodePort` distinct
   par core.

### Mise à jour

```bash
helm upgrade vaultaire oci://ghcr.io/vaultaire-ad/charts/vaultaire --version 2.3.1 \
  -n vaultaire --reuse-values
```

Le schéma de la base est migré par le core à son démarrage. Sauvegardez la
base avant (`mariadb-dump`), comme pour toute mise à jour.

---

## 3. Limites connues de la 2.3.0

- **Image `linux/amd64` seulement** : le paquet d'agent est compilé pour amd64.
- **Windows** : le client Windows reste une démonstration ; l'image ne l'embarque
  pas.
- **Keycloak** n'est pas déployé par la chart : c'est une application cliente
  du LDAPS, à installer avec sa propre chart.
- Les **clés et secrets en base** ne sont pas chiffrés au repos (TO-DO 98) :
  protégez la base et ses sauvegardes.
