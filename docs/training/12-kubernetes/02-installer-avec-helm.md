[⌂ Formation](../README.md) › [Chapitre 12](./README.md) › Jalon 12.2

# Jalon 12.2 — Installer dans Kubernetes avec Helm

[← Jalon 12.1](./01-image-rootless.md) · [Sommaire du chapitre](./README.md) · [Jalon suivant : 12.3 →](./03-gitops-et-secrets.md)

---

## Objectif

Déployer le core et sa base dans un namespace soumis au profil **restricted**,
l'exposer hors du cluster, puis y intégrer `web01` et s'y connecter.

## Étapes

1. **Le namespace, au plus strict** — un pod qui demanderait root, une capacité
   ou une élévation de privilège y serait refusé :

   ```bash
   kubectl create namespace vaultaire
   kubectl label ns vaultaire \
     pod-security.kubernetes.io/enforce=restricted \
     pod-security.kubernetes.io/warn=restricted
   ```

2. **Le Secret** — créé à part, jamais dans les valeurs :

   ```bash
   kubectl -n vaultaire create secret generic vaultaire-secrets \
     --from-literal=db-password="$(openssl rand -base64 24)" \
     --from-literal=db-root-password="$(openssl rand -base64 24)" \
     --from-literal=admin-password='Lune-Orange-Velo-42!'
   ```

3. **La chart** :

   ```bash
   helm install vaultaire oci://ghcr.io/vaultaire-ad/charts/vaultaire --version 2.3.0 \
     -n vaultaire --set auth.existingSecret=vaultaire-secrets \
     --set service.type=LoadBalancer \
     --set 'config.ldap.tlsDnsNames={ldap.acme.lan}'
   kubectl -n vaultaire get pods,svc,pvc
   kubectl -n vaultaire logs -f statefulset/vaultaire
   ```

   Sur k3s, le `LoadBalancer` est servi par l'adresse du nœud (`<IP-k8s>`).
   Le pod `vaultaire-0` attend la base (conteneur d'initialisation
   `attente-base`), puis démarre.

4. **Administrer** :

   ```bash
   alias vlt='kubectl -n vaultaire exec -i vaultaire-0 -c core -- /opt/vaultaire/bin/vaultaire_cli'
   vlt version
   vlt cluster expose vaultaire-0 <IP-k8s> 6666     # l'adresse que recevront les agents
   ```

   Recréez l'annuaire du fil rouge (chapitre 2), le compte de service et sa
   permission (jalon 8.1), et la permission de connexion d'`Infra` (jalon 5.3).

5. **L'annuaire, par le Service** :

   ```bash
   LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://<IP-k8s>:636 \
     -D "uid=svc_keycloak,dc=svc,dc=acme,dc=lan" -W \
     -b dc=acme,dc=lan "(objectClass=inetOrgPerson)" uid
   echo | openssl s_client -connect <IP-k8s>:636 2>/dev/null | openssl x509 -noout -ext subjectAltName
   ```

   Le certificat couvre `ldap.acme.lan` (déclaré) et les noms du Service
   (`vaultaire.vaultaire.svc…`, ajoutés par la chart).

6. **Intégrer `web01`** — comme au jalon 5.2, mais la clé du core se lit sur le
   **portail** (`https://<IP-k8s>/`, tableau de bord, section « Client -join », bouton « Copier ») :
   l'image n'a pas de `ssh-keyscan` et n'en a plus besoin, le core parle SSH
   lui-même.

   ```bash
   # sur web01, en root : la clé copiée depuis le portail
   echo 'ssh-rsa AAAA…' >> /root/.ssh/authorized_keys
   # sur votre poste
   vlt create -c oui -join <IP-web01> root
   vlt add -c <computeur_id> -g Infra
   ```

   Puis connectez-vous à `web01` avec `alice.martin@acme.lan` (clé, mot de passe,
   code), comme au jalon 5.3.

## ✅ Vous avez réussi si

- `kubectl -n vaultaire get pods` montre `vaultaire-0` et `vaultaire-mariadb-0`
  en `Running`, **sans** avertissement « violates PodSecurity » ;
- `vlt get -c` montre `web01` avec la version de l'agent embarqué dans l'image ;
- la connexion SSH d'Alice sur `web01` aboutit.

## 🧪 Exercice — la base n'est qu'au core

Lancez un pod quelconque dans le namespace et essayez de joindre la base.
Pourquoi échoue-t-il, alors que le core y arrive ?

<details><summary>Solution</summary>

```bash
kubectl -n vaultaire run essai --rm -i --restart=Never \
  --image=ghcr.io/vaultaire-ad/vaultaire-server:2.3.0 \
  --overrides='{"spec":{"containers":[{"name":"essai","image":"ghcr.io/vaultaire-ad/vaultaire-server:2.3.0","command":["/opt/vaultaire/bin/vaultaire_serveur","--attendre-base","8"],"env":[{"name":"VAULTAIRE_DB_HOST","value":"vaultaire-mariadb"}],"securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}}]}}'
```

« base injoignable après 8 s ». La chart pose une `NetworkPolicy` sur MariaDB :
seuls les pods étiquetés `app.kubernetes.io/component: core` de la release y
entrent. Il faut un CNI qui applique les NetworkPolicy (k3s en embarque un ;
sans, la politique est acceptée mais sans effet).
</details>

## 🧪 Exercice — redémarrer sans perdre le parc

Supprimez le pod du core (`kubectl -n vaultaire delete pod vaultaire-0`). Que
deviennent la machine `web01` et la session d'Alice ?

<details><summary>Solution</summary>

Le StatefulSet recrée `vaultaire-0` sous le **même nom** — c'est le nom du nœud
dans le cluster de cores — et sur le **même volume** (`data-vaultaire-0`).
L'agent de `web01` perd sa session Ducky, la rouvre à la même adresse dès que le
core est prêt, et la connexion SSH suivante d'Alice aboutit. Une session SSH
déjà ouverte n'est pas coupée : elle ne dépend pas du core.
</details>

## 📚 Référence

[`docs/Installation/Kubernetes.md` § 2](../../Installation/Kubernetes.md) ·
[`values.yaml`](../../../deployments/k8s/helm/vaultaire/values.yaml)

---

[← Jalon 12.1](./01-image-rootless.md) · [Sommaire du chapitre](./README.md) · [Jalon suivant : 12.3 →](./03-gitops-et-secrets.md)
