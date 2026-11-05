[⌂ Formation](../README.md) › [Chapitre 12](./README.md) › Jalon 12.4

# Jalon 12.4 — Des certificats émis par cert-manager

[← Jalon 12.3](./03-gitops-et-secrets.md) · [Sommaire du chapitre](./README.md)

---

## Objectif

Remplacer les certificats auto-signés du LDAPS et du portail par des
certificats émis par **cert-manager**, et voir un renouvellement servi **sans
redémarrer** le core. Les applications clientes font alors confiance à une
autorité, et non plus à l'empreinte d'un certificat qu'il faudrait réimporter.

## Étapes

1. **Installer cert-manager** (une fois par cluster) :

   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml
   kubectl -n cert-manager rollout status deploy/cert-manager-webhook
   ```

2. **Une autorité de laboratoire** — un émetteur auto-signé fabrique une CA,
   un second émetteur signe avec elle :

   ```yaml
   # ca-labo.yaml
   apiVersion: cert-manager.io/v1
   kind: ClusterIssuer
   metadata: { name: selfsigned }
   spec: { selfSigned: {} }
   ---
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata: { name: ca-labo, namespace: cert-manager }
   spec:
     isCA: true
     commonName: CA du labo
     secretName: ca-labo
     privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
     issuerRef: { name: selfsigned, kind: ClusterIssuer }
   ---
   apiVersion: cert-manager.io/v1
   kind: ClusterIssuer
   metadata: { name: ca-labo }
   spec: { ca: { secretName: ca-labo } }
   ```

   ```bash
   kubectl apply -f ca-labo.yaml
   kubectl -n cert-manager get secret ca-labo -o jsonpath='{.data.ca\.crt}' | base64 -d > ca-labo.crt
   ```

3. **Brancher la chart** :

   ```bash
   helm upgrade vaultaire oci://ghcr.io/vaultaire-ad/charts/vaultaire -n vaultaire --reuse-values \
     --set tls.certManager.enabled=true \
     --set tls.certManager.issuerRef.name=ca-labo \
     --set 'tls.certManager.services={ldaps,web}' \
     --set 'config.ldap.tlsIpAddresses={<IP-k8s>}' \
     --set 'config.web.tlsIpAddresses={<IP-k8s>}'
   kubectl -n vaultaire get certificate        # READY True
   ```

4. **Vérifier ce qui est servi**, en faisant confiance à la seule autorité :

   ```bash
   LDAPTLS_CACERT=ca-labo.crt LDAPTLS_REQCERT=demand \
     ldapsearch -x -H ldaps://<IP-k8s>:636 -D "<dn de service>" -W -b dc=acme,dc=lan "(uid=*)" uid
   curl --cacert ca-labo.crt https://<IP-k8s>/healthz
   kubectl -n vaultaire exec vaultaire-0 -- /opt/vaultaire/bin/vaultaire_cli certificate show ldaps | head -8
   ```

5. **Un renouvellement** — forcez-le en changeant la demande (un nom de
   plus), puis regardez le journal du core :

   ```bash
   kubectl -n vaultaire patch certificate vaultaire-ldaps --type merge \
     -p '{"spec":{"dnsNames":["vaultaire","ldap.acme.lan"]}}'
   kubectl -n vaultaire logs vaultaire-0 -f | grep 'certificat rechargé'
   ```

## ✅ Vous avez réussi si

- `ldapsearch` et `curl` passent avec la **seule** autorité du labo, sans
  `LDAPTLS_REQCERT=never` ni `-k` ;
- `certificate show ldaps` dit « IMPORTÉ » et nomme l'émetteur `CA du labo` ;
- après le renouvellement, la ligne `certificat rechargé` apparaît en moins
  d'une minute et demie, et `kubectl get pod vaultaire-0` montre le même pod,
  sans redémarrage (`RESTARTS` inchangé).

## 🧪 Exercice — regenerate

Que répond `vlt certificate regenerate ldaps` maintenant ? Pourquoi ?

<details><summary>Solution</summary>

Il refuse : le certificat servi vient d'un fichier. En régénérer un en base ne
changerait rien à ce que voient les clients, et laisserait croire le contraire.
On le renouvelle à sa source — ici, cert-manager.
</details>

## 🧪 Exercice — une paire cassée

Dans un essai Docker, posez `VAULTAIRE_LDAPS_TLS_CERT_FILE` sans
`VAULTAIRE_LDAPS_TLS_KEY_FILE`. Que fait le core ?

<details><summary>Solution</summary>

Il refuse de démarrer : « certificat déclaré … sans clé ». Démarrer sur
l'auto-signé servirait aux clients un certificat qu'ils ne connaissent pas, et
l'écart ne se verrait qu'à leurs poignées de main refusées.
</details>

## 📚 Référence

[`docs/Installation/Kubernetes.md` § Certificats TLS](../../Installation/Kubernetes.md#certificats-tls--cert-manager-ou-une-pki-to-do-262) ·
[`docs/Installation/Variables_environnement.md` § Certificats importés](../../Installation/Variables_environnement.md)

---

[← Jalon 12.3](./03-gitops-et-secrets.md) · [Sommaire du chapitre](./README.md)
