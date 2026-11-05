[⌂ Formation](../README.md) › [Chapitre 12](./README.md) › Jalon 12.1

# Jalon 12.1 — L'image rootless : vérifier, lancer, interroger

[← Sommaire du chapitre](./README.md) · [Jalon suivant : 12.2 →](./02-installer-avec-helm.md)

---

## Objectif

Vérifier que l'image vient bien de la CI du projet, la lancer avec **toutes**
les protections du moteur de conteneurs, et constater qu'elle ne peut rien
faire d'autre que servir l'annuaire.

## Étapes

1. **Vérifier la signature** — l'image est signée sans clé par le workflow de
   release ; cosign contrôle l'identité du signataire :

   ```bash
   IMAGE=ghcr.io/vaultaire-ad/vaultaire-server:2.3.0
   cosign verify "$IMAGE" \
     --certificate-identity-regexp '^https://github.com/Vaultaire-AD/vaultaire-core/.github/workflows/release.yaml@' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com | head -c 300
   ```

   Une image reconstruite ailleurs, ou republiée par quelqu'un d'autre, échoue
   ici.

2. **Regarder ce qu'elle contient** :

   ```bash
   docker image inspect "$IMAGE" --format 'user={{.Config.User}} ports={{json .Config.ExposedPorts}}'
   docker run --rm --entrypoint /bin/sh "$IMAGE" -c id     # échoue : il n'y a pas de shell
   ```

   `user=65532:65532`, ports 3389/3636/4443/6643/6666 : aucun port sous 1024,
   donc aucune capacité requise.

3. **Une base et des secrets** — les mots de passe vivent dans des fichiers,
   jamais dans la ligne de commande :

   ```bash
   mkdir -p ~/vlt-secrets && cd ~/vlt-secrets
   openssl rand -base64 18 > db-password
   openssl rand -base64 18 > root-password
   echo 'Lune-Orange-Velo-42!' > admin-password
   chmod 644 *          # lisibles par l'UID 65532 du conteneur
   docker network create vlt
   docker run -d --name vlt-db --network vlt -v vlt-db:/var/lib/mysql \
     -e MARIADB_DATABASE=vaultaire -e MARIADB_USER=vaultaire \
     -e MARIADB_PASSWORD_FILE=/s/db-password -e MARIADB_ROOT_PASSWORD_FILE=/s/root-password \
     -v ~/vlt-secrets:/s:ro mariadb:11.4
   ```

4. **Le core, au plus strict** :

   ```bash
   docker run --rm --network vlt -e VAULTAIRE_DB_HOST=vlt-db \
     --entrypoint /opt/vaultaire/bin/vaultaire_serveur "$IMAGE" --attendre-base 120

   docker run -d --name vlt-core --hostname vlt-core --network vlt \
     --read-only --cap-drop ALL --security-opt no-new-privileges \
     --tmpfs /run/vaultaire:uid=65532,gid=65532,mode=0700 \
     --tmpfs /var/log/vaultaire:uid=65532,gid=65532,mode=0700 \
     -v vlt-data:/var/lib/vaultaire \
     -e VAULTAIRE_DB_HOST=vlt-db \
     -e VAULTAIRE_DB_PASSWORD_FILE=/run/secrets/db-password \
     -e VAULTAIRE_ADMIN_PASSWORD_FILE=/run/secrets/admin-password \
     -v ~/vlt-secrets:/run/secrets:ro \
     -p 1389:3389 -p 1636:3636 -p 6666:6666 -p 4443:4443 -p 6643:6643 "$IMAGE"
   docker logs -f vlt-core       # JSON ; attendre « LDAPS listening on [::]:3636 »
   ```

5. **Administrer** — le CLI est dans l'image et parle au core par son socket :

   ```bash
   alias vlt='docker exec vlt-core /opt/vaultaire/bin/vaultaire_cli'
   vlt version
   vlt create -g Services svc.acme.lan
   vlt create -u svc_ldap svc.acme.lan 'Ancre-Violon-Galet-91' 01/01/2000 --permanent
   vlt add -u svc_ldap -g Services
   vlt create -p ldap-lecture non --desc "Lecture LDAP"
   vlt update -pu ldap-lecture auth   -a 1 acme.lan
   vlt update -pu ldap-lecture search -a 1 acme.lan
   vlt add -gu Services -p ldap-lecture
   ```

6. **Interroger l'annuaire** :

   ```bash
   D="uid=svc_ldap,dc=svc,dc=acme,dc=lan"
   ldapsearch -x -H ldap://127.0.0.1:1389 -D "$D" -w 'Ancre-Violon-Galet-91' -b dc=acme,dc=lan -s base
   LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://127.0.0.1:1636 -D "$D" -w 'Ancre-Violon-Galet-91' \
     -b dc=acme,dc=lan "(objectClass=inetOrgPerson)" uid
   ```

## ✅ Vous avez réussi si

- `cosign verify` affiche le certificat du workflow de release ;
- `docker top vlt-core` montre un seul processus, sous l'UID **65532** ;
- le bind sur 389 est refusé — `Strong(er) authentication required … TLS is
  required for password authentication` — et le même bind en LDAPS rend les
  comptes.

## 🧪 Exercice

Le core est lancé en `--read-only`. Où peut-il encore écrire, et que se passe-t-il
si vous retirez `--tmpfs /run/vaultaire…` ?

<details><summary>Solution</summary>

Seulement dans `/var/lib/vaultaire` (volume), `/var/log/vaultaire` et
`/run/vaultaire` (tmpfs). Sans le tmpfs de `/run/vaultaire`, le core ne peut pas
créer le socket d'administration et **s'arrête** au démarrage : `CRITICAL socket:
failed to create UNIX socket … read-only file system`. C'est voulu : un core sans
socket ne se laisserait plus administrer en local, et le HEALTHCHECK ne pourrait
plus rien constater.
</details>

## 🧪 Exercice — une variable vide

Relancez le core avec `-e VAULTAIRE_DB_PASSWORD=` en plus. Que se passe-t-il, et
pourquoi est-ce voulu ?

<details><summary>Solution</summary>

Le core refuse de démarrer : « VAULTAIRE_DB_PASSWORD est posée mais vide ». Une
variable vide est presque toujours une clé de Secret mal nommée ; la laisser
passer ferait tourner le core sur la valeur du fichier sans que personne ne le
voie. Poser à la fois `VAULTAIRE_DB_PASSWORD` et `VAULTAIRE_DB_PASSWORD_FILE` est
refusé pour la même raison.
</details>

## 📚 Référence

[`docs/Installation/Kubernetes.md` § 1](../../Installation/Kubernetes.md) ·
[`Variables_environnement.md`](../../Installation/Variables_environnement.md)

---

[← Sommaire du chapitre](./README.md) · [Jalon suivant : 12.2 →](./02-installer-avec-helm.md)
