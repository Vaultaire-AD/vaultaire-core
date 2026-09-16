[⌂ Formation](../README.md) › [Chapitre 3 — Administrer Vaultaire via vlt](./README.md) › Jalon 3.2

# Jalon 3.2 — vlt à distance par l'API

[← La CLI locale](./01-cli-locale.md) · [Le portail web →](./03-portail-web.md)

---

## Objectif

Administrer le serveur depuis votre poste avec `vaultaire_ctl`, installé sous le
nom `vlt`.

## Ce qu'il faut savoir

- `vaultaire_ctl` envoie les **mêmes commandes** que la CLI locale, par l'API
  REST (port **6643**, HTTPS).
- Chaque requête est **signée** avec votre clé privée SSH ; la clé publique doit
  être enregistrée sur votre compte.
- `vlt` n'accorde aucun droit : une commande refusée en local l'est aussi à
  distance.
- La pile de démonstration fournit un couple prêt à l'emploi : le compte
  `admin` et la clé `deployments/configs/demo_admin_key`.

## Étapes

1. Récupérez le binaire dans la release (archive `vaultaire_ctl`) et
   installez-le :

   ```bash
   tar xzf vaultaire_ctl-v*-linux-amd64.tar.gz
   sudo install -m 0755 vaultaire_ctl/vaultaire_ctl /usr/local/bin/vlt
   ```

2. Récupérez le certificat de l'API pour que `vlt` puisse le vérifier. Sur le
   serveur :

   ```bash
   docker exec vaultaire-ad /opt/vaultaire/bin/vaultaire_cli certificate show api
   ```

   Copiez le bloc `BEGIN CERTIFICATE … END CERTIFICATE` dans
   `~/.vaultaire/api-cert.pem` sur votre poste.

3. Préparez la clé de démonstration :

   ```bash
   mkdir -p ~/.vaultaire
   cp deployments/configs/demo_admin_key ~/.vaultaire/demo_admin_key
   chmod 600 ~/.vaultaire/demo_admin_key
   ```

4. Écrivez `~/.vaultaire/config.json` :

   ```json
   {
     "server": "https://<IP>:6643",
     "username": "admin",
     "private_key": "/home/<vous>/.vaultaire/demo_admin_key",
     "ca_certificate": "/home/<vous>/.vaultaire/api-cert.pem"
   }
   ```

5. Testez :

   ```bash
   vlt version
   vlt get -u
   ```

## ✅ Vous avez réussi si

`vlt get -u` répond depuis votre poste, et le journal du serveur trace l'appel
avec l'utilisateur `admin`.

## 🧪 Exercice

Donnez à Alice son propre accès `vlt` : générez-lui une clé, enregistrez la
partie publique sur son compte, puis écrivez sa configuration.

<details><summary>Solution</summary>

```bash
ssh-keygen -t ed25519 -f ~/.vaultaire/alice -N ''
vlt add -u alice.martin -k "poste-alice" "$(cat ~/.vaultaire/alice.pub)"
vlt get -u alice.martin          # la clé apparaît avec son identifiant
```

Dans une copie de `config.json`, `username` devient `alice.martin` et
`private_key` pointe sur `~/.vaultaire/alice`. Pour l'instant Alice ne peut
presque rien faire : ses droits arrivent au
[chapitre 4](../04-permissions-et-delegation/README.md).
</details>

> 🔐 Une clé enregistrée donne aussi un accès SSH **sans mot de passe** aux
> machines du parc où le compte est provisionné. Une clé n'appartient qu'à un
> seul compte.

---

[← La CLI locale](./01-cli-locale.md) · [Le portail web →](./03-portail-web.md)
