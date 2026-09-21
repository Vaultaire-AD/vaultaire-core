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
- Chaque requête est **signée** avec votre clé privée SSH (ed25519 ou RSA) ; la
  clé publique doit être enregistrée sur votre compte. L'horloge du poste doit
  être à l'heure : une requête datée de plus de deux minutes est refusée.
- `vlt` n'accorde aucun droit : une commande refusée en local l'est aussi à
  distance.
- La pile de démonstration fournit un couple prêt à l'emploi : le compte
  `admin` et la clé `deployments/configs/demo_admin_key`.
- La configuration est lue dans `~/.vaultaire/config.json` (ou le fichier
  désigné par `VAULTAIRE_CONFIG`). Il n'y a pas d'option en ligne de
  commande : tout ce qui suit `vlt` est la commande envoyée au serveur.
- Chaque réponse commence par `✅ Résultat:` ; une erreur de l'API, par
  `❌ erreur serveur:`.

## Étapes

1. Installez le binaire sous le nom `vlt`.

   - **Sur l'hôte du serveur**, `docker-update.sh` (jalon 1.2) l'a déjà
     déposé dans `cmd/vaultaire_ctl/`. Retirez d'abord l'alias du jalon 1.3,
     qui masquerait le binaire :

     ```bash
     unalias vlt
     sudo install -m 0755 cmd/vaultaire_ctl/vaultaire_ctl /usr/local/bin/vlt
     ```

   - **Sur un autre poste**, prenez l'archive `vaultaire_ctl` de la release :

     ```bash
     tar xzf vaultaire_ctl-v*-linux-amd64.tar.gz
     sudo install -m 0755 vaultaire_ctl/vaultaire_ctl /usr/local/bin/vlt
     ```

2. Faites couvrir l'adresse du serveur par le certificat de l'API.

   `vlt` vérifie le certificat **et le nom** qu'il porte. Or le certificat de
   l'API est produit au premier démarrage avec les noms que le core détecte
   seul — dans la pile Docker, le nom et l'adresse **du conteneur**, pas ceux
   de l'hôte. Sans cette étape, `vlt` échoue avec
   `x509: certificate is valid for …, not <IP>`.

   Sur le serveur :

   ```bash
   docker exec vaultaire-ad /opt/vaultaire/bin/vaultaire_cli \
     certificate regenerate api --ip <IP>
   docker restart vaultaire-ad       # le certificat est chargé au démarrage
   ```

   Si vous joignez le serveur par un nom, ajoutez `--dns <nom>` (plusieurs
   valeurs séparées par des virgules).

3. Récupérez ce certificat pour que `vlt` puisse le vérifier. Sur le serveur :

   ```bash
   docker exec vaultaire-ad /opt/vaultaire/bin/vaultaire_cli certificate show api
   ```

   Copiez le bloc `BEGIN CERTIFICATE … END CERTIFICATE` dans
   `~/.vaultaire/api-cert.pem` sur votre poste.

4. Préparez la clé de démonstration :

   ```bash
   mkdir -p ~/.vaultaire
   cp deployments/configs/demo_admin_key ~/.vaultaire/demo_admin_key
   chmod 600 ~/.vaultaire/demo_admin_key
   ```

5. Écrivez `~/.vaultaire/config.json` :

   ```json
   {
     "server": "https://<IP>:6643",
     "username": "admin",
     "private_key": "/home/<vous>/.vaultaire/demo_admin_key",
     "ca_certificate": "/home/<vous>/.vaultaire/api-cert.pem"
   }
   ```

   `<IP>` doit être exactement l'adresse (ou le nom) couverte à l'étape 2.
   `insecure_skip_verify: true` existe pour un diagnostic ponctuel : il accepte
   n'importe quel serveur, ne le laissez pas dans une configuration.

6. Testez :

   ```bash
   vlt version       # version du SERVEUR : vlt n'a pas de commande locale
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
