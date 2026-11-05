[⌂ Formation](../README.md) › [Chapitre 11 — Nexus](./README.md) › Jalon 11.1

# Jalon 11.1 — Déployer et raccorder un Nexus

[← Sommaire du chapitre](./README.md) · [Les dépôts : créer, publier, consommer →](./02-depots.md)

---

## Objectif

Démarrer un Nexus à côté de la pile, l'enrôler dans le cluster, et le voir dans
`vlt cluster list` avec l'adresse que les agents utiliseront.

## Ce qu'il faut savoir

- Nexus est un **service** du cluster, comme le proxy : il s'**enrôle lui-même**
  avec une clé de type `vaultaire_nexus` (jalon 10.1) et garde son identité dans
  `<data_dir>/ducky`. Ce dossier doit **persister** : sinon Nexus se réenrôle à
  chaque démarrage.
- **`public_url`** est l'adresse par laquelle les clients le joignent. C'est elle
  que le core annonce aux agents comme dépôt de mise à jour, et elle que
  `vlt cluster list` affiche en **ACCÈS AGENTS**.
- Le certificat est **auto-signé** par défaut. Il doit couvrir le nom **ou**
  l'adresse de `public_url` : `tls.dns_names` et `tls.ip_addresses`. Un client
  qui vise une adresse absente du certificat refuse la connexion.
- Le compte **`admin`** est local à Nexus, indépendant de l'annuaire, et reste
  actif quel que soit le mode d'authentification : c'est le compte de secours.

## Étapes

1. Sur l'hôte Docker, à côté du compose de Nexus, écrivez une configuration
   minimale, sur le modèle de `config.example.yaml` :

   ```bash
   cd src/vaultaire_nexus/deploy
   cp ducky.example.yaml ducky.yaml
   ```

   `config.yaml` :

   ```yaml
   listen: ":8843"
   public_url: "https://<IP-serveur>:8843"
   data_dir: /var/lib/vaultaire_nexus
   log_path: /var/log/vaultaire/
   tls:
     enable: true
     self_signed: true
     dns_names: [nexus.acme.lan, localhost]
     ip_addresses: [<IP-serveur>, 127.0.0.1]
   auth:
     mode: ducky                 # les comptes Vaultaire, vérifiés par le core
     local_admin:
       enable: true
       username: admin
     roles:
       admin:     [vaultaire]
       publisher: []
       reader:    ["*"]          # tout compte authentifié lit
   repositories:
     - name: releases            # le dépôt du parc (jalon 11.3)
       type: vaultaire
       public: true              # lu sans compte par les agents
   ducky:
     enable: true
     config: /etc/vaultaire_nexus/ducky.yaml
     keys: /var/lib/vaultaire_nexus/ducky
   ```

   > La lecture est **stricte** : une clé inconnue empêche le démarrage.
   > Une fois les montages faits (étape 3), `docker compose run --rm nexus
   > -config /etc/vaultaire_nexus/config.yaml -check` valide sans démarrer.

2. Créez la clé d'enrôlement, puis collez-la dans `ducky.yaml` :

   ```bash
   vlt enroll create --type vaultaire_nexus --uses 1 --expires 1h --label nexus-lab
   ```

   ```yaml
   servers:
     - ip: "<IP-serveur>"
       port: 6666
   enrollment:
     key: "VLT-ENR-…"
     label: "nexus-lab"
   ```

3. Dans `docker-compose.yml`, décommentez les deux montages (`config.yaml`,
   `ducky.yaml`), puis démarrez :

   ```bash
   NEXUS_PUBLIC_URL=https://<IP-serveur>:8843 docker compose up -d --build
   docker compose logs -f nexus          # Ctrl+C une fois l’enrôlement journalisé
   docker compose exec nexus cat /var/lib/vaultaire_nexus/admin.initial
   ```

   > Le compose passe toujours `NEXUS_PUBLIC_URL`, qui **remplace** `public_url`
   > du fichier (défaut : `https://localhost:8843`). D'où la variable sur la
   > ligne de commande : sans elle, le core annoncerait `localhost` aux agents.

   > `NEXUS_ADMIN_PASSWORD` fixe le mot de passe sans fichier — pratique en
   > labo, mais il devient lisible par `docker inspect` et ne se change plus
   > depuis l'interface. Ici, laissez-le vide : le mot de passe est tiré au
   > hasard et écrit **une fois** dans `admin.initial`.

4. Côté core :

   ```bash
   vlt cluster list
   ```

   Une ligne `vaultaire_nexus`, **online**, ACCÈS AGENTS
   `https://<IP-serveur>:8843`. S'il est en ROT. `out`, il n'est annoncé ni aux
   agents ni aux proxys : `vlt cluster rotation <nœud-nexus> in`.

5. Ouvrez `https://<IP-serveur>:8843`, acceptez le certificat, connectez-vous en
   `admin`. Dans **Administration**, changez le mot de passe : `admin.initial`
   disparaît. Puis déconnectez-vous et reconnectez-vous avec
   `alice.martin@infra.acme.lan` : le mode `ducky` fait vérifier le mot de passe
   **et le second facteur** par le core.

## ✅ Vous avez réussi si

- `vlt cluster list` montre le Nexus en ligne, avec `public_url` en ACCÈS AGENTS ;
- `curl -k https://<IP-serveur>:8843/healthz` répond ;
- vous vous êtes connecté avec un compte Vaultaire.

## 🧪 Exercice

`alice.martin` se connecte, mais ne voit ni **Administration** ni le bouton de
création de dépôt : elle n'est que `reader`, par la ligne `"*"` de
`auth.roles`. Donnez-lui le rôle **admin** de Nexus **depuis le core**, sans
toucher au fichier de Nexus. Et que se passerait-il sans la ligne `"*"` ?

<details><summary>Solution</summary>

Le rôle est le plus élevé entre les **droits du core** (`read:nexus`,
`write:nexus`, `write:nexus_admin`) et la table `auth.roles`. Depuis le core :

```bash
vlt create -p nexus-admin non
vlt update -pu nexus-admin write:nexus_admin all
vlt add -gu Infra -p nexus-admin
```

Ou sur le portail : **Permissions → Actions hors matrice**. Nexus relit les
droits des sessions ouvertes toutes les 5 minutes ; reconnectez-vous pour l'avoir
tout de suite.

Sans `"*"`, un compte sans aucun rôle est **refusé**, même avec le bon mot de
passe et le bon code. Avec `auth.ducky.require_right: true`, la table est
ignorée : seul le core décide.
</details>

## 📚 Référence

[`vaultaire_nexus/README.md`](../../../src/vaultaire_nexus/README.md) §1, §3, §4,
§8 « Raccordement au cluster » ·
[`config.example.yaml`](../../../src/vaultaire_nexus/config.example.yaml)

---

[← Sommaire du chapitre](./README.md) · [Les dépôts : créer, publier, consommer →](./02-depots.md)
