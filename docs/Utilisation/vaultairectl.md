# `vaultaire_ctl` — administration à distance

`vaultaire_ctl` administre un serveur Vaultaire **par l'API REST signée**, depuis
n'importe quelle machine. Les commandes sont celles de `vaultaire_cli`, qui lui
s'exécute sur le serveur par le socket UNIX local.

| | |
| --- | --- |
| Source | [`src/vaultaire_ctl/`](../../src/vaultaire_ctl/) |
| Binaire | `cmd/vaultaire_ctl/vaultaire_ctl`, produit par [`auto-compil.sh`](../../auto-compil.sh) |
| Transport | API REST sur le port `6643` (HTTPS), requêtes signées par clé privée |
| Manuel des commandes | [`MAN.md`](./MAN.md) |

---

## Installation

```sh
install -o root -g root -m 0755 cmd/vaultaire_ctl/vaultaire_ctl /usr/local/bin/vlt
```

## Configuration

Créez `~/.vaultaire/config.json` :

```json
{
  "server": "https://192.168.10.57:6643",
  "username": "alice",
  "private_key": "/home/alice/.ssh/id_rsa",
  "ca_certificate": "/root/.vaultaire/api-cert.pem"
}
```

La **clé publique** correspondante doit être enregistrée sur le serveur, par le
portail web (page Profil) ou par un administrateur :

```sh
vlt add -u alice -k "ssh-ed25519 AAAA…"
```

> Le fichier référencé par `private_key` doit être lisible par le seul
> utilisateur (`chmod 600`). C'est lui qui signe chaque requête : le posséder
> revient à posséder l'identité.

---

## ⚠️ Changement de protocole — Alpha 2.0.0

Depuis la 2.0.0, le corps signé de chaque requête doit porter un champ
`timestamp`, et le serveur tient un registre de nonces sur une fenêtre glissante
de deux minutes.

Une signature dit *qui*, jamais *quand* : sans horodatage, une requête capturée
restait rejouable indéfiniment.

`vaultaire_ctl` et `api_client_package` sont à jour. **Tout consommateur externe
de `/api/command` doit être adapté**, sans quoi ses requêtes sont refusées. Voir
[`../Version/2.0/2.0.md`](../Version/2.0/2.0.md).

---

## Utilisation

La syntaxe est celle de `vaultaire_cli` :

```sh
[alice@poste ~]$ vlt get -u
✅ Résultat: 👥 Liste de tous les Utilisateurs
--------------------------------------------------
ID Utilisateur  Username                  Date de Naissance Créé à
1               vaultaire                 1990-01-01      2025-07-13 14:09:44
2               alice                     1992-02-06      2025-07-13 14:12:20
3               bob                       1988-12-09      2025-07-13 14:12:20
--------------------------------------------------
```

Les droits sont les mêmes que sur le serveur : `vaultaire_ctl` n'accorde rien,
il transporte. Une commande refusée en local l'est aussi à distance, et
réciproquement.

---

## Journalisation

Chaque requête API est journalisée côté serveur, avec l'identité de l'appelant :

```sh
tail -n 1 /var/log/vaultaire/vaultaire.log
2025-09-03 23:22:26 [INFO] 🕵️ User: alice | Command: get -u | Status: SUCCESS
```

---

## Intégration dans un programme

Pour piloter l'API depuis du code Go plutôt que depuis un terminal, utilisez
[`src/api_client_package/`](../../src/api_client_package/) : c'est la
bibliothèque dont `vaultaire_ctl` est lui-même le client, horodatage et
signature compris.
