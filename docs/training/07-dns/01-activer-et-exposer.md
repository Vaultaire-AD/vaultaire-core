[⌂ Formation](../README.md) › [Chapitre 7 — DNS](./README.md) › Jalon 7.1

# Jalon 7.1 — Activer et exposer le DNS

[← Sommaire du chapitre](./README.md) · [Zones et enregistrements →](./02-zones-et-enregistrements.md)

---

## Objectif

Rendre le DNS du core interrogeable depuis le réseau.

## Ce qu'il faut savoir

- Le DNS écoute sur **53/udp**, activé par `dns.dns_enable: true` dans
  `serveur_conf.yaml` (c'est le cas de la configuration de démonstration).
- Le compose de préprod **ne publie pas** ce port.
- Toutes les commandes `dns` exigent `write:dns` (global).

## Étapes

1. Dans `deployments/pre-prod/docker-compose.yml`, ajoutez aux `ports` du
   service `vaultaire-ad` :

   ```yaml
         - "53:53/udp"
   ```

   Sur beaucoup de distributions, `systemd-resolved` occupe déjà le port 53 de
   l'hôte : libérez-le ou publiez sur une adresse précise
   (`"<IP>:53:53/udp"`).

2. Recréez le conteneur :

   ```bash
   docker compose -f deployments/pre-prod/docker-compose.yml up -d vaultaire-ad
   ```

3. Testez :

   ```bash
   dig @<IP-serveur> vaultaire.acme.lan
   ```

   La réponse est vide (`NXDOMAIN` ou `REFUSED`) : aucune zone n'existe encore,
   mais le serveur **répond**.

## ✅ Vous avez réussi si

`dig` obtient une réponse du serveur, pas un « connection timed out ».

## 🧪 Exercice

Où vérifier, sans `dig`, que le DNS est bien activé ?

<details><summary>Solution</summary>

Dans le journal du core : `dns: waiting for DNS requests on port 53`. Le menu
**Admin → DNS** n'apparaît aussi que si le module est activé.
</details>

---

[← Sommaire du chapitre](./README.md) · [Zones et enregistrements →](./02-zones-et-enregistrements.md)
