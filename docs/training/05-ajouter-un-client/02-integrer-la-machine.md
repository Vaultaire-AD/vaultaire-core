[⌂ Formation](../README.md) › [Chapitre 5 — Ajouter un client](./README.md) › Jalon 5.2

# Jalon 5.2 — Intégrer la machine

[← Préparer la machine](./01-preparer-la-machine.md) · [Première connexion d'un utilisateur →](./03-premiere-connexion.md)

---

## Objectif

Créer le client dans l'annuaire, installer l'agent, et rattacher la machine à
un groupe.

## Syntaxe

```text
create -c <oui|non> [-join <hôte[:port]> <utilisateur>]
```

`oui|non` indique si la machine est un **serveur membre** (l'agent ouvre alors
en plus un tunnel machine). Le port de `-join` vaut 22 par défaut.

## Étapes

1. Créez et installez :

   ```bash
   vlt create -c oui -join <IP-web01> root
   ```

   Le core affiche l'OS détecté, transfère le script, l'exécute, puis rend
   l'**identifiant** de la machine (`computeur_id`). Notez-le.

   > Un message « Variable d'environnement VAULTAIRE_pubKeyLogin non définie »
   > peut apparaître : il vient de l'ancienne méthode d'échange de clé et n'empêche
   > pas l'installation, la clé ayant été posée au jalon précédent.

2. **Sur `web01`**, vérifiez l'adresse du serveur dans la configuration de
   l'agent, puis démarrez-le :

   ```bash
   cat /etc/vaultaire_client/client_conf.json
   # remplacez l'IP si ce n'est pas celle de votre serveur
   systemctl enable --now vaultaire_client
   journalctl -u vaultaire_client -n 30
   ```

   > ⚠️ Le script d'installation écrit aujourd'hui une adresse de serveur fixe.
   > Tant que ce n'est pas corrigé, ajustez `client_conf.json` à la main.

3. Rattachez la machine au groupe `Infra` :

   ```bash
   vlt get -c
   vlt add -c <computeur_id> -g Infra
   vlt status -c
   ```

## ✅ Vous avez réussi si

- `get -c` liste la machine ;
- `status -c` la montre connectée ;
- `get -g Infra` la compte parmi ses clients.

## 🧪 Exercice

Quels nœuds `web01` va-t-il essayer de joindre, et dans quel ordre ?

<details><summary>Solution</summary>

```bash
vlt get -c <computeur_id> --targets
```

La liste est celle que le serveur répond à la machine ; l'agent la parcourt de
haut en bas. Cette vue exige `read:cluster`.
</details>

---

[← Préparer la machine](./01-preparer-la-machine.md) · [Première connexion d'un utilisateur →](./03-premiere-connexion.md)
