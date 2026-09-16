[⌂ Formation](../README.md) › [Chapitre 1 — Installer le serveur](./README.md) › Jalon 1.3

# Jalon 1.3 — Premier accès et sécurisation

[← Démarrer la pile](./02-demarrer-la-pile.md) · [Chapitre 2 — Premiers groupes et utilisateurs →](../02-groupes-et-utilisateurs/README.md)

---

## Objectif

Se connecter au portail et à la ligne de commande, puis retirer les
identifiants par défaut.

## Les accès par défaut

| Accès | Adresse | Identifiants |
|---|---|---|
| Portail | `https://<IP>:4443/login` | `vaultaire` / `password` ou `admin` / `admin123` |
| CLI locale | `docker exec -it vaultaire-ad /opt/vaultaire/bin/vaultaire_cli` | aucun : socket local |

Le certificat du portail est auto-signé : acceptez l'avertissement du
navigateur.

## Étapes

1. Ouvrez `https://<IP>:4443/login` et connectez-vous avec `vaultaire` /
   `password`. Parcourez le menu **Admin** : Utilisateurs, Groupes, Clients,
   GPO, DNS, Logs, Arborescence.

2. Ouvrez la ligne de commande et créez un alias pour la suite :

   ```bash
   alias vlt='docker exec -it vaultaire-ad /opt/vaultaire/bin/vaultaire_cli'
   vlt help
   vlt get -u
   ```

3. Changez les deux mots de passe par défaut :

   ```bash
   vlt update -u vaultaire -p 'Un-Mot-De-Passe-Solide'
   vlt update -u admin -p 'Un-Autre-Mot-De-Passe'
   ```

   Le compte `vaultaire` ne peut être ni supprimé ni renommé, mais son mot de
   passe peut — et doit — changer.

4. Notez l'empreinte du core : chaque agent la comparera à la clé qu'on lui
   sert.

   ```bash
   vlt certificate fingerprint
   ```

## ✅ Vous avez réussi si

- vous voyez le tableau de bord du portail ;
- `vlt get -u` liste au moins `vaultaire` et `admin` ;
- l'ancien mot de passe `password` est refusé sur le portail.

## 🧪 Exercice

Le portail sera joint par le nom `vaultaire.acme.lan`. Faites en sorte que son
certificat couvre ce nom, puis vérifiez-le.

<details><summary>Solution</summary>

```bash
vlt certificate regenerate web --dns vaultaire.acme.lan
vlt certificate show web
```

Un certificat est produit au premier démarrage : un nom ajouté ensuite ne le
couvre qu'après régénération.
</details>

> ⚠️ Hors démonstration, désactivez aussi `debug` et remplacez la section
> `administreur` de `serveur_conf.yaml` : sa clé publique correspond à la clé de
> démonstration publiée dans le dépôt.

---

[← Démarrer la pile](./02-demarrer-la-pile.md) · [Chapitre 2 — Premiers groupes et utilisateurs →](../02-groupes-et-utilisateurs/README.md)
