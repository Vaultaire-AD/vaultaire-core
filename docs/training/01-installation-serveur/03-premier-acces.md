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
| Portail | `https://<IP>:4443/login` | `admin` / `admin123` |
| CLI locale | `docker exec -it vaultaire-ad /opt/vaultaire/bin/vaultaire_cli` | aucun : socket local |

Le certificat du portail est auto-signé : acceptez l'avertissement du
navigateur.

Deux comptes existent dès le premier démarrage :

| Compte | Rôle | Mot de passe à l'installation |
|---|---|---|
| `admin` | administrateur de la pile, membre du groupe `vaultaire` | `admin123` — section `administreur` de `serveur_conf.yaml` |
| `vaultaire` | compte d'amorçage du core, protégé | **aucun utilisable** : il faut lui en donner un |

> ℹ️ `vaultaire` n'a pas de mot de passe par défaut. La ligne créée par le
> schéma porte une empreinte d'un format que le core ne lit pas : **aucun** mot
> de passe ne l'ouvre tant qu'on ne lui en a pas posé un. `vaultaire` /
> `password` n'a jamais fonctionné.

## Étapes

1. Ouvrez `https://<IP>:4443/login` et connectez-vous avec `admin` /
   `admin123`. Parcourez le menu **Admin** : Utilisateurs, Groupes, Clients,
   GPO, DNS, Logs, Arborescence.

2. Ouvrez la ligne de commande et créez un alias pour la suite :

   ```bash
   alias vlt='docker exec -i vaultaire-ad /opt/vaultaire/bin/vaultaire_cli'
   vlt help
   vlt get -u
   ```

   `-i` et non `-it` : sans terminal (un script, un `$( … )`), `-t` échoue avec
   « the input device is not a TTY ». Pour l'invite interactive `vaultaire>`,
   lancez la commande complète avec `-it` (jalon 3.1).

3. Remplacez le mot de passe de `admin`, puis **donnez-en un** à `vaultaire` :

   ```bash
   vlt update -u admin -p 'Un-Mot-De-Passe-Solide'
   vlt update -u vaultaire -p 'Un-Autre-Mot-De-Passe-Solide'
   ```

   - `admin` : le nouveau mot de passe remplace `admin123` pour de bon. Le
     modifier ensuite dans `serveur_conf.yaml` n'a plus d'effet : la section
     `administreur` ne sert qu'à **créer** le compte, au premier démarrage.
   - `vaultaire` : c'est le compte de secours. Il ne peut être ni supprimé ni
     renommé ; son mot de passe n'ouvre **que le portail** — le bind LDAP et les
     connexions aux machines (SSH, PAM) lui sont refusés — et n'expire jamais.
     Gardez-le hors ligne, comme un secret d'infrastructure.
   - La CLI locale, elle, n'utilise aucun mot de passe : elle agit sous
     l'identité `vaultaire` parce qu'elle passe par le socket.

4. Notez l'empreinte du core : chaque agent la comparera à la clé qu'on lui
   sert.

   ```bash
   vlt certificate fingerprint
   ```

## ✅ Vous avez réussi si

- vous voyez le tableau de bord du portail ;
- `vlt get -u` liste au moins `vaultaire` et `admin` ;
- `admin123` est refusé sur le portail ;
- vous ouvrez le portail avec `vaultaire` et son nouveau mot de passe.

## 🧪 Exercice

Le portail sera joint par le nom `vaultaire.acme.lan`. Faites en sorte que son
certificat couvre ce nom, puis vérifiez-le.

<details><summary>Solution</summary>

```bash
vlt certificate regenerate web --dns vaultaire.acme.lan
vlt certificate show web
```

Un certificat est produit au premier démarrage : un nom ajouté ensuite ne le
couvre qu'après régénération **et redémarrage** du core, qui charge ses
certificats au démarrage (`docker restart vaultaire-ad`). `web` ne couvre que le
portail : l'API (port 6643) a son propre certificat, `api` — voir le
[jalon 3.2](../03-administrer-avec-vlt/02-vlt-a-distance.md).
</details>

> ⚠️ Hors démonstration :
>
> - désactivez `debug` : `vlt update -debug false` ;
> - retirez la clé de démonstration du compte `admin`. Sa partie publique
>   correspond à `deployments/configs/demo_admin_key`, publiée dans le dépôt.
>   Modifier la section `administreur` de `serveur_conf.yaml` **après** le
>   premier démarrage n'y change rien — le compte existe déjà. Retirez-la
>   depuis la CLI :
>
>   ```bash
>   vlt get -u admin                  # repère l'identifiant de la clé
>   vlt remove -u admin -k <id_clé>
>   ```
>
>   Sur une installation neuve, modifiez `administreur` **avant** le premier
>   démarrage.

---

[← Démarrer la pile](./02-demarrer-la-pile.md) · [Chapitre 2 — Premiers groupes et utilisateurs →](../02-groupes-et-utilisateurs/README.md)
