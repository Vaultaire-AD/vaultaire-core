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
| Portail | `https://<IP>:4443/login` | `admin` / le mot de passe que **vous** avez posé |
| CLI locale | `docker exec -it vaultaire-ad /opt/vaultaire/bin/vaultaire_cli` | aucun : socket local |

Le certificat du portail est auto-signé : acceptez l'avertissement du
navigateur.

Deux comptes existent dès le premier démarrage :

| Compte | Rôle | Mot de passe à l'installation |
|---|---|---|
| `admin` | administrateur de la pile, membre du groupe `vaultaire` | celui de `administrateur.password` (ou `VAULTAIRE_ADMIN_PASSWORD`) — **provisoire** |
| `vaultaire` | compte d'amorçage du core, protégé | **aucun utilisable** : il faut lui en donner un |

> ⚠️ **Il n'y a plus de mot de passe par défaut** (TO-DO 99). Le fichier livré
> ne porte que des marqueurs `CHANGEZ_MOI`, et le core **refuse de démarrer**
> tant qu'ils y sont : c'est vous qui posez le mot de passe de `admin`, avant le
> premier démarrage. Il doit tenir la règle de robustesse — 12 caractères par
> défaut, et ne pas contenir l'identifiant du compte ni son domaine (TO-DO 100).
>
> Ce mot de passe est **provisoire** : à votre première connexion, le portail ne
> vous laissera aller nulle part ailleurs que sur la page de changement. C'est
> voulu — celui qui a posé ce mot de passe le connaît, donc ce n'est pas encore
> un secret.

> ℹ️ `vaultaire` n'a pas de mot de passe par défaut. La ligne créée par le
> schéma porte une empreinte d'un format que le core ne lit pas : **aucun** mot
> de passe ne l'ouvre tant qu'on ne lui en a pas posé un. `vaultaire` /
> `password` n'a jamais fonctionné.

## Étapes

0. **Avant le premier démarrage**, posez le mot de passe d'amorçage — sans quoi
   le core refusera de démarrer :

   ```bash
   export VAULTAIRE_ADMIN_PASSWORD='correcte agrafe batterie'
   ```

   ou remplacez `CHANGEZ_MOI` dans `administrateur.password` de
   `serveur_conf.yaml`. Une phrase de passe est exactement ce qu'on veut : c'est
   la longueur qui compte, pas les caractères spéciaux.

1. Ouvrez `https://<IP>:4443/login` et connectez-vous avec `admin` et ce mot de
   passe. **Le portail vous envoie directement sur la page de changement** : le
   mot de passe d'amorçage est provisoire. Posez-en un nouveau, puis parcourez le
   menu **Admin** : Utilisateurs, Groupes, Clients, GPO, DNS, Logs, Arborescence.

2. Ouvrez la ligne de commande et créez un alias pour la suite :

   ```bash
   alias vlt='docker exec -i vaultaire-ad /opt/vaultaire/bin/vaultaire_cli'
   vlt help
   vlt get -u
   ```

   `-i` et non `-it` : sans terminal (un script, un `$( … )`), `-t` échoue avec
   « the input device is not a TTY ». Pour l'invite interactive `vaultaire>`,
   lancez la commande complète avec `-it` (jalon 3.1).

3. **Donnez un mot de passe** à `vaultaire` :

   ```bash
   vlt update -u vaultaire -p 'une autre phrase de passe solide'
   ```

   - `admin` : vous venez de le changer sur le portail, à l'étape 1. Le modifier
     ensuite dans `serveur_conf.yaml` n'a aucun effet : la section
     `administrateur` ne sert qu'à **créer** le compte, au premier démarrage.
   - ⚠️ Un mot de passe posé par `vlt update -u <autre> -p …` est **provisoire** :
     son titulaire devra le changer sur le portail, et il cesse de fonctionner au
     bout de 24 h. C'est voulu — vous le connaissez, donc ce n'est pas un secret.
     Ce n'est pas le cas ici : `vaultaire` est le compte de secours, et vous en
     êtes le titulaire.
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
- l'ancien mot de passe d'amorçage est refusé sur le portail ;
- le portail ne vous a laissé aller nulle part avant que vous n'en ayez posé un
  nouveau ;
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
