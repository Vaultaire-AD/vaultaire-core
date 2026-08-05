# duckynetwork — socle Ducky Network à copier-coller

Ce dépôt n'est pas une bibliothèque à importer depuis un dépôt distant. C'est un
**dossier destiné à être copié dans vos projets**, avec un script qui réécrit
ses imports au passage.

```
ducky-network-sdk/
├── duckynetwork/          ← LE dossier à copier
├── install.sh             ← le copie et réécrit ses imports
├── go.mod                 ← module de développement, JAMAIS copié
└── doc/
    ├── README.md              ce fichier
    ├── IMPLEMENTER.md         mettre en place dans un projet neuf
    ├── AJOUTER_UNE_TRAME.md   étendre sans casser les mises à jour
    └── PROTOCOLE.md           format des trames et chiffrement
```

## Pourquoi un copier-coller et non un vrai paquet

Go n'a pas d'imports relatifs. Un dossier à sous-paquets porte donc toujours,
dans ses propres imports, le nom du module qui l'héberge :

```go
// dans vaultaire_client
import "vaultaire_client/duckynetworkClient/sendmessage"

// dans le proxy
import "vaultaire_proxy/duckynetwork/sendmessage"
```

Le même fichier ne peut pas convenir aux deux sans réécriture. Faire un vrai
module publié résoudrait cela, mais imposerait une version figée à des
programmes qu'on veut pouvoir diverger : un agent ajoute la catégorie 03 et 05,
un proxy la 04, une extension inventera la sienne. Le copier-coller assume cette
divergence — chacun garde le socle et greffe ce qui lui est propre.

Le prix est la réécriture du préfixe, que `install.sh` fait pour vous.

## Ce que le dossier contient

| Sous-dossier      | Rôle |
|-------------------|------|
| `storage/`        | Types partagés : trame, session. |
| `logs/`           | Indirection de journalisation, silencieuse par défaut. |
| `key_encode_decode/` | RSA-OAEP, AES-256-GCM, génération de paires. |
| `keymanagement/`  | Clés et identité sur disque. |
| `sendmessage/`    | Fabrication et envoi d'une trame. |
| `trames_manager/` | Lecture du cadrage, déchiffrement, `Spliter`. |
| `session/`        | Cycle de vie complet : connexion, reconnexion, réenrôlement. |
| `trames/t01_*`    | `askkey`, défi d'authentification du serveur, enrôlement. |
| `trames/t02_*`    | Authentification du programme ou d'une personne. |
| `trames/t03_*`    | Authentification d'un utilisateur tiers, sans transmettre son mot de passe. |
| `trames/t04_*`    | Cluster : enregistrement, battement de cœur, sortie. |
| `trames/t05_*`    | GPO — squelette, propre à l'agent. |

Les catégories sont dans des dossiers séparés pour qu'un programme voie du
premier coup d'œil ce qui le concerne, et pour qu'une catégorie qu'il n'utilise
pas reste un dossier de constantes plutôt qu'un tronçon de `switch` mort au
milieu d'un fichier commun.

## Le socle de connexion : 01, 02, 03

Ces trois catégories sont **communes à tout programme**, quel qu'il soit, et
entièrement implémentées ici :

```
01   le programme authentifie LE SERVEUR      (défi : un aléa doit revenir intact)
02   le programme s'authentifie AUPRÈS de lui (compte « vaultaire » pour un service)
03   le programme fait authentifier UN TIERS  (le mot de passe ne part jamais)
```

`session.Run` enchaîne 01 puis 02 tout seul. La catégorie 03 est à la main du
programme : c'est lui qui décide quand il a un utilisateur à faire valider.

`t05_gpo` reste un squelette : les politiques ne concernent que les machines du
parc, et les remplir ici ferait porter à un proxy du code qu'il n'exécutera
jamais. Sa place est réservée.

## Démarrage

```bash
./install.sh /chemin/vers/mon-projet
```

Puis lisez [IMPLEMENTER.md](IMPLEMENTER.md).

## Mise à jour

Relancez `install.sh` sur le projet : le dossier est **entièrement remplacé**.

C'est pour cela que vos ajouts doivent vivre **hors** de `duckynetwork/`. Voir
[AJOUTER_UNE_TRAME.md](AJOUTER_UNE_TRAME.md).
