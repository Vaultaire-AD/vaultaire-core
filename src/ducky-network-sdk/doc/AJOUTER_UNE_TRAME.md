# Ajouter des trames sans casser les mises à jour

## La règle

> `install.sh` **remplace entièrement** `duckynetwork/`.
> Ce que vous écrivez vit donc **à côté**, pas dedans.

Un fichier ajouté dans `duckynetwork/trames/t04_cluster/` disparaît à la
prochaine mise à jour, sans avertissement. Le même fichier dans
`internal/trames/t07_web/` survit à toutes.

```
mon-service/
├── duckynetwork/          ← remplacé à chaque install.sh, NE RIEN Y METTRE
│   ├── session/
│   ├── trames/t01_serveurauth/ …
│   └── …
└── internal/
    └── trames/
        └── t07_web/       ← à vous
            ├── handler.go
            └── commande.go
```

## Le point d'extension : le Spliter

Il aiguille sur la **catégorie**, les deux premiers chiffres du code. Un
gestionnaire par catégorie, branché avant `Run` :

```go
client.Spliter().Handle("07", web.Handler)
```

C'est tout. Rien à modifier dans `duckynetwork/`.

## Écrire un gestionnaire

```go
// internal/trames/t07_web/handler.go
package web

import (
    "mon-service/duckynetwork/logs"
    "mon-service/duckynetwork/storage"
)

const (
    AskCommand = "07_01"
    CommandOK  = "07_02"
    CommandKO  = "07_03"
)

// Handler traite les trames 07.
//
// La chaîne renvoyée, si elle n'est pas vide, est renvoyée au core comme
// réponse. Renvoyer "" ne répond rien : c'est le cas normal d'un acquittement.
func Handler(trames storage.Trames_struct_client, session *storage.DuckySession) string {
    switch trames.Code() {
    case CommandOK:
        logs.Write("INFO", "commande acceptée")
    case CommandKO:
        logs.Write("ERROR", "commande refusée : "+trames.Content)
    default:
        logs.Write("DEBUG", "trame 07 inconnue : "+trames.Code())
    }
    return ""
}
```

## Émettre

```go
import "mon-service/duckynetwork/sendmessage"

message := sendmessage.BuildClientTrame(
    AskCommand,
    "serveur_central",
    session.SessionID,
    session.Username,
    session.ComputeurID,
    "user list",          // chaque argument devient une ligne de contenu
)
err := sendmessage.SendMessage(message, session, "")
```

Le dernier paramètre est la clé publique du core, utile seulement avant que la
session soit chiffrée. Une fois `IsSafe` vrai — c'est-à-dire partout dans votre
code métier — passez `""`.

## Ne bloquez pas le Spliter

Un gestionnaire s'exécute **dans la boucle de réception**. Tant qu'il n'a pas
rendu la main, aucune autre trame n'est lue, battements de cœur compris.

Un traitement long, ou qui attend lui-même une réponse du core, doit rendre la
main tout de suite et travailler ailleurs :

```go
func Handler(trames storage.Trames_struct_client, session *storage.DuckySession) string {
    go traiterLonguement(trames)   // ne bloque pas la réception
    return ""
}
```

C'est exactement ce que fait la catégorie 05 côté agent : elle réveille un cycle
en attente au lieu de transférer les fragments dans le fil du Spliter.

## Ce que le core doit savoir de vous

Une trame émise n'est acceptée que si le **catalogue de types de clients** du
core l'autorise pour votre type. Côté core, dans
`src/vaultaire_serveur/core/clienttype/clienttype.go` :

```go
"mon_service": {
    Name:    "mon_service",
    Kind:    KindService,
    Frames:  map[string][]string{
        "01": {"01_01", "01_03"},
        "02": {"02_01", "02_03"},
        "04": {"04_09", "04_12", "04_14"},
        "07": {"07_01"},
    },
},
```

Le catalogue est **fermé par défaut** : une sous-trame absente de la liste est
refusée. Un nouveau code qui « ne passe pas » alors que le client tourne est
presque toujours un oubli ici — regardez les logs `SECURITY` du core avant de
chercher ailleurs.

Le catalogue ne contient pas le core lui-même : il juge les trames qu'il reçoit
d'après le type de leur émetteur, et il ne peut pas juger les siennes.

## Numéro de catégorie

| Catégorie | Usage |
|-----------|-------|
| 01 | Clé serveur, poignée de main, enrôlement |
| 02 | Authentification |
| 03 | SSH |
| 04 | Cluster |
| 05 | GPO |
| 06 | Réservé |
| 07 | Interface web |
| 08+ | Libre |

Prenez le prochain libre et notez-le ici et dans la documentation du protocole.
Réutiliser un numéro pour deux sens différents selon le programme rendrait les
journaux du core inexploitables : il ne voit que le code.

## Avant de livrer

```bash
go build ./... && go vet ./...
```

Puis relancez `install.sh` sur une copie du projet et revérifiez : si quelque
chose casse, c'est que du code à vous s'était glissé dans `duckynetwork/`.
