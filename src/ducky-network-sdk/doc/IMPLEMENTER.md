# Mettre en place duckynetwork dans un projet

## 1. Installer le dossier

```bash
cd /chemin/vers/ducky-network-sdk
./install.sh ~/dev/mon-service
```

Le script lit le nom du module dans `go.mod`, copie `duckynetwork/`, et réécrit
le préfixe d'import. Rien d'autre n'est touché dans votre projet.

## 2. Le minimum qui tourne

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "mon-service/duckynetwork/logs"
    "mon-service/duckynetwork/session"
)

func main() {
    // La journalisation est SILENCIEUSE par défaut : le dossier ne décide pas
    // où votre programme écrit. Sans cette ligne, vous ne verrez rien.
    logs.SetWriter(func(level, message string) {
        log.Printf("[%s] %s", level, message)
    })

    client, err := session.New(session.Config{
        ServerAddress: os.Getenv("VAULTAIRE_IP_CORE"),
        KeyDir:        "/var/lib/mon-service/keys",
        EnrollmentKey: os.Getenv("ENROLLMENT_KEY"),
        Label:         "mon-service-01",
        AllowReEnroll: true,
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx, stop := signal.NotifyContext(context.Background(),
        syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    if err := client.Run(ctx); err != nil && ctx.Err() == nil {
        log.Fatal(err)
    }
}
```

`Run` ne rend la main que sur annulation du contexte, ou sur une erreur dont il
ne peut pas se remettre. Tout le reste — coupure réseau, core redémarré,
identité effacée — est traité à l'intérieur.

## 3. Ce qui vous appartient : `KeyDir`

Ce répertoire contient :

| Fichier             | Contenu | Perte = |
|---------------------|---------|---------|
| `private_key.pem`   | votre clé privée, jamais transmise | réenrôlement |
| `public_key.pem`    | votre clé publique | réenrôlement |
| `server_public.pem` | la clé publique du core | `askkey` en clair au démarrage |
| `identity.json`     | identifiant machine attribué, type | réenrôlement |

**Il doit survivre aux redémarrages.** Un conteneur sans volume persistant se
réenrôle à chaque lancement et consomme une place de clé d'enrôlement à chaque
fois — jusqu'à épuiser le quota et rester bloqué dehors.

## 4. La clé d'enrôlement

Elle n'est lue qu'au premier démarrage, ou après un réenrôlement forcé. Elle
porte le **type** du client : c'est elle qui décide de ce que le core vous
laissera émettre. Un programme ne peut pas déclarer son type — sinon il suffirait
de s'enrôler pour se donner les privilèges qu'on veut.

Côté core :

```
vlt enroll create --type vaultaire_proxy --uses 1 --expires 24h
```

`--uses 0` et pas de `--expires` donnent une clé sans limite : pratique pour un
parc qui se déploie tout seul, à réserver aux cas où c'est vraiment voulu.

## 5. Ce que `Run` fait pour vous : 01 puis 02

À chaque connexion, et sans que vous ayez rien à écrire :

```
01   le défi qui authentifie LE SERVEUR   → sinon on ne parle pas à lui
02   votre programme s'authentifie        → sous le compte « vaultaire »
```

`Run` ne considère la session établie qu'une fois les DEUX faites. Une session
arrêtée après 01 aurait un tunnel chiffré mais aucune identité reconnue côté
core : elle serait refusée à la première trame utile, avec un message qui ne
dirait pas que le login manque.

Si le serveur échoue au défi 01, `Run` **s'arrête sans réessayer**. Ce n'est pas
une panne réseau : c'est que le serveur en face n'est pas le core, ou que sa clé
a changé sans qu'on le sache. Reconnecter en boucle ne ferait que redonner des
occasions à qui se fait passer pour lui.

Pour ouvrir la session au nom d'une **personne** plutôt que du programme,
renseignez `Username` et `Password` dans la Config. C'est rare : authentifier un
utilisateur tiers passe par la catégorie 03, pas par là.

## 6. Authentifier un utilisateur — catégorie 03

C'est la question « cette personne a-t-elle le droit, et est-ce bien son mot de
passe ». **Le mot de passe ne quitte jamais votre machine** : le core donne un
sel et un aléa, vous renvoyez un HMAC.

```go
import (
    "context"
    "time"
    sshauth "mon-service/duckynetwork/trames/t03_ssh"
)

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

answer, err := sshauth.Authenticate(ctx, client.SSH(), client.Session(),
    "alice", motDePasse)
if err != nil {
    // refusé, ou le core n'a pas répondu
    return err
}
// answer.Username   nom complet retenu par le core, domaine compris
// answer.IsAdmin     administrateur de CETTE machine
// answer.PublicKeys  clés publiques SSH du compte
```

Le contexte n'est pas optionnel. Sur certains refus — compte inexistant, révoqué,
sans droit sur la machine — le core **ne répond rien du tout**, délibérément :
répondre « refusé » ferait de la trame un moyen d'énumérer l'annuaire. Sans
délai, vous bloquez sur le cas le plus courant.

Pour ne récupérer que les clés publiques, sans vérifier de mot de passe :

```go
ch, err := client.SSH().AskUserPublicKeys(client.Session(), "alice")
```

## 7. Se déclarer dans le cluster

Un service qui ne s'enregistre pas est invisible dans `vlt cluster list`. Il faut
le faire à **chaque** connexion, reconnexions comprises : d'où `OnReady`.

```go
import (
    "context"
    "mon-service/duckynetwork/storage"
    cluster "mon-service/duckynetwork/trames/t04_cluster"
)

state := &cluster.State{}

cfg := session.Config{
    // ...
    OnReady: func(s *storage.DuckySession) error {
        if err := cluster.Register(s, cluster.Registration{
            Version:      "1.0.0",
            Endpoint:     "10.0.0.12:8080",
            Capabilities: []string{"ldap-proxy", "tls"},
        }); err != nil {
            return err
        }
        go cluster.RunHeartbeat(context.Background(), s,
            cluster.DefaultHeartbeatPeriod)
        return nil
    },
}

client, _ := session.New(cfg)
client.Spliter().Handle("04", state.Handler)
```

Sans battement de cœur, le core vous bascule hors ligne au bout de trois
minutes. `DefaultHeartbeatPeriod` vaut une minute : deux battements peuvent être
ratés avant l'alarme.

`state.NeedsRegister()` passe à vrai si le core répond qu'il ne vous connaît
plus — sa ligne a été purgée. Rejouez `Register` : l'identité, elle, reste
valable.

## 8. Sortir proprement

```go
defer func() {
    if s := client.Session(); s != nil {
        cluster.Deregister(s)
    }
}()
```

Sans cette trame, un arrêt planifié est indistinguable d'une panne pendant toute
la fenêtre de battement.

## 9. Réenrôlement automatique — à décider consciemment

`AllowReEnroll: true` fait qu'une identité refusée par le core déclenche
l'effacement des clés locales et un nouvel enrôlement.

C'est ce qu'on veut d'un service autonome dont le core a été réinstallé. C'est
exactement ce qu'on **ne** veut **pas** d'un programme qu'un administrateur vient
de révoquer : il reprendrait sa place tant que la clé d'enrôlement reste valide.

Laissé à faux (le défaut), le programme s'arrête et l'incident se voit.

## Vérification

```bash
cd ~/dev/mon-service && go build ./... && go vet ./...
```

Côté core, après le premier démarrage :

```
vlt client list        # l'identifiant attribué doit apparaître
vlt cluster list       # le service doit être « online »
vlt enroll list        # le compteur d'utilisations doit avoir bougé
```
