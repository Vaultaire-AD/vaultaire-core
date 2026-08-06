# Utiliser le paquet

Socle Ducky Network d'un client service : enrôlement, authentification du serveur
(01) et authentification du client (02). Tout le reste se branche par-dessus.

## Le minimum qui tourne

```go
package main

import (
    "log"

    "duckynetworkclient/V1/ducky"
)

func main() {
    session, err := ducky.Start(ducky.Options{
        ConfigPath: "/etc/mon-service/config.yaml",
        KeyPath:    "/etc/mon-service/.ssh",
        Enroll:     true,
        Persistent: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("session %s ouverte", session.SessionID)

    select {} // la boucle de réception tourne dans sa goroutine
}
```

`Start` enchaîne tout seul :

```
enrôlement (01_05 → 01_08)   si aucune identité locale
connexion au premier serveur qui répond
askkey                        si la clé publique du core manque
01                            le défi qui authentifie LE SERVEUR
02                            l'authentification du programme
```

Elle ne rend la main qu'une fois le client **authentifié**, pas dès la connexion
TCP : sinon vous auriez une session qui a l'air ouverte mais que le core refusera
à la première trame utile, avec un message qui ne dira pas que le login manque.

## Configuration

Un seul fichier YAML, même format que `vaultaire_client` :

```yaml
servers:
  - ip: "10.0.0.1"
    port: 6666
  - ip: "10.0.0.2"
    port: 6666

enrollment:
  key: "la-clé-créée-sur-le-core"
  label: "proxy-preprod-01"
```

Les serveurs sont essayés dans l'ordre, le premier qui répond gagne.

La section `enrollment` n'est lue **qu'au premier démarrage**. Une fois l'identité
écrite, la clé ne sert plus et peut être retirée du fichier — la laisser garde un
secret sur le disque sans raison.

## Ce que `KeyPath` contient

| Fichier | Écrit par | Perte = |
|---------|-----------|---------|
| `client_software.yaml` | l'enrôlement | réenrôlement |
| `private_key.pem` | l'enrôlement | réenrôlement |
| `public.pem` | l'enrôlement | régénérable depuis la privée |
| `serveurpublickey.pem` | `askkey` | `askkey` au démarrage suivant |

**Ce répertoire doit survivre aux redémarrages.** Sans persistance, le service se
réenrôle à chaque lancement et consomme une utilisation de la clé d'enrôlement à
chaque fois — jusqu'à épuiser le quota et rester dehors, avec un message qui ne
dit pas que la cause est là.

## L'enrôlement, en une phrase par étape

```
01_05  →  clé d'enrôlement + clé de session TEMPORAIRE   (RSA, clé du core)
01_06  ←  identifiant attribué + type de client          (AES, clé temporaire)
01_07  →  la clé publique du service                     (AES, clé temporaire)
01_08  ←  confirmation                                   (RSA, clé du service)
01_09  ←  refus, en clair
```

**Pourquoi la clé temporaire.** Une clé publique RSA-4096 fait 1116 octets une
fois en base64 dans une trame ; une charge RSA-OAEP sur clé 4096 en accepte 446.
Elle ne peut pas voyager dans une enveloppe asymétrique, et aucun encodage n'y
change rien. La clé temporaire, elle, tient en RSA — 32 octets — et ouvre un canal
symétrique sans limite de taille.

**Ce que le service ne choisit pas** : ni son identifiant, ni son type. Le premier
est attribué, le second est porté par la clé d'enrôlement. Un service qui pourrait
annoncer son type n'aurait qu'à s'enrôler pour se donner les privilèges qu'il veut.

**La connexion d'enrôlement est jetable** : elle se ferme après `01_08`, et le
service en ouvre une neuve pour `01_01`, avec son identité cette fois.

`Enroll: false` refuse l'enrôlement automatique — le service s'arrête avec un
message clair au lieu d'aller créer une identité. C'est ce qu'on veut d'un
déploiement où l'enrôlement est un geste d'administration délibéré.

## Ajouter ses propres trames

Le Spliter aiguille sur la **catégorie**, les deux premiers chiffres du code.

```go
func gpoHandler(t storage.Trames_struct_client, s *storage.DuckySession) string {
    switch t.Message_Order[1] {
    case "01":
        return "06_02\nserveur_central\n" + t.SessionIntegritykey + "\nok"
    }
    return "" // ne rien renvoyer ne répond rien
}

func main() {
    ducky.Handle("06", gpoHandler)   // AVANT Start
    session, err := ducky.Start(opts)
    ...
}
```

### Brancher AVANT `Start`, sans exception

La boucle de réception démarre avec la connexion. Un gestionnaire branché après
coup laisse passer sans traitement les trames arrivées entre-temps — un défaut de
course, donc rare en test et fréquent en production.

### Ne bloquez pas le gestionnaire

Il s'exécute **dans la boucle de réception**. Tant qu'il n'a pas rendu la main,
aucune autre trame n'est lue. Un traitement long, ou qui attend lui-même une
réponse du core, doit rendre la main tout de suite :

```go
func handler(t storage.Trames_struct_client, s *storage.DuckySession) string {
    go traiterLonguement(t)
    return ""
}
```

### Catégories

| Code | Usage | Fourni ici |
|------|-------|------------|
| 01 | Serveur, enrôlement | oui, hors Spliter |
| 02 | Authentification du client | oui |
| 03 | SSH | non |
| 04 | Cluster | non |
| 05 | GPO | non |
| 06 | Révocation | non |
| 07 | Interface web | non |

`01` n'est pas dans le Spliter et c'est voulu : ses réponses sont lues
directement, de façon synchrone, avant que la boucle de réception ne démarre.

`Handle` accepte de remplacer une catégorie déjà branchée — un programme peut
vouloir son propre 02 — mais le journalise, parce que le faire par inadvertance
rendrait l'authentification muette sans autre symptôme.

## Ce que le paquet ne fait pas

- **le cluster** (04) : enregistrement, battement de cœur, sortie ;
- **toute catégorie autre que 01 et 02.**

## Diagnostic

| Symptôme | Cause |
|----------|-------|
| `ConfigPath est requis` | option manquante |
| `configuration … : aucun serveur déclaré` | YAML vide ou mal indenté |
| `aucune identité utilisable … et enrôlement non autorisé` | `Enroll: false` sans `client_software.yaml` |
| `aucune clé d'enrôlement dans la configuration` | section `enrollment` absente |
| `enrôlement refusé (invalid_key)` | clé inconnue, expirée, épuisée ou révoquée — le motif exact est dans le journal du **core** |
| `identité présente mais clé privée absente` | `KeyPath` partiellement effacé ; le service se réenrôle |
| `aucune session authentifiée après 30s` | core injoignable, ou clé publique enregistrée côté core ≠ celle du service |
| `catégorie XX reçue sans gestionnaire branché` | `Handle` oublié, ou appelé après `Start` |
