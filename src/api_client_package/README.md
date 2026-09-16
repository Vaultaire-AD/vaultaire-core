# API Client Package (Vaultaire)

Petit package Go pour appeler l'API Vaultaire sans taper les commandes CLI a la main.

Ce module encapsule :
- signature de requete (cle privee SSH),
- generation du nonce,
- appel `POST /api/command`,
- fonctions pretes a l'emploi pour users/groups/permissions.

## Installation

Depuis ton autre programme Go :

```bash
go get vaultaire_api_client
```

Ou en local avec `replace` dans ton `go.mod`.

## Initialisation

```go
package main

import (
	"context"
	"fmt"
	"time"

	apiclient "vaultaire_api_client"
)

func main() {
	client, err := apiclient.NewClient(apiclient.Config{
		Server:             "https://127.0.0.1:6643",
		Username:           "alice",
		PrivateKeyPath:     "/home/alice/.vaultaire/id_rsa",
		InsecureSkipVerify: true,
		Timeout:            20 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	res, err := client.GetUsers(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}
```

## Fonctions disponibles

### Creation user/group

- `CreateUser(ctx, username, domain, password, birthdate)`
- `CreateUserWithNames(ctx, username, domain, password, birthdate, firstName, lastName)`
- `CreateGroup(ctx, groupName, domain)`

### Assignation user/group/permissions

- `AddUserToGroup(ctx, username, groupName)`
- `AddUserPermissionToGroup(ctx, groupName, permissionName)` (commande `add -gu`)
- `AddClientPermissionToGroup(ctx, groupName, permissionName)` (commande `add -gc`)

### Commandes GET users/groups

- `GetUsers(ctx)`
- `GetUser(ctx, username)`
- `GetUsersByGroup(ctx, groupName)` (commande `get -u -g`)
- `GetGroups(ctx)`
- `GetGroup(ctx, groupName)`
- `GetGroupUsers(ctx, groupName)` (commande `get -g -u`)

## Methode bas niveau

Si besoin, tu peux envoyer une commande brute :

- `Execute(ctx, "commande complete")`

Exemple :

```go
res, err := client.Execute(ctx, "get -g admins")
```

## Notes

- Le serveur valide la signature avec la cle publique de l'utilisateur.
- Si ton certificat serveur est autosigne, garde `InsecureSkipVerify: true`.
- En prod, mets `InsecureSkipVerify: false` et utilise un certificat TLS valide.
