package userauth

import (
	"fmt"
	"os"
	"runtime"
)

// DefaultMachineInfo produit le contenu de 02_12.
//
// Quatre lignes, dans cet ordre — le core les lit par position :
//
//	hostname
//	système
//	mémoire
//	processeurs
//
// # Pourquoi une version portable et non l'inventaire de l'agent
//
// L'agent lit /proc et connaît la mémoire physique exacte ; ce dossier est
// copié dans des programmes qui tournent en conteneur, sur d'autres systèmes,
// parfois sans /proc lisible. Une implémentation qui échouerait là-bas ferait
// échouer l'authentification pour une ligne d'inventaire.
//
// Un programme qui veut mieux renseigne Manager.MachineInfo.
func DefaultMachineInfo() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	return fmt.Sprintf("%s\n%s/%s\nunknown\n%d",
		hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
}
