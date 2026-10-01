//go:build !windows

package compte

import "fmt"

// Le provisionnement n'existe QUE sous Windows : c'est le seul système où ce
// module tourne. La souche existe pour que le reste du module — protocole,
// nommage des comptes, validation — se compile et se TESTE sur la machine de
// développement, qui est sous Linux.
//
// Elle échoue franchement plutôt que de ne rien faire : un provisionnement
// silencieusement sauté rendrait un « succès » à l'écran de connexion, pour une
// session que Windows refuserait ensuite d'ouvrir.
func Provisionner(utilisateur, motDePasse string, administrateur bool) (string, error) {
	_ = motDePasse
	_ = administrateur
	return "", fmt.Errorf("provisionnement de compte local : Windows uniquement (demandé pour %s)", utilisateur)
}
