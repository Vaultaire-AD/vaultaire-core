package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayClientPermission rend la fiche d'une permission client.
func DisplayClientPermission(permission storage.ClientPermission) string {
	f := NouvelleFiche("Permission client — " + permission.Name)
	f.Ajouter("Identifiant", fmt.Sprintf("%d", permission.ID))
	f.Ajouter("Administration", OuiNon(permission.IsAdmin))

	if permission.IsAdmin {
		// La conséquence est dite, pas seulement le drapeau. « oui » ne
		// renseigne pas sur ce que ce oui emporte.
		f.AjouterSection("Ce que cette permission accorde")
		f.Ajouter("effet", "les machines du groupe qui la porte disposent des droits d'administration")
	}
	return f.String()
}
