package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayAllClientPermissions liste les permissions des machines.
//
// « admin » signale ici que les machines du groupe porteur disposent des droits
// d'administration. Le privilège s'exerce sans qu'aucun humain soit identifié
// derrière : il mérite d'être visible dans la liste, pas seulement dans le
// détail.
func DisplayAllClientPermissions(permissions []storage.ClientPermission) string {
	if len(permissions) == 0 {
		return "Aucune permission client."
	}

	t := NouvelleTable("ID", "Nom", "Administration")
	for _, p := range permissions {
		t.Ajouter(
			fmt.Sprintf("%d", p.ID),
			Valeur(p.Name),
			OuiNon(p.IsAdmin),
		)
	}
	return fmt.Sprintf("%d permission(s) client\n\n%s", len(permissions), t.String())
}
