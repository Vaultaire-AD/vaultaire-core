package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayAllUserPermissions liste les permissions utilisateur.
//
// La colonne « admin web » est mise en avant : c'est le seul réglage de cette
// liste qui donne un pouvoir, et le repérer d'un coup d'œil est précisément ce
// qu'on cherche en ouvrant cette page.
//
// Le détail des droits RBAC n'y figure pas — une trentaine de clés par ligne
// serait illisible. « get -p -u <nom> » les affiche.
func DisplayAllUserPermissions(permissions []storage.UserPermission) string {
	if len(permissions) == 0 {
		return "Aucune permission utilisateur."
	}

	t := NouvelleTable("ID", "Nom", "Admin web", "Description")
	for _, p := range permissions {
		t.Ajouter(
			fmt.Sprintf("%d", p.ID),
			Valeur(p.Name),
			lisibleValeurAction(p.Web_admin),
			Valeur(p.Description),
		)
	}
	return fmt.Sprintf("%d permission(s) utilisateur\n\nDétail d'une permission : get -p -u <nom>\n\n%s",
		len(permissions), t.String())
}
