package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayGroupDetails liste les groupes et leurs effectifs.
//
// Les quatre compteurs disent d'un coup d'œil ce que porte chaque groupe : un
// groupe à zéro permission n'accorde rien à ses membres, un groupe à zéro
// membre n'accorde rien à personne. Les deux cas se repèrent ici sans ouvrir
// chaque fiche.
func DisplayGroupDetails(groupDetails []storage.GroupDetails) string {
	if len(groupDetails) == 0 {
		return "Aucun groupe."
	}

	t := NouvelleTable("Groupe", "Domaine", "Membres", "Machines", "Perms. utilisateur", "Perms. client")
	for _, g := range groupDetails {
		t.Ajouter(
			Valeur(g.GroupName),
			Valeur(g.DomainName),
			fmt.Sprintf("%d", g.UserCount),
			fmt.Sprintf("%d", g.ClientCount),
			fmt.Sprintf("%d", g.UserPermissionCount),
			fmt.Sprintf("%d", g.LogicielPermissionCount),
		)
	}
	return fmt.Sprintf("%d groupe(s)\n\n%s", len(groupDetails), t.String())
}
