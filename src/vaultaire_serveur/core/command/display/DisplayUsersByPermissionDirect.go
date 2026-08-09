package display

import (
	"fmt"
	"sort"
)

// DisplayUsersByPermissionDirect liste les comptes qui détiennent chaque
// permission.
//
// Les permissions sont triées, et les comptes de chacune aussi. L'ancienne
// version parcourait la map telle quelle : l'ordre des lignes changeait à
// chaque appel, ce qui rendait impossible de comparer deux sorties — et c'est
// précisément ce qu'on fait quand on vérifie qu'une délégation a bien été
// retirée.
func DisplayUsersByPermissionDirect(permissionsUsers map[string][]string) string {
	if len(permissionsUsers) == 0 {
		return "Aucune permission attribuée."
	}

	noms := make([]string, 0, len(permissionsUsers))
	for nom := range permissionsUsers {
		noms = append(noms, nom)
	}
	sort.Strings(noms)

	t := NouvelleTable("Permission", "Comptes", "Détenteurs")
	for _, nom := range noms {
		comptes := append([]string(nil), permissionsUsers[nom]...)
		sort.Strings(comptes)
		t.Ajouter(nom, fmt.Sprintf("%d", len(comptes)), Liste(comptes))
	}
	return fmt.Sprintf("%d permission(s) attribuée(s)\n\n%s", len(noms), t.String())
}
