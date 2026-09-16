package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayAllUsers liste les comptes de l'annuaire.
//
// L'ancienne version combinait tabwriter et `%-15s`, deux mécanismes
// d'alignement incompatibles, et comptait les codes couleur dans la largeur des
// en-têtes. Voir table.go.
//
// Elle omettait aussi l'adresse électronique, pourtant présente dans les données
// et souvent le seul moyen de distinguer deux comptes homonymes de domaines
// différents.
func DisplayAllUsers(users []storage.GetUsers) string {
	if len(users) == 0 {
		return "Aucun utilisateur."
	}

	t := NouvelleTable("ID", "Identifiant", "Adresse", "Naissance", "Créé le")
	for _, u := range users {
		t.Ajouter(
			fmt.Sprintf("%d", u.ID),
			Valeur(u.Username),
			Valeur(u.Email),
			Valeur(u.DateNaissance),
			Valeur(u.CreatedAt),
		)
	}
	return fmt.Sprintf("%d utilisateur(s)\n\n%s", len(users), t.String())
}
