package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayUsersByGroup liste les membres d'un groupe.
func DisplayUsersByGroup(groupName string, users []storage.DisplayUsersByGroup) string {
	if len(users) == 0 {
		return fmt.Sprintf("Le groupe %s n'a aucun membre.", groupName)
	}

	t := NouvelleTable("Identifiant", "Naissance", "Session")
	for _, u := range users {
		t.Ajouter(Valeur(u.Username), Valeur(u.DateOfBirth), sessionOuverte(u.Connected))
	}
	return fmt.Sprintf("Groupe %s — %d membre(s)\n\n%s", groupName, len(users), t.String())
}

// sessionOuverte rend l'état de connexion.
//
// « ouverte / fermée » plutôt que « oui / non » : la colonne s'appelle
// « Session », et « oui » y répondrait à une question que personne n'a posée.
func sessionOuverte(connecte bool) string {
	if connecte {
		return "ouverte"
	}
	return "fermée"
}
