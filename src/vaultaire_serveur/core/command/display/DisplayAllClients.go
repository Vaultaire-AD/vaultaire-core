package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayAllClients liste les machines du parc.
//
// Le rôle — serveur ou poste — est rendu en toutes lettres plutôt qu'en
// « true/false » : la colonne se lit d'un coup d'œil, et « false » ne dit pas
// de quoi il est la négation.
func DisplayAllClients(clients []storage.GetClientsByPermission) string {
	if len(clients) == 0 {
		return "Aucune machine."
	}

	t := NouvelleTable("ID", "Identifiant machine", "Nom d'hôte", "Type", "Rôle", "OS", "RAM", "CPU")
	for _, c := range clients {
		t.Ajouter(
			fmt.Sprintf("%d", c.ID),
			Valeur(c.ComputeurID),
			Valeur(c.Hostname),
			Valeur(c.LogicielType),
			roleMachine(c.Serveur),
			Valeur(c.OS),
			Valeur(c.RAM),
			nombreOuTiret(c.Processeur),
		)
	}
	return fmt.Sprintf("%d machine(s)\n\n%s", len(clients), t.String())
}

// roleMachine traduit le drapeau « serveur ».
func roleMachine(serveur bool) string {
	if serveur {
		return "serveur"
	}
	return "poste"
}

// nombreOuTiret distingue « zéro » de « non renseigné ».
//
// Un inventaire jamais remonté vaut 0 en base. Afficher « 0 » laisserait croire
// à une machine sans processeur ; le tiret dit que la valeur manque.
func nombreOuTiret(n int) string {
	if n <= 0 {
		return "—"
	}
	return fmt.Sprintf("%d", n)
}
