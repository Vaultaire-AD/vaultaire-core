package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayClientsByStatus liste les machines connectées.
func DisplayClientsByStatus(clients []storage.ClientConnected) string {
	if len(clients) == 0 {
		return "Aucune machine connectée."
	}

	t := NouvelleTable("Identifiant machine", "Nom d'hôte", "Type", "Rôle", "OS", "RAM", "CPU")
	for _, c := range clients {
		t.Ajouter(
			Valeur(c.ComputeurID),
			Valeur(c.Hostname),
			Valeur(c.LogicielType),
			roleMachine(c.Serveur),
			Valeur(c.OS),
			Valeur(c.RAM),
			nombreOuTiret(c.Processeur),
		)
	}
	return fmt.Sprintf("%d machine(s) connectée(s)\n\n%s", len(clients), t.String())
}
