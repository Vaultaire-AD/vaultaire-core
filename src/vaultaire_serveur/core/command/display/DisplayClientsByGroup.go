package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayClientsByGroup liste les machines d'un groupe.
func DisplayClientsByGroup(clients []storage.GetClientsByGroup, groupName string) string {
	if len(clients) == 0 {
		return fmt.Sprintf("Le groupe %s n'a aucune machine.", groupName)
	}

	t := NouvelleTable("Identifiant machine", "Nom d'hôte", "Type", "Rôle", "OS", "RAM", "CPU", "VERSION")
	for _, c := range clients {
		t.Ajouter(
			Valeur(c.ComputeurID),
			Valeur(c.Hostname),
			Valeur(c.LogicielType),
			roleMachine(c.Serveur),
			Valeur(c.OS),
			Valeur(c.RAM),
			nombreOuTiret(c.Processeur),
			Valeur(c.AgentVersion),
		)
	}
	return fmt.Sprintf("Groupe %s — %d machine(s)\n\n%s", groupName, len(clients), t.String())
}
