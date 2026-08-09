package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplaySoftware rend la fiche d'une machine.
func DisplaySoftware(software *storage.Software) string {
	if software == nil {
		return "Machine introuvable."
	}

	f := NouvelleFiche("Machine — " + software.ComputeurID)
	f.Ajouter("Identifiant", fmt.Sprintf("%d", software.ID))
	f.Ajouter("Identifiant machine", software.ComputeurID)
	f.Ajouter("Nom d'hôte", software.Hostname)
	f.Ajouter("Type de logiciel", software.LogicielType)
	f.Ajouter("Rôle", roleMachine(software.Serveur))

	f.AjouterSection("Inventaire")
	f.Ajouter("Système", software.OS)
	f.Ajouter("Mémoire", software.RAM)
	f.Ajouter("Processeurs", nombreOuTiret(software.Processeur))

	ajouterSectionListe(f, "Groupes", software.Groups)
	ajouterSectionListe(f, "Permissions", software.Permissions)

	return f.String()
}
