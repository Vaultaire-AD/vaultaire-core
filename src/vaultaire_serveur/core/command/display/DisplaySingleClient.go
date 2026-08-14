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

	// Les VERSIONS, dans l'inventaire : elles décrivent ce qui tourne, au même
	// titre que le système et la mémoire.
	//
	// « inconnue » et non un tiret : un tiret se lit comme « rien à dire »,
	// alors que l'absence de version DIT quelque chose — un agent d'une version
	// antérieure, ou une machine créée et jamais connectée. C'est précisément ce
	// qu'on cherche avant un déploiement.
	f.Ajouter("Version de l'agent", versionOuInconnue(software.AgentVersion))
	f.Ajouter("Version du SDK", versionOuInconnue(software.SDKVersion))

	ajouterSectionListe(f, "Groupes", software.Groups)
	ajouterSectionListe(f, "Permissions", software.Permissions)

	return f.String()
}

// versionOuInconnue rend « inconnue » plutôt qu'un vide.
//
// Une case vide se lit comme un oubli d'affichage. « inconnue » dit que la
// machine ne l'a jamais déclarée — ce qui est une information, et non une
// absence d'information.
func versionOuInconnue(v string) string {
	if v == "" {
		return "inconnue"
	}
	return v
}
