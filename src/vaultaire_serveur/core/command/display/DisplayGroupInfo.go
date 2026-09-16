package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayGroupInfo rend la fiche d'un groupe.
//
// Un groupe rassemble cinq choses de natures différentes — membres, machines,
// permissions utilisateur, permissions client, GPO — et les mélanger dans une
// liste unique rendrait la fiche illisible. D'où les sections.
//
// Chacune annonce son effectif : « Membres (0) » se distingue d'une section
// dont l'affichage aurait échoué.
func DisplayGroupInfo(group *storage.GroupInfo) string {
	if group == nil {
		return "Groupe introuvable."
	}

	f := NouvelleFiche("Groupe — " + group.Name)
	f.Ajouter("Identifiant", fmt.Sprintf("%d", group.ID))
	f.Ajouter("Domaine", group.DomainName)

	ajouterSectionListe(f, "Membres", group.Users)
	ajouterSectionListe(f, "Machines", group.Clients)
	ajouterSectionListe(f, "Permissions utilisateur", group.Permissions)
	ajouterSectionListe(f, "Permissions client", group.ClientPerms)
	ajouterSectionListe(f, "GPO liées", group.GPOs)

	return f.String()
}

// ajouterSectionListe ajoute une section et ses éléments, un par ligne.
//
// Un par ligne plutôt qu'une énumération sur une ligne : les noms de groupes et
// de permissions sont longs, et une ligne de deux cents caractères se replie
// dans le terminal en perdant tout alignement.
func ajouterSectionListe(f *Fiche, titre string, elements []string) {
	f.AjouterSection(fmt.Sprintf("%s (%d)", titre, len(elements)))
	if len(elements) == 0 {
		f.AjouterElement("aucun")
		return
	}
	for _, e := range elements {
		f.AjouterElement(e)
	}
}
