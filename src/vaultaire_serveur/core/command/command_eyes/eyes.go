package commandeyes

// Eyes_Command affiche l'annuaire sous forme d'arborescence.
//
// La clé « write:eyes » qui voyageait ici a disparu : la commande ne fait que
// lire, et l'action domain.list_tree exige `read:get:group` — le même droit
// que `get -g`, dont elle n'est qu'une autre présentation.
func Eyes_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	if len(command_list) == 0 {
		return aide()
	}
	switch command_list[0] {
	case "-h", "help", "--help":
		return aide()
	case "-g":
		return eyes_by_domain(command_list, sender_groupsIDs, "", sender_Username)
	default:
		return "Requête invalide. Essayez « eyes -h »."
	}
}

func aide() string {
	return `eyes — l'annuaire en arborescence.

  eyes -g              domaines et leurs groupes
  eyes -g <domaine>    groupes situés sous un domaine

L'arborescence est réduite à votre périmètre : les domaines dont vous
n'administrez aucun groupe n'y figurent pas. Le décompte des entrées masquées
est indiqué au-dessus de l'arbre.`
}
