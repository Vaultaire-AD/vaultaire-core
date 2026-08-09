package display

import (
	"vaultaire/core/storage"
)

// DisplayUsersInfoByName rend la fiche d'un compte.
//
// Les groupes sont listés parce qu'ils SONT les droits : un utilisateur ne
// détient rien en propre. Une fiche qui les omettrait ne dirait pas ce que le
// compte peut faire.
func DisplayUsersInfoByName(user *storage.GetUserInfoSingle) string {
	if user == nil {
		return "Utilisateur introuvable."
	}

	f := NouvelleFiche("Utilisateur — " + user.Username)
	f.Ajouter("Identifiant", user.Username)
	f.Ajouter("Prénom", user.Firstname)
	f.Ajouter("Nom", user.Lastname)
	f.Ajouter("Adresse", user.Email)
	f.Ajouter("Naissance", user.DateOfBirth)
	f.Ajouter("Session ouverte", OuiNon(user.Connected))

	f.AjouterSection("Groupes")
	if len(user.Groups) == 0 {
		// Le dire explicitement : un compte sans groupe n'a AUCUN droit, ce
		// qu'une section vide ne ferait pas comprendre.
		f.Ajouter("aucun", "ce compte ne détient aucun droit")
	}
	for _, g := range user.Groups {
		f.AjouterElement(g)
	}

	return f.String()
}
