package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayUsersByStatus liste les sessions utilisateur ouvertes.
//
// L'expiration du jeton est affichée : c'est ce qui décide du moment où la
// session tombera, et donc la seule colonne qui permette de distinguer une
// session active d'une session qui va expirer dans la minute.
//
// La colonne MACHINE dit OÙ la session est ouverte. Sans elle, la même personne
// connectée sur trois postes donnait trois lignes identiques, et le compte
// `vaultaire` — le tunnel de chaque machine du parc — une par machine, toutes
// indiscernables. Une session, c'est « qui, et où ».
func DisplayUsersByStatus(users []storage.UserConnected) string {
	if len(users) == 0 {
		return "Aucune session utilisateur ouverte."
	}

	t := NouvelleTable("ID", "Identifiant", "Machine", "Ouverte le", "Jeton valide jusqu'à")
	for _, u := range users {
		t.Ajouter(
			fmt.Sprintf("%d", u.ID),
			Valeur(u.Username),
			Valeur(u.Machine),
			Valeur(u.CreatedAt),
			Valeur(u.TokenExpiry),
		)
	}
	return fmt.Sprintf("%d session(s) utilisateur ouverte(s)\n\n%s", len(users), t.String())
}
