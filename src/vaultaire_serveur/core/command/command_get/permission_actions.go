package commandget

import (
	"vaultaire/core/command/display"
	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/permission"
)

// lireActionsRBAC rassemble les droits d'une permission utilisateur.
//
// # Pourquoi lire TOUTES les clés plutôt que celles présentes en base
//
// La table user_permission_action ne contient que les actions qui ont été
// réglées au moins une fois. Une permission fraîchement créée y a zéro ligne —
// ce qui ne veut pas dire qu'elle accorde tout, mais qu'elle n'accorde rien.
//
// Ne lister que les lignes présentes donnerait donc une fiche vide, impossible
// à distinguer d'un défaut de lecture. On interroge donc chaque clé connue, et
// l'absence est rendue explicitement par « refusé ».
//
// # Sur le coût
//
// Une requête par clé, soit une trentaine. C'est acceptable pour une commande
// de consultation lancée à la main ; ce serait à revoir si cette fonction
// devait servir dans une boucle, ce qui n'est pas le cas.
func lireActionsRBAC(permissionID int64) []display.ActionRBAC {
	db := database.GetDatabase()
	if db == nil {
		// nil et non une liste vide : l'affichage distingue les deux, et dire
		// « base indisponible » vaut mieux que d'afficher une permission qui
		// paraîtrait ne rien accorder.
		return nil
	}

	cles := permission.AllRBACActionKeys()
	cles = append(cles, permission.SpecialActionKeys()...)

	out := make([]display.ActionRBAC, 0, len(cles))
	for _, cle := range cles {
		valeur, err := dbpermission.Command_GET_UserPermissionAction(db, permissionID, cle)
		if err != nil {
			// Une clé jamais réglée n'a pas de ligne : l'erreur signifie
			// « absente », donc « refusée ». La traiter comme un échec de
			// lecture ferait échouer la fiche entière sur le cas le plus
			// courant.
			valeur = "nil"
		}
		out = append(out, display.ActionRBAC{Cle: cle, Valeur: valeur})
	}
	return out
}
