// Package groupview rend la fiche d'un groupe après une écriture.
//
// # Pourquoi ce paquet existe
//
// Les commandes qui modifient un groupe réaffichent le groupe : l'utilisateur
// voit le résultat de son geste sans avoir à enchaîner « get -g ». Les actions
// du registre le font par leur message de retour ; les commandes GPO, qui sont
// restées hors du registre, ne l'ont pas.
//
// La fonction vivait donc en double, à l'identique, dans commandadd et
// commandremove — et les deux copies avaient déjà divergé sur le texte de leur
// journal. Elle est ici, une fois.
//
// # Pourquoi pas dans commandaction
//
// commandaction est le pont vers le registre : il ne connaît ni la base ni
// l'affichage, et c'est ce qui le garde lisible. Y verser une lecture en base
// et un rendu lui ajouterait trois dépendances pour un cas particulier qui,
// justement, ne passe pas par le registre.
package groupview

import (
	"vaultaire/core/command/display"
	"vaultaire/core/database"
	dbgroups "vaultaire/core/database/db_groups"
	"vaultaire/core/logs"
)

// Fiche charge un groupe par son nom et rend sa fiche.
//
// N'effectue AUCUN contrôle de droits : l'appelant l'a déjà fait pour
// l'écriture qu'il vient de réaliser, et il ne peut réafficher que ce qu'il
// venait de modifier. Ajouter un contrôle ici ferait deux endroits où le droit
// se décide pour un seul geste.
func Fiche(groupName string) string {
	info, err := dbgroups.Command_GET_GroupInfo(database.GetDatabase(), groupName)
	if err != nil {
		logs.Write_Log("WARNING",
			"Relecture du groupe "+groupName+" après écriture : "+err.Error())
		// L'écriture, elle, a réussi : le dire, sinon l'utilisateur conclut
		// que son opération a échoué alors qu'elle est en base.
		return "Opération effectuée. La relecture du groupe " + groupName +
			" a échoué : " + err.Error()
	}
	return display.DisplayGroupInfo(info)
}
