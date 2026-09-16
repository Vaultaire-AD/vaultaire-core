package commanddelete

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
)

// delete_GPO_Command_Parser supprime définitivement une GPO, ses modules et ses
// liaisons de groupe.
//
// Usage : delete -gpo <nom_gpo>
//
// # Ce qui a disparu d'ici
//
// La résolution des domaines, le contrôle du droit, l'écriture et la
// vérification post-suppression : tout cela vit dans l'action gpo.delete.
//
// Le raisonnement, lui, est conservé mot pour mot dans la portée : les domaines
// sont lus AVANT la suppression, car après, la GPO n'a plus de liaison de
// groupe et le contrôle porterait sur une liste vide. Et une GPO non liée
// n'ayant aucun domaine, la suppression exige alors le droit global — faute de
// quoi n'importe quel délégué pourrait effacer une GPO en attente de
// rattachement.
func delete_GPO_Command_Parser(command_list []string, sender_groupsIDs []int, _ string, sender_Username string) string {
	if len(command_list) != 2 || command_list[0] != "-gpo" {
		return "Requête invalide. Utilisez : delete -gpo <nom_de_la_GPO>"
	}

	res, err := action.Executer("gpo.delete",
		action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs},
		action.Params{"gpo": command_list[1]})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}
