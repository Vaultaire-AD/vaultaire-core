package commanddelete

import (
	"fmt"

	"vaultaire/core/logs"
	"vaultaire/core/revocation"
	revocationmanager "vaultaire/ducky-network/revocation_manager"
)

// delete_users_Command_Parser supprime un utilisateur, partout.
//
// Format attendu : ["-u", "username"]
//
// LA SUPPRESSION PASSE PAR LE KILL SWITCH, en mode hard. Auparavant cette
// commande retirait le compte de l'annuaire et s'arrêtait là : le compte local
// restait vivant sur chaque machine où l'utilisateur s'était connecté, avec son
// mot de passe toujours dans /etc/shadow, écrit par le module PAM. Le compte
// survivait donc à sa propre suppression, et rien dans l'interface ne le
// laissait deviner.
//
// Déléguer à revocationmanager.Trigger apporte, en plus de la propagation :
//
//   - la liste des machines cibles calculée AVANT la suppression, sans quoi
//     l'appartenance aux groupes disparaîtrait avec le compte ;
//   - un ordre durable, rejoué aux machines hors ligne à leur reconnexion ;
//   - la fermeture immédiate des sessions ouvertes ;
//   - une trace d'audit qui survit au compte supprimé.
//
// Les contrôles RBAC sont faits par Trigger : write:killswitch ET
// write:delete:user, tous deux sur l'ensemble des domaines de la cible. La
// suppression reste donc au moins aussi difficile qu'avant.
func delete_users_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 2 || command_list[0] != "-u" {
		return "Invalid request. Try 'delete -h' for more information."
	}
	username := command_list[1]

	out, err := revocationmanager.Trigger(sender_Username, sender_groupsIDs, username,
		revocation.ModeHard, revocation.ReasonOffboarding)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"delete -u refusé : %s sur %s — %v", sender_Username, username, err))
		return ">> -" + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"Utilisateur %s supprimé par %s (ordre de révocation %d, %d machine(s) visée(s))",
		username, sender_Username, out.OrderID, out.TargetCount))

	msg := fmt.Sprintf("Utilisateur %s supprimé (ordre %d).\n", username, out.OrderID)
	msg += fmt.Sprintf("  Machines visées : %d, nettoyées immédiatement : %d\n",
		out.TargetCount, out.PushedNow)
	if remaining := out.TargetCount - out.PushedNow; remaining > 0 {
		msg += fmt.Sprintf("  %d machine(s) hors ligne : le compte local y sera supprimé à leur reconnexion\n", remaining)
	}
	return msg
}
