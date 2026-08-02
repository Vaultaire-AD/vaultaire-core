// Package commandkill expose le kill switch en ligne de commande.
//
// Trois modes, du moins au plus grave :
//
//	vlt kill -u <user>            verrouille le compte partout (réversible)
//	vlt kill -u <user> --unlock   lève le verrouillage
//	vlt kill -u <user> --hard     supprime le compte de l'annuaire ET des machines
//
// Toute la logique — contrôles RBAC, calcul des machines, écriture de l'ordre,
// poussée — vit dans ducky-network/revocation_manager. Ce paquet ne fait que
// traduire des arguments : le CLI, l'interface web et l'API doivent déclencher
// exactement le même chemin, sans quoi un durcissement posé sur l'un
// manquerait aux autres.
package commandkill

import (
	"fmt"
	"strings"

	"vaultaire/core/logs"
	"vaultaire/core/revocation"
	revocationmanager "vaultaire/ducky-network/revocation_manager"
)

// Kill_Command traite `vlt kill ...`.
func Kill_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	if len(command_list) == 0 {
		return helpText()
	}

	switch command_list[0] {
	case "-h", "help", "--help":
		return helpText()
	case "-u":
	default:
		return "Invalid Request. Try 'kill -h' for more information."
	}

	if len(command_list) < 2 || strings.TrimSpace(command_list[1]) == "" {
		return "Utilisateur cible requis. Usage : kill -u <username> [--unlock|--hard] [--reason <code>]"
	}
	targetUser := strings.TrimSpace(command_list[1])

	// Le mode par défaut est le moins destructeur. Une commande d'urgence tapée
	// à la hâte, sans option, ne doit jamais détruire quoi que ce soit.
	mode := revocation.ModeSoft
	reason := revocation.ReasonCompromised

	for i := 2; i < len(command_list); i++ {
		switch strings.ToLower(command_list[i]) {
		case "--hard":
			mode = revocation.ModeHard
		case "--unlock":
			mode = revocation.ModeUnlock
		case "--reason":
			if i+1 >= len(command_list) {
				return "Option --reason : motif manquant. Motifs acceptés : " + reasonList()
			}
			i++
			reason = revocation.Reason(strings.ToLower(strings.TrimSpace(command_list[i])))
			if !revocation.IsValidReason(reason) {
				return fmt.Sprintf("Motif inconnu %q. Motifs acceptés : %s", command_list[i], reasonList())
			}
		default:
			return fmt.Sprintf("Option inconnue %q. Try 'kill -h' for more information.", command_list[i])
		}
	}

	// Le déverrouillage n'est pas une urgence : le motif « compte compromis »
	// serait trompeur dans la trace d'audit.
	if mode == revocation.ModeUnlock && reason == revocation.ReasonCompromised {
		reason = revocation.ReasonAdminRequest
	}

	out, err := revocationmanager.Trigger(sender_Username, sender_groupsIDs, targetUser, mode, reason)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"kill: échec pour %s sur %s (%s) : %v", sender_Username, targetUser, mode, err))
		return ">> -" + err.Error()
	}

	return formatOutcome(out)
}

// formatOutcome rend le compte rendu lisible.
//
// Le nombre de machines NON jointes est affiché explicitement plutôt que déduit :
// après une révocation d'urgence, « 12 machines visées » sans savoir combien
// restent ouvertes est une information inutilisable.
func formatOutcome(out revocationmanager.Outcome) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Ordre %d — %s sur %s\n", out.OrderID, out.Mode.Label(), out.Username)
	if out.DirectoryNote != "" {
		fmt.Fprintf(&b, "  Annuaire : %s\n", out.DirectoryNote)
	}
	if out.SessionsKilled > 0 {
		fmt.Fprintf(&b, "  Sessions fermées : %d\n", out.SessionsKilled)
	}
	fmt.Fprintf(&b, "  Machines visées : %d\n", out.TargetCount)
	fmt.Fprintf(&b, "  Appliqué immédiatement : %d\n", out.PushedNow)

	remaining := out.TargetCount - out.PushedNow
	if remaining > 0 {
		fmt.Fprintf(&b, "  En attente (machines hors ligne) : %d — l'ordre sera rejoué à leur reconnexion\n", remaining)
	}
	if out.Mode == revocation.ModeSoft {
		b.WriteString("  Réversible : kill -u " + out.Username + " --unlock\n")
	}
	return b.String()
}

func reasonList() string {
	names := make([]string, 0, len(revocation.AllReasons()))
	for _, r := range revocation.AllReasons() {
		names = append(names, string(r))
	}
	return strings.Join(names, ", ")
}

func helpText() string {
	return `kill — désactivation d'urgence d'un compte (kill switch)

  kill -u <username>                     verrouille le compte partout (mode par défaut)
  kill -u <username> --unlock            lève le verrouillage
  kill -u <username> --hard              SUPPRIME le compte de l'annuaire et des machines

Options :
  --reason <code>    compromised (défaut) | offboarding | admin_request

Ce que fait le mode par défaut (soft) :
  - le compte ne peut plus s'authentifier : Ducky, SSH, LDAP, interface web, API
  - il perd toutes ses permissions RBAC
  - ses sessions ouvertes sont fermées immédiatement
  - son compte local est verrouillé sur toutes les machines partageant un de ses
    groupes ; le répertoire personnel et les données restent intacts

Le mode --hard est IRRÉVERSIBLE : le compte est supprimé de l'annuaire, et le
compte local ainsi que son répertoire personnel sont supprimés sur chaque
machine.

Les machines hors ligne ne sont pas oubliées : l'ordre est conservé et rejoué à
leur prochaine connexion.

Droits requis : write:killswitch sur tous les domaines de la cible.
Le mode --hard exige en plus write:delete:user.`
}
