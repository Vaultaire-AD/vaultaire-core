// Package commandkill expose le kill switch en ligne de commande.
//
// Trois modes, du moins au plus grave :
//
//	vlt kill -u <user>            verrouille le compte partout (réversible)
//	vlt kill -u <user> --unlock   lève le verrouillage
//	vlt kill -u <user> --hard     supprime le compte de l'annuaire ET des machines
//
// Et une lecture, qui ne déclenche rien :
//
//	vlt kill -u <user> --status   où en est l'ordre, machine par machine
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

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	dbrevocation "vaultaire/core/database/db_revocation"
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
	// suivi : --status demande une LECTURE. Les autres options le rendent
	// ambigu — voir plus bas.
	suivi, autres := false, []string{}

	for i := 2; i < len(command_list); i++ {
		if opt := strings.ToLower(command_list[i]); opt == "--status" {
			suivi = true
			continue
		} else if strings.HasPrefix(opt, "--") {
			autres = append(autres, opt)
		}
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

	if suivi {
		// --status ne se combine avec RIEN. « kill -u bob --hard --status »
		// pourrait se lire « dis-moi où en est la suppression » comme
		// « supprime, puis dis-moi » : sur la commande la plus destructrice du
		// produit, une lecture qui déclenche par malentendu ne se rattrape
		// pas. On refuse, et on dit pourquoi.
		if len(autres) > 0 {
			return fmt.Sprintf("--status est une lecture et ne se combine pas avec %s : rien n'a été déclenché.\n"+
				"Usage : kill -u %s --status", strings.Join(autres, ", "), targetUser)
		}
		return suiviDUnCompte(action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs}, targetUser)
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
	// « Sessions Vaultaire », et non « sessions » : ce compteur n'a jamais
	// compté un `ssh`. Il disait « Sessions fermées : 2 » pendant que la
	// personne continuait de travailler dans son terminal (TO-DO 133).
	if out.SessionsKilled > 0 {
		fmt.Fprintf(&b, "  Sessions Vaultaire fermées (portail, Ducky) : %d\n", out.SessionsKilled)
	}
	fmt.Fprintf(&b, "  Machines visées : %d", out.TargetCount)
	if out.MachinesEnSession > 0 {
		fmt.Fprintf(&b, " — dont %d où une session du compte est ouverte", out.MachinesEnSession)
	}
	b.WriteString("\n")
	if out.HorsGroupes > 0 {
		fmt.Fprintf(&b, "    (%d visée(s) pour cette seule raison : le compte n'y partage plus aucun groupe)\n",
			out.HorsGroupes)
	}
	// « Remis », et non « appliqué » : c'est ce que le core SAIT à cet instant.
	// L'application — verrouiller, puis couper ce qui est ouvert — est le fait
	// de l'agent, qui l'acquitte ensuite. L'acquittement de chaque machine, ou
	// son échec, se lit avec « kill -u <compte> --status » (TO-DO 164).
	fmt.Fprintf(&b, "  Ordre remis immédiatement : %d machine(s) en ligne\n", out.PushedNow)
	if out.Mode != revocation.ModeUnlock && out.PushedNow > 0 {
		b.WriteString("    chacune verrouille le compte local, puis ferme ses sessions et tue ses processus ;\n")
		b.WriteString("    son acquittement — ou son échec — se lit avec « kill -u " + out.Username + " --status » ;\n")
		b.WriteString("    un ordre en échec ou resté sans réponse est rejoué par le core, de plus en plus espacé\n")
	}

	remaining := out.TargetCount - out.PushedNow
	if remaining > 0 {
		fmt.Fprintf(&b, "  En attente (machines hors ligne) : %d — l'ordre leur sera remis dès leur retour\n", remaining)
	}
	if out.Mode == revocation.ModeSoft {
		b.WriteString("  Réversible : kill -u " + out.Username + " --unlock\n")
	}
	return b.String()
}

// suiviDUnCompte rend où en est la révocation d'un compte, machine par
// machine — TO-DO 164. La lecture, son contrôle de droits et la réduction au
// périmètre de l'appelant sont le fait de l'action ; ici, on met en forme.
func suiviDUnCompte(appelant action.Appelant, compte string) string {
	res, err := action.Executer("revocation.get_status", appelant, action.Params{"username": compte})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	suivi, ok := res.Donnees.(dbrevocation.Suivi)
	if !ok {
		return res.Message
	}
	return rendreSuivi(suivi, res.Message)
}

// rendreSuivi met en forme un suivi. Le tri, les libellés, le décompte et le
// commentaire de chaque cible viennent de db_revocation : la fiche du compte
// du portail emprunte les mêmes fonctions.
func rendreSuivi(suivi dbrevocation.Suivi, message string) string {
	if len(suivi.Ordres) == 0 {
		return message
	}
	var b strings.Builder

	etat := "aucun verrouillage en vigueur"
	if suivi.Verrouille {
		etat = "VERROUILLÉ"
	}
	fmt.Fprintf(&b, "Compte %s — %s\n", suivi.Username, etat)

	for i, o := range suivi.Ordres {
		fmt.Fprintf(&b, "\nOrdre %d — %s (%s), par %s le %s\n",
			o.ID, o.Mode.Label(), o.Reason.Label(), o.IssuedBy, o.IssuedAt.Format("2006-01-02 15:04:05"))
		if o.LiftedBy != "" {
			fmt.Fprintf(&b, "  Levé par %s\n", o.LiftedBy)
		}

		decompte := dbrevocation.Compter(o.Cibles)
		fmt.Fprintf(&b, "  %s\n", decompte.Lisible())
		if o.Masquees > 0 {
			fmt.Fprintf(&b, "  %d autre(s) machine(s) visée(s) sont hors de votre périmètre et ne sont pas montrées.\n", o.Masquees)
		}
		// Le tableau, pour l'ordre le plus récent et pour tout ordre qui n'est
		// pas réglé. Un ordre ancien et réglé tient en une ligne : cinq
		// tableaux de machines « appliqué » repousseraient hors de l'écran la
		// seule ligne qu'on cherche. Le portail les replie pour la même raison.
		if len(o.Cibles) == 0 || (i > 0 && decompte.ResteAFaire() == 0) {
			continue
		}

		tb := display.NouvelleTable("MACHINE", "ÉTAT", "REMISES", "DERNIER ÉCHANGE", "DÉTAIL")
		for _, c := range o.Cibles {
			tb.Ajouter(c.ComputeurID, c.Status.Libelle(), fmt.Sprint(c.Attempts), c.Echange(), unLigne(c.Commentaire()))
		}
		for _, ligne := range strings.Split(strings.TrimRight(tb.String(), "\n"), "\n") {
			b.WriteString("  " + ligne + "\n")
		}
	}

	if suivi.PlusAnciens > 0 {
		fmt.Fprintf(&b, "\n%d ordre(s) plus ancien(s) ne sont pas détaillés.\n", suivi.PlusAnciens)
	}

	// La phrase qui répond à la question posée pendant un incident : sur
	// l'ordre le plus récent, reste-t-il une machine où le compte n'est pas
	// coupé ?
	dernier := suivi.Ordres[0]
	if reste := dbrevocation.Compter(dernier.Cibles).ResteAFaire(); reste > 0 {
		fmt.Fprintf(&b, "\nL'ordre %d n'est PAS appliqué sur %d machine(s) : le core le leur remet de lui-même, "+
			"de plus en plus espacé, sans renoncer.\n", dernier.ID, reste)
	} else if dernier.Masquees == 0 {
		fmt.Fprintf(&b, "\nL'ordre %d est réglé sur toutes les machines visées.\n", dernier.ID)
	}
	return b.String()
}

// unLigne ramène un détail venu d'une machine à une ligne : il est écrit par
// l'agent, et un retour à la ligne y casserait le tableau.
func unLigne(s string) string {
	return strings.Join(strings.Fields(s), " ")
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
  kill -u <username> --status            où en est l'ordre, machine par machine (lecture)

Options :
  --reason <code>    compromised (défaut) | offboarding | admin_request

Ce que fait le mode par défaut (soft) :
  - le compte ne peut plus s'authentifier : Ducky, SSH, LDAP, interface web, API
  - il perd toutes ses permissions RBAC
  - ses sessions Vaultaire (portail, Ducky) sont fermées immédiatement
  - sur chaque machine jointe, son compte local est verrouillé, PUIS tout ce
    qu'il y a d'ouvert est coupé : sessions SSH, console et bureau, mais aussi
    ce qui tourne détaché d'un terminal (tmux, nohup, tâches planifiées). Le
    répertoire personnel et les données restent intacts
  - les machines visées sont celles qui partagent un de ses groupes, ET celles
    où il a une session ouverte

Ce qu'il ne fait pas tout de suite : une machine HORS LIGNE garde le compte et
ses sessions jusqu'à sa reconnexion, où l'ordre est rejoué. Tant que la ligne
« En attente » du compte rendu n'est pas à zéro, le compte travaille peut-être
encore quelque part.

Le mode --hard est IRRÉVERSIBLE : le compte est supprimé de l'annuaire, et le
compte local ainsi que son répertoire personnel sont supprimés sur chaque
machine.

Les machines hors ligne ne sont pas oubliées : l'ordre est conservé, et leur est
remis dans les secondes qui suivent leur retour. Un ordre qui n'a pas abouti du
premier coup — envoi perdu, processus qui refusent de mourir — est rejoué par le
core : dix secondes plus tard, puis de plus en plus espacé, jusqu'à cinq minutes,
sans jamais renoncer. De son côté, un agent redemande ses ordres en attente
toutes les dix minutes.

Lever un verrouillage (--unlock) le retire aussi des machines qui ne l'avaient
pas encore appliqué : elles ne recevront que la levée.

Savoir où en est un ordre : « kill -u <username> --status ». Chaque machine
visée y a son état — appliqué, en échec avec le motif rendu par la machine, en
attente, ou levé avant application —, le nombre de fois où l'ordre lui a été
remis, et le temps écoulé depuis le dernier échange. Ce qui n'est pas réglé est
en tête. --status ne déclenche rien, et ne se combine avec aucune autre option.

Droits requis : write:killswitch sur tous les domaines de la cible.
Le mode --hard exige en plus write:delete:user.
--status demande read:status:user sur un domaine de la cible, et ne montre que
les machines de votre périmètre.`
}
