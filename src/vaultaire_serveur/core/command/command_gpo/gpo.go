// Package commandgpo expose l'état d'application des GPO sur le parc.
//
//	vlt gpo status                 vue d'ensemble
//	vlt gpo status <computeur_id>  détail d'une machine
//	vlt gpo drift                  uniquement ce qui a dérivé
//
// # Pourquoi cette commande existe
//
// Avant elle, le serveur savait ce qu'il avait DEMANDÉ et rien de plus. Les
// rapports d'application des agents étaient journalisés puis oubliés : pour
// savoir si une politique était réellement en place sur une machine, il fallait
// aller lire le journal, en connaître le format, et espérer qu'il n'ait pas
// tourné. Autant dire que personne ne le faisait.
//
// # Deux questions distinctes, deux colonnes
//
//	APPLICATION — le dernier rapport 05_12 : la politique a-t-elle pu être posée ?
//	CONFORMITÉ  — le dernier scan 05_15    : est-elle encore en place aujourd'hui ?
//
// Une machine peut être « applied » et en dérive : elle a bien reçu la
// politique, et quelqu'un a édité les fichiers depuis. Fusionner les deux
// colonnes ferait disparaître exactement ce cas, qui est le seul que la
// détection de dérive existe pour montrer.
package commandgpo

import (
	"fmt"
	"strings"
	"time"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	dbgpo "vaultaire/core/database/db_gpo"
)

// GPO_Command traite `vlt gpo ...`.
//
// # Contrôle d'accès
//
// Lecture seule, donc `read:get:gpo`, porté par les actions gpo.list_compliance
// et gpo.get_compliance. La vue d'ensemble est RÉDUITE aux machines du
// périmètre de l'appelant, et le nombre d'entrées masquées est annoncé.
func GPO_Command(commandList []string, senderGroupIDs []int, senderUsername string) string {
	if len(commandList) == 0 {
		return helpText()
	}

	sub := strings.ToLower(commandList[0])
	if sub == "-h" || sub == "--help" || sub == "help" {
		return helpText()
	}

	// Le contrôle sur « * » a disparu.
	//
	// Il exigeait le droit GLOBAL, avec ce motif : « un rapport filtré par
	// domaine donnerait une vue partielle présentée comme complète — pire
	// qu'un refus ». Le raisonnement tenait tant qu'aucun filtre ne pouvait le
	// dire ; le registre annonce désormais le nombre d'entrées masquées.
	//
	// Une vue partielle qui S'ANNONCE partielle vaut mieux qu'un refus : le
	// délégué voyait auparavant zéro machine, la sienne comprise.
	appelant := action.Appelant{Username: senderUsername, GroupIDs: senderGroupIDs}

	switch sub {
	case "status":
		if len(commandList) > 1 {
			return conformiteMachine(appelant, strings.TrimSpace(commandList[1]))
		}
		return conformiteParc(appelant, false)
	case "drift":
		return conformiteParc(appelant, true)
	default:
		return "Requête invalide. Essayez « gpo -h »."
	}
}

// conformiteParc rend la vue d'ensemble, filtrée au périmètre.
//
// driftOnly restreint aux machines en écart : sur un parc conforme, la commande
// répond alors « rien à signaler », ce qui est l'information utile.
func conformiteParc(appelant action.Appelant, driftOnly bool) string {
	res, err := action.Executer("gpo.list_compliance", appelant, action.Params{})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	rows, _ := res.Donnees.([]dbgpo.ComplianceRow)
	return res.Message + "\n\n" + rendreConformite(rows, driftOnly)
}

// conformiteMachine rend le détail d'une machine.
func conformiteMachine(appelant action.Appelant, computeurID string) string {
	if computeurID == "" {
		return "Identifiant de machine manquant."
	}
	res, err := action.Executer("gpo.get_compliance", appelant,
		action.Params{"computeur_id": computeurID})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	d, ok := res.Donnees.(action.ConformiteMachine)
	if !ok {
		return res.Message
	}
	return rendreConformiteMachine(d)
}

// rendreConformite met en forme la vue d'ensemble.
//
// Ne lit plus la base et ne contrôle plus rien : l'action a fait les deux, et
// les lignes reçues sont DÉJÀ réduites au périmètre de l'appelant.
func rendreConformite(rows []dbgpo.ComplianceRow, driftOnly bool) string {
	if len(rows) == 0 {
		return "Aucun rapport reçu. Les agents rapportent après application ; si le parc\n" +
			"est actif depuis plus d'un cycle, vérifiez le journal côté serveur."
	}

	// Les largeurs ne sont plus imposées ni les valeurs tronquées.
	//
	// `%-24s` sur un identifiant de machine supposait qu'aucun ne dépassait
	// vingt-quatre caractères ; au-delà, tronquer coupait LA FIN — c'est-à-dire
	// précisément la partie qui distingue deux machines d'un même parc. Le
	// tableau calcule maintenant chaque colonne sur son contenu réel.
	tb := display.NouvelleTable(
		"MACHINE", "SCOPE", "UTILISATEUR", "APPLICATION", "MODULES", "CONFORMITÉ", "VU")

	affichées := 0
	for _, r := range rows {
		if driftOnly && r.DriftCount == 0 {
			continue
		}
		affichées++
		tb.Ajouter(
			r.ComputeurID,
			r.Scope,
			orDash(r.TargetUser),
			orDash(r.Status),
			fmt.Sprintf("%d/%d", r.ModulesTotal-r.ModulesFailed, r.ModulesTotal),
			conformitéTexte(r),
			âge(r.ReportedAt))
	}

	var b strings.Builder
	b.WriteString(tb.String())

	if affichées == 0 {
		return "Aucun écart de conformité sur les " + fmt.Sprint(len(rows)) + " scope(s) suivi(s)."
	}

	// Le total est rappelé même en vue filtrée : « 3 machines en dérive » ne veut
	// rien dire sans savoir si le parc en compte 4 ou 4000.
	fmt.Fprintf(&b, "\n%d ligne(s) sur %d scope(s) suivi(s).\n", affichées, len(rows))
	fmt.Fprintf(&b, "Détail d'une machine : vlt gpo status <computeur_id>\n")
	return b.String()
}

// rendreConformiteMachine met en forme le détail d'une machine.
//
// Les trois lectures — état par portée, modules en échec, écarts — sont faites
// par l'action, qui signale séparément celles qui ont échoué. Refuser toute la
// fiche parce que le détail des modules manque priverait de la réponse
// principale : « cette machine est-elle conforme ».
func rendreConformiteMachine(d action.ConformiteMachine) string {
	if len(d.Etats) == 0 {
		return "Aucun rapport pour " + d.ComputeurID + ".\n" +
			"Soit la machine n'a jamais appliqué de politique, soit son identifiant diffère."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Machine %s\n\n", d.ComputeurID)

	for _, r := range d.Etats {
		fmt.Fprintf(&b, "  %s%s\n", r.Scope, userSuffix(r.TargetUser))
		fmt.Fprintf(&b, "    application : %s (%d module(s), %d échec(s), %d ignoré(s)) — %s\n",
			orDash(r.Status), r.ModulesTotal, r.ModulesFailed, r.ModulesSkipped, âge(r.ReportedAt))
		fmt.Fprintf(&b, "    empreinte   : %s\n", courte(r.Fingerprint))
		if r.DriftAt.Valid {
			fmt.Fprintf(&b, "    conformité  : %s — %s\n", conformitéTexte(r), âge(r.DriftAt.Time))
		} else {
			// Distinguer « conforme » de « jamais vérifié » : afficher un tiret
			// plutôt qu'un zéro rassurant.
			fmt.Fprintf(&b, "    conformité  : jamais vérifiée\n")
		}
	}

	if d.ModulesIllisibles != "" {
		b.WriteString("\n  Détail des modules illisible : " + d.ModulesIllisibles + "\n")
	} else if len(d.Echecs) > 0 {
		b.WriteString("\n  Modules en échec\n")
		te := display.NouvelleTable("SCOPE", "CLÉ", "DÉTAIL")
		for _, m := range d.Echecs {
			te.Ajouter(m.Scope, m.StateKey, unLigne(m.Detail))
		}
		b.WriteString(indenter(te.String(), "    "))
	}

	if d.EcartsIllisibles != "" {
		b.WriteString("\n  Écarts illisibles : " + d.EcartsIllisibles + "\n")
	} else if len(d.Ecarts) > 0 {
		b.WriteString("\n  Écarts constatés\n")
		td := display.NouvelleTable("NATURE", "CHEMIN", "DÉTAIL")
		for _, e := range d.Ecarts {
			// Le chemin n'est pas tronqué : c'est la fin d'un chemin qui dit de
			// quel fichier il s'agit.
			td.Ajouter(e.Kind, e.Path, unLigne(e.Detail))
		}
		b.WriteString(indenter(td.String(), "    "))
	}

	return b.String()
}

// conformitéTexte rend l'état de conformité en une cellule.
func conformitéTexte(r dbgpo.ComplianceRow) string {
	if !r.DriftAt.Valid {
		return "non vérifié"
	}
	if r.DriftCount == 0 {
		return fmt.Sprintf("ok (%d)", r.DriftChecked)
	}
	return fmt.Sprintf("%d écart(s)", r.DriftCount)
}

// âge rend une date en durée relative.
//
// Un horodatage absolu oblige à faire la soustraction de tête, et c'est
// précisément ce qu'on veut savoir : est-ce que cette machine rapporte encore ?
func âge(t time.Time) string {
	if t.IsZero() {
		return "jamais"
	}
	d := time.Since(t.UTC())
	switch {
	case d < time.Minute:
		return "à l'instant"
	case d < time.Hour:
		return fmt.Sprintf("il y a %dmin", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("il y a %dh", int(d.Hours()))
	default:
		return fmt.Sprintf("il y a %dj", int(d.Hours()/24))
	}
}

func userSuffix(username string) string {
	if username == "" {
		return ""
	}
	return " (" + username + ")"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func courte(fingerprint string) string {
	if len(fingerprint) <= 16 {
		return orDash(fingerprint)
	}
	return fingerprint[:16] + "…"
}

// indenter décale un bloc déjà rendu, ligne à ligne.
//
// Le module d'affichage produit un tableau aligné sur sa propre marge ; ces
// tableaux-ci sont imbriqués sous un intertitre. Préfixer chaque ligne
// conserve l'alignement interne du tableau tout en le rattachant visuellement
// à sa section.
func indenter(bloc, marge string) string {
	var sb strings.Builder
	for _, l := range strings.Split(strings.TrimRight(bloc, "\n"), "\n") {
		sb.WriteString(marge + l + "\n")
	}
	return sb.String()
}

// unLigne aplatit un détail multi-ligne.
//
// Un message d'erreur d'applier peut contenir la sortie d'une commande système,
// sauts de ligne compris. Le laisser tel quel casserait l'alignement du tableau
// et rendrait les lignes suivantes illisibles.
func unLigne(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:79] + "…"
	}
	return s
}

func helpText() string {
	return `Utilisation : vlt gpo <sous-commande>

  status                 état d'application et de conformité du parc
  status <computeur_id>  détail d'une machine : modules en échec, écarts
  drift                  uniquement les machines en écart

Deux informations distinctes :
  APPLICATION  le dernier rapport de l'agent — la politique a-t-elle pu être posée ?
  CONFORMITÉ   le dernier scan de l'agent    — est-elle encore en place ?

« non vérifié » ne veut pas dire conforme : il veut dire que l'agent n'a pas
encore rapporté de scan, ou qu'il n'a aucun fichier inventorié.`
}
