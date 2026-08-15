// Package commandgpo expose l'état d'application des GPO sur le parc.
//
//	vlt gpo status                 vue d'ensemble
//	vlt gpo status <computeur_id>  détail d'une machine
//	vlt gpo drift                  uniquement ce qui a dérivé
//	vlt gpo mode <gpo> <valeur>    enforce ou audit — ce qu'on fait d'un écart
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
// Porté par les actions, jamais re-vérifié ici.
//
// Les sous-commandes de lecture exigent `read:get:gpo` (gpo.list_compliance,
// gpo.get_compliance) ; la vue d'ensemble est RÉDUITE aux machines du périmètre
// de l'appelant, et le nombre d'entrées masquées est annoncé.
//
// `mode` est la seule ÉCRITURE de ce paquet et exige `write:update:gpo` sur
// chaque domaine couvert par la GPO, via gpo.set_drift_mode. Elle vit ici et non
// dans `update` parce qu'elle porte sur la conformité, c'est-à-dire sur le sujet
// de cette commande — pas sur le contenu de la GPO.
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
	case "mode":
		return reglerMode(appelant, commandList[1:])
	default:
		return "Requête invalide. Essayez « gpo -h »."
	}
}

// reglerMode traite `vlt gpo mode <nom> <enforce|audit>`.
//
// # Pourquoi la valeur est obligatoire et positionnelle
//
// Une commande qui accepterait `vlt gpo mode <nom>` seul devrait choisir entre
// afficher le mode et le régler. La lecture existe déjà — `vlt gpo status` et la
// page d'administration — donc cette forme ne servirait qu'à faire hésiter.
//
// Le contrôle de droits n'est pas ici : il est porté par l'action
// gpo.set_drift_mode, donc partagé avec le portail web. C'est la règle du
// fichier actions_gpo.go, et la raison pour laquelle les commandes ne
// re-vérifient plus rien.
func reglerMode(appelant action.Appelant, args []string) string {
	if len(args) < 2 {
		return "Usage : vlt gpo mode <nom_gpo> <enforce|audit>\n\n" +
			"  enforce  un écart est signalé PUIS corrigé au cycle suivant\n" +
			"  audit    un écart est signalé, et rien n'est corrigé\n\n" +
			"Le mode ne change pas ce que la GPO décrit, mais ce qu'elle garantit."
	}

	nom := strings.TrimSpace(args[0])
	mode := strings.TrimSpace(args[1])

	res, err := action.Executer("gpo.set_drift_mode", appelant, action.Params{
		"gpo":        nom,
		"drift_mode": mode,
	})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
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
	return rendreConformiteA(rows, driftOnly, time.Now())
}

// rendreConformiteA prend l'instant en paramètre, pour être éprouvable.
//
// La fraîcheur d'un rapport se juge par rapport à MAINTENANT. Un rendu qui
// appelle time.Now() en son sein ne se teste qu'en attendant trois heures,
// c'est-à-dire jamais.
func rendreConformiteA(rows []dbgpo.ComplianceRow, driftOnly bool, maintenant time.Time) string {
	if len(rows) == 0 {
		// Le message a changé de sens avec la vue.
		//
		// Il disait « aucun rapport reçu », parce que la liste venait des
		// rapports : zéro ligne signifiait zéro rapport. Elle vient désormais de
		// l'INVENTAIRE — zéro ligne signifie donc zéro machine enregistrée, ce
		// qui est un tout autre problème et appelle une tout autre action.
		return "Aucune machine à l'inventaire. Créez-en une avec « vlt create -c », puis\n" +
			"installez l'agent : la conformité apparaîtra dès son premier rapport."
	}

	// Les largeurs ne sont plus imposées ni les valeurs tronquées.
	//
	// `%-24s` sur un identifiant de machine supposait qu'aucun ne dépassait
	// vingt-quatre caractères ; au-delà, tronquer coupait LA FIN — c'est-à-dire
	// précisément la partie qui distingue deux machines d'un même parc. Le
	// tableau calcule maintenant chaque colonne sur son contenu réel.
	tb := display.NouvelleTable(
		"MACHINE", "SCOPE", "UTILISATEUR", "SUIVI", "APPLICATION", "MODULES", "CONFORMITÉ", "VU")

	affichées := 0
	for _, r := range rows {
		// Le filtre « écarts seulement » ne masque PAS les machines muettes.
		//
		// Une machine qui ne rapporte plus a zéro écart constaté — non parce
		// qu'elle est saine, mais parce que plus personne ne regarde. La retirer
		// d'une vue qui cherche les problèmes reviendrait à cacher le seul cas
		// où l'on ne sait rien.
		if driftOnly && !r.ARetenirDansLaVueDesEcarts(maintenant) {
			continue
		}
		affichées++
		tb.Ajouter(
			r.ComputeurID,
			orDash(r.Scope),
			orDash(r.TargetUser),
			string(r.Fraicheur(maintenant)),
			orDash(r.Status),
			r.ModulesAppliques(),
			r.EtatConformite(),
			dbgpo.AgeRelatif(r.ReportedAt, maintenant))
	}

	var b strings.Builder
	b.WriteString(tb.String())

	if affichées == 0 {
		return "Aucun écart de conformité, et aucune machine muette, sur les " +
			fmt.Sprint(len(rows)) + " ligne(s) suivie(s)."
	}

	// Le total est rappelé même en vue filtrée : « 3 machines en dérive » ne veut
	// rien dire sans savoir si le parc en compte 4 ou 4000.
	fmt.Fprintf(&b, "\n%d ligne(s) sur %d suivie(s).\n", affichées, len(rows))
	b.WriteString(dbgpo.ResumerParc(rows, maintenant).Lisible() + "\n")
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
	return rendreConformiteMachineA(d, time.Now())
}

// rendreConformiteMachineA prend l'instant en paramètre, pour la même raison que
// rendreConformiteA : la fraîcheur d'un rapport se juge par rapport à MAINTENANT.
func rendreConformiteMachineA(d action.ConformiteMachine, maintenant time.Time) string {
	if len(d.Etats) == 0 {
		return "Aucun rapport pour " + d.ComputeurID + ".\n" +
			"Soit la machine n'a jamais appliqué de politique, soit son identifiant diffère."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Machine %s\n\n", d.ComputeurID)

	for _, r := range d.Etats {
		fmt.Fprintf(&b, "  %s%s\n", r.Scope, userSuffix(r.TargetUser))
		fmt.Fprintf(&b, "    application : %s (%d module(s), %d échec(s), %d ignoré(s)) — %s\n",
			orDash(r.Status), r.ModulesTotal, r.ModulesFailed, r.ModulesSkipped, dbgpo.AgeRelatif(r.ReportedAt, maintenant))
		fmt.Fprintf(&b, "    empreinte   : %s\n", courte(r.Fingerprint))
		if r.DriftAt.Valid {
			fmt.Fprintf(&b, "    conformité  : %s — %s\n", r.EtatConformite(),
				dbgpo.AgeRelatif(r.DriftAt.Time, maintenant))
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
  drift                  machines en écart, et machines muettes
  mode <gpo> <valeur>    enforce | audit — ce qui est fait d'un écart

Le mode est porté par la GPO et hérité par ses modules : une machine qui reçoit
une GPO en audit et une autre en enforce applique la règle de chacune. Un écart
est signalé dans les deux cas ; seul le fait de le corriger change.

Trois informations distinctes :
  SUIVI        la machine parle-t-elle encore ? à jour / en retard / jamais
  APPLICATION  le dernier rapport de l'agent — la politique a-t-elle pu être posée ?
  CONFORMITÉ   le dernier scan de l'agent    — est-elle encore en place ?

« non vérifié » ne veut pas dire conforme : il veut dire que l'agent n'a pas
encore rapporté de scan, ou qu'il n'a aucun fichier inventorié.

La vue part de l'INVENTAIRE et non des rapports : une machine créée mais jamais
installée, ou dont l'agent est tombé, apparaît en « jamais » ou « en retard ».
« en retard » se déclenche après trois cycles manqués, soit trois heures — un
redémarrage ou une maintenance en coûtent un et ne remontent pas.

Le tri place devant ce dont on ne sait rien, puis les échecs, puis les écarts.`
}
