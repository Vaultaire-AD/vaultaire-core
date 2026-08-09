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

	"vaultaire/core/command/display"
	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// GPO_Command traite `vlt gpo ...`.
//
// # Contrôle d'accès
//
// Lecture seule, donc `read:get:gpo`. Le droit est exigé sur « * » : l'état de
// conformité couvre tout le parc, et un rapport filtré par domaine donnerait une
// vue partielle présentée comme complète — pire qu'un refus.
func GPO_Command(commandList []string, senderGroupIDs []int, senderUsername string) string {
	if len(commandList) == 0 {
		return helpText()
	}

	sub := strings.ToLower(commandList[0])
	if sub == "-h" || sub == "--help" || sub == "help" {
		return helpText()
	}

	const actionKey = "read:get:gpo"
	ok, reason := permission.CheckPermissionsMultipleDomains(senderGroupIDs, actionKey, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"Permission refused: user=%s action=%s (gpo %s) reason=%s",
			senderUsername, actionKey, sub, reason))
		return "Permission refusée : " + reason
	}
	logs.Write_Log("INFO", fmt.Sprintf(
		"Permission used: user=%s action=%s (gpo %s)", senderUsername, actionKey, sub))

	switch sub {
	case "status":
		if len(commandList) > 1 {
			return statusForClient(strings.TrimSpace(commandList[1]))
		}
		return statusOverview(false)
	case "drift":
		return statusOverview(true)
	default:
		return "Requête invalide. Essayez 'gpo -h'."
	}
}

// statusOverview affiche une ligne par scope suivi.
//
// driftOnly restreint aux machines en écart : sur un parc conforme, la commande
// répond alors « rien à signaler », ce qui est l'information utile.
func statusOverview(driftOnly bool) string {
	rows, err := dbgpo.ListCompliance(database.GetDatabase())
	if err != nil {
		return "Lecture impossible : " + err.Error()
	}
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

// statusForClient détaille une machine : modules en échec, puis écarts.
func statusForClient(computeurID string) string {
	if computeurID == "" {
		return "Identifiant de machine manquant."
	}
	db := database.GetDatabase()

	rows, err := dbgpo.GetComplianceForClient(db, computeurID)
	if err != nil {
		return "Lecture impossible : " + err.Error()
	}
	if len(rows) == 0 {
		return "Aucun rapport pour " + computeurID + ".\n" +
			"Soit la machine n'a jamais appliqué de politique, soit son identifiant diffère."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Machine %s\n\n", computeurID)

	for _, r := range rows {
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

	modules, err := dbgpo.GetModuleReports(db, computeurID)
	if err != nil {
		return b.String() + "\nDétail des modules illisible : " + err.Error()
	}
	var échecs []dbgpo.ModuleReportRow
	for _, m := range modules {
		if m.Result == "failed" {
			échecs = append(échecs, m)
		}
	}
	if len(échecs) > 0 {
		b.WriteString("\n  Modules en échec\n")
		te := display.NouvelleTable("SCOPE", "CLÉ", "DÉTAIL")
		for _, m := range échecs {
			te.Ajouter(m.Scope, m.StateKey, unLigne(m.Detail))
		}
		b.WriteString(indenter(te.String(), "    "))
	}

	écarts, err := dbgpo.GetDriftForClient(db, computeurID)
	if err != nil {
		return b.String() + "\nÉcarts illisibles : " + err.Error()
	}
	if len(écarts) > 0 {
		b.WriteString("\n  Écarts constatés\n")
		td := display.NouvelleTable("NATURE", "CHEMIN", "DÉTAIL")
		for _, d := range écarts {
			// Le chemin n'est plus tronqué : c'est la fin d'un chemin qui dit
			// de quel fichier il s'agit, et `tronquer` coupait en octets, ce
			// qui pouvait de surcroît scinder un caractère accentué en deux.
			td.Ajouter(d.Kind, d.Path, unLigne(d.Detail))
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
