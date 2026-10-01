// Package commandlogs expose le journal commun des cores en ligne de commande.
package commandlogs

import (
	"fmt"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	dbjournaux "vaultaire/core/database/db_journaux"
	"vaultaire/core/logs"
)

// ActionsUtilisees liste les actions du registre appelées ici.
var ActionsUtilisees = []string{
	"log.list",
}

// options fait correspondre une option de la commande au paramètre de
// `log.list`. Les noms des paramètres sont ceux du portail : les deux façades
// décrivent la même consultation.
var options = map[string]string{
	"--level":    "level",
	"--core":     "core",
	"--code":     "code",
	"--since":    "since",
	"--until":    "until",
	"--page":     "page",
	"--per-page": "per_page",
}

// Logs_Command traite « logs … ».
func Logs_Command(commandList []string, groupIDs []int, sender string) string {
	if len(commandList) > 0 {
		switch strings.ToLower(commandList[0]) {
		case "-h", "help", "--help":
			return aide()
		}
	}

	p, err := lireOptions(commandList)
	if err != nil {
		return err.Error() + "\n\n" + aide()
	}

	appelant := action.Appelant{Username: sender, GroupIDs: groupIDs}
	res, err := action.Executer("log.list", appelant, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	vue, ok := res.Donnees.(action.JournalVue)
	if !ok {
		return res.Message
	}
	return afficher(vue, commandList)
}

// lireOptions traduit « --option valeur » en paramètres.
//
// Une option inconnue est REFUSÉE : ignorée, « --sinec 2h » rendrait tout le
// journal en laissant croire qu'il a été filtré.
func lireOptions(args []string) (action.Params, error) {
	p := action.Params{}
	for i := 0; i < len(args); i++ {
		nom, connu := options[strings.ToLower(args[i])]
		if !connu {
			return nil, fmt.Errorf("option %q inconnue", args[i])
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("option %s : valeur manquante", args[i])
		}
		i++
		p[nom] = args[i]
	}
	return p, nil
}

// afficher met en forme une page de journal.
//
// La ligne la plus récente EN HAUT, comme sur le portail et comme dans la
// requête : la page 1 est « ce qui vient de se passer ».
func afficher(vue action.JournalVue, args []string) string {
	var b strings.Builder

	if vue.Source == action.SourceMemoire {
		b.WriteString("⚠ " + vue.Avertissement + "\n\n")
	} else {
		b.WriteString("Journal commun des cores")
		if len(vue.Cores) > 0 {
			b.WriteString(" (" + strings.Join(vue.Cores, ", ") + ")")
		}
		b.WriteString("\n\n")
	}

	if len(vue.Lignes) == 0 {
		b.WriteString("Aucune ligne pour ce filtre.\n")
		return b.String()
	}

	largeurCore := 0
	for _, l := range vue.Lignes {
		if len(l.Hostname) > largeurCore {
			largeurCore = len(l.Hostname)
		}
	}
	for _, l := range vue.Lignes {
		b.WriteString(ligne(l, largeurCore))
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("\nPage %d, %d ligne(s), la plus récente en haut.\n",
		vue.Page.Page, len(vue.Lignes)))
	if vue.Suivante {
		b.WriteString("Suite : logs " + argumentsPourPage(args, vue.Page.Page+1) + "\n")
	}
	return b.String()
}

// ligne rend une entrée en une ligne. L'heure est LOCALE : c'est celle qu'on
// compare à sa montre et aux témoignages.
func ligne(l logs.LogEntry, largeurCore int) string {
	s := fmt.Sprintf("%s  %-*s  %-8s",
		l.Timestamp.Local().Format("2006-01-02 15:04:05"), largeurCore, l.Hostname, l.Level)
	if l.Code != "" {
		s += "  " + l.Code
	}
	return s + "  " + l.Message
}

// argumentsPourPage recompose la commande avec un autre numéro de page, pour
// que la suite se tape par copier-coller sans reformuler le filtre.
func argumentsPourPage(args []string, page int) string {
	var garde []string
	for i := 0; i < len(args); i++ {
		if strings.EqualFold(args[i], "--page") {
			i++
			continue
		}
		garde = append(garde, args[i])
	}
	garde = append(garde, "--page", fmt.Sprint(page))
	return strings.Join(garde, " ")
}

func aide() string {
	return `logs — journal commun des cores.

  logs [--level NIVEAU] [--core NOM] [--code CODE]
       [--since QUAND] [--until QUAND] [--page N] [--per-page N]

  --level     seuil : WARNING rend WARNING, ERROR et CRITICAL
  --core      un seul core, par son nom (celui de « cluster »)
  --code      un code précis, ex. VLT-AUTH001
  --since     début, inclus : « 2h », « 30m », « 3j », « 2026-09-24 »,
              « 2026-09-24 14:30 » (heure du core)
  --until     fin, exclue, mêmes formes
  --page      page à afficher, 1 = la plus récente
  --per-page  lignes par page (` + fmt.Sprint(dbjournaux.ParPageDefaut) +
		` par défaut, ` + fmt.Sprint(dbjournaux.ParPageMax) + ` au plus)

Exemples :
  logs --level ERROR --since 2h
  logs --core core-2 --since 2026-09-24 --until 2026-09-25

Les lignes viennent de la BASE : tous les cores y écrivent, chacun signant les
siennes. Si la base ne répond pas, la commande le dit et montre la mémoire du
core qui répond — lui seul.

Le DEBUG n'y figure jamais : il reste sur la sortie standard du core. La
conservation se règle par « settings set log_retention_days <jours> ».

Droit requis : read:log.`
}
