// Package commandsettings expose les durées d'exploitation en ligne de commande.
package commandsettings

import (
	"fmt"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/reglages"
)

// ActionsUtilisees liste les actions du registre appelées ici.
//
// Vérifiée au démarrage : une action absente échouerait sinon au moment où
// quelqu'un tape la commande.
var ActionsUtilisees = []string{
	"settings.list",
	"settings.set",
	"settings.reset",
}

// Settings_Command traite « settings … ».
func Settings_Command(commandList []string, groupIDs []int, sender string) string {
	if len(commandList) == 0 {
		return aide()
	}

	appelant := action.Appelant{Username: sender, GroupIDs: groupIDs}

	switch strings.ToLower(commandList[0]) {
	case "-h", "help", "--help":
		return aide()

	case "list":
		res, err := action.Executer("settings.list", appelant, action.Params{})
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		etats, ok := res.Donnees.([]reglages.Etat)
		if !ok {
			return res.Message
		}
		return afficher(etats)

	case "set":
		// settings set <clé> <valeur>
		if len(commandList) < 3 {
			return "Requête invalide : settings set <clé> <valeur>\nClés : " + reglages.Cles()
		}
		p := action.Params{"setting": commandList[1], "value": commandList[2]}
		return commandaction.ExecuterAction("settings.set", p, groupIDs, sender)

	case "reset":
		if len(commandList) < 2 {
			return "Requête invalide : settings reset <clé>\nClés : " + reglages.Cles()
		}
		p := action.Params{"setting": commandList[1]}
		return commandaction.ExecuterAction("settings.reset", p, groupIDs, sender)

	default:
		return "Requête invalide. Essayez « settings -h »."
	}
}

// afficher met en forme le tableau des réglages.
//
// La colonne « défaut » est montrée MÊME quand la valeur y est égale : c'est ce
// qui permet de savoir ce à quoi on reviendrait, sans avoir à lire le code. Et
// la marque sur les valeurs modifiées répond à la question qu'on se pose devant
// un serveur qu'on ne connaît pas — « qu'est-ce qui a été touché ici ? ».
func afficher(etats []reglages.Etat) string {
	var b strings.Builder
	b.WriteString("Durées d'exploitation\n\n")

	largeur := 0
	for _, e := range etats {
		if len(e.Cle) > largeur {
			largeur = len(e.Cle)
		}
	}

	modifies := 0
	for _, e := range etats {
		marque := "  "
		if !e.AuDefaut {
			marque = "* "
			modifies++
		}
		b.WriteString(fmt.Sprintf("%s%-*s  %6s   (défaut %d %s, entre %d et %d)\n",
			marque, largeur, e.Cle, e.Affichage, e.Defaut, e.Unite, e.Min, e.Max))
		b.WriteString(fmt.Sprintf("  %-*s  %s\n\n", largeur, "", e.Libelle))
	}

	if modifies > 0 {
		b.WriteString(fmt.Sprintf("* %d valeur(s) écartée(s) du défaut.\n", modifies))
	} else {
		b.WriteString("Toutes les valeurs sont au défaut.\n")
	}
	b.WriteString("\nUn changement prend effet au prochain tour de la boucle concernée,\n")
	b.WriteString("sans redémarrage du serveur.\n")
	return b.String()
}

func aide() string {
	return `settings — durées d'exploitation du serveur.

  settings list                  les durées, leur valeur et leur défaut
  settings set <clé> <valeur>    règle une durée
  settings reset <clé>           la ramène à son défaut codé

Clés : ` + reglages.Cles() + `

Les valeurs vivent en BASE ; les défauts sont codés dans le serveur. Un
changement prend effet au prochain tour de la boucle concernée — aucun
redémarrage, donc aucune coupure du parc pour ajuster une cadence.

Ce qui n'est PAS ici : les délais de protocole et de sécurité — échéances de
lecture réseau, fenêtre anti-rejeu, barème de limitation de débit. Ce ne sont
pas des préférences d'exploitation mais des propriétés du protocole, et les
exposer inviterait à les régler sans savoir ce qu'on règle.

Les durées de l'AGENT ne sont pas ici non plus : elles vivent sur la machine du
parc et relèvent des GPO.`
}
