// Package commandagent expose la version attendue des agents — TO-DO 111.
//
//	vlt agent                              constaté vs attendu, tout le parc
//	vlt agent -g <groupe>                  les agents d'un groupe
//	vlt agent target <version|none>        défaut du parc
//	vlt agent target -g <groupe> <version|none>
//	vlt agent pin <computeur_id> <version|none>
//
// Ce paquet traduit des arguments ; le contrôle des droits, la validation des
// versions et la résolution vivent dans les actions agent.*, partagées avec le
// portail.
package commandagent

import (
	"fmt"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	"vaultaire/core/parcversion"
)

// ActionsUtilisees liste les actions du registre appelées ici.
var ActionsUtilisees = action.ActionsVersionAgent

// demande est une ligne de commande analysée.
type demande struct {
	action string
	params action.Params
	aide   bool
}

// analyser traduit les arguments, sans rien exécuter — c'est ce que les tests
// éprouvent.
func analyser(args []string) (demande, error) {
	if len(args) == 0 {
		return demande{action: "agent.status", params: action.Params{}}, nil
	}
	switch strings.ToLower(args[0]) {
	case "-h", "help", "--help":
		return demande{aide: true}, nil

	case "-g":
		if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
			return demande{}, fmt.Errorf("usage : agent -g <groupe>")
		}
		return demande{action: "agent.status", params: action.Params{"group": args[1]}}, nil

	case "target":
		reste := args[1:]
		p := action.Params{}
		if len(reste) > 0 && reste[0] == "-g" {
			if len(reste) != 3 {
				return demande{}, fmt.Errorf("usage : agent target -g <groupe> <version|none>")
			}
			p["group"], p["version"] = reste[1], reste[2]
		} else {
			if len(reste) != 1 {
				return demande{}, fmt.Errorf("usage : agent target <version|none>")
			}
			p["version"] = reste[0]
		}
		return demande{action: "agent.set_target", params: p}, nil

	case "pin":
		if len(args) != 3 {
			return demande{}, fmt.Errorf("usage : agent pin <computeur_id> <version|none>")
		}
		return demande{action: "agent.pin",
			params: action.Params{"computeur_id": args[1], "version": args[2]}}, nil
	}
	return demande{}, fmt.Errorf("requête invalide. Essayez 'agent -h'")
}

// Agent_Command traite « agent … ».
func Agent_Command(args []string, groupIDs []int, sender string) string {
	d, err := analyser(args)
	if err != nil {
		return "Erreur : " + err.Error()
	}
	if d.aide {
		return aide()
	}
	if d.action != "agent.status" {
		return commandaction.ExecuterAction(d.action, d.params, groupIDs, sender)
	}

	res, err := action.Executer(d.action, action.Appelant{Username: sender, GroupIDs: groupIDs}, d.params)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	vue, ok := res.Donnees.(action.VueAgents)
	if !ok {
		return res.Message
	}
	return rendre(vue)
}

// rendre met la vue en forme pour un terminal.
func rendre(v action.VueAgents) string {
	var b strings.Builder

	switch {
	case v.Parc != "":
		fmt.Fprintf(&b, "Défaut du parc   : %s\n", v.Parc)
	case v.ParcIllisible != "":
		fmt.Fprintf(&b, "Défaut du parc   : illisible (%q) — ignoré, corrigez-le par « agent target »\n",
			v.ParcIllisible)
	default:
		b.WriteString("Défaut du parc   : aucun\n")
	}
	if len(v.CiblesDesGroupes) == 0 {
		b.WriteString("Cibles de groupe : aucune\n")
	} else {
		var l []string
		for _, c := range v.CiblesDesGroupes {
			l = append(l, c.Groupe+" "+c.Version)
		}
		fmt.Fprintf(&b, "Cibles de groupe : %s\n", strings.Join(l, ", "))
	}
	b.WriteString("\n")

	if len(v.Machines) == 0 {
		if v.Groupe != "" {
			fmt.Fprintf(&b, "Aucun agent dans le groupe %s.\n", v.Groupe)
		} else {
			b.WriteString("Aucun agent inscrit.\n")
		}
		return b.String()
	}

	t := display.NouvelleTable("MACHINE", "COMPUTEUR ID", "DÉCLARÉE", "ATTENDUE", "ÉTAT")
	for _, l := range v.Machines {
		etat := string(l.Etat)
		if l.Etat.AUnEcart() {
			etat = "⚠ " + etat
		}
		t.Ajouter(l.Nom(), l.ComputeurID, l.VersionLisible, l.Attendue.Lisible(), etat)
	}
	b.WriteString(t.String())
	b.WriteString("\n" + v.Bilan() + "\n")

	if v.Compteurs[parcversion.EtatSansCible] == len(v.Machines) {
		b.WriteString("Aucune cible ne s'applique : aucun agent ne sera mis à jour.\n")
	}
	return b.String()
}

func aide() string {
	return `Version attendue des agents : ce que chaque agent déclare, face à ce qu'on attend de lui.

  agent                                    tout le parc (read:log)
  agent -g <groupe>                        les agents d'un groupe (read:log)
  agent target <version|none>              défaut du parc (write:server)
  agent target -g <groupe> <version|none>  cible d'un groupe — un anneau (write:server)
  agent pin <computeur_id> <version|none>  dérogation d'une machine (write:server)

Résolution, pour chaque agent : sa dérogation, sinon LA PLUS HAUTE des cibles de
ses groupes, sinon le défaut du parc, sinon aucune — et aucune cible veut dire
aucune mise à jour automatique. C'est le défaut.

Une version s'écrit en trois nombres (2.3.1) ; « none » retire la cible.
Figer un poste : « agent pin <id> <sa version actuelle> ».

États : en retard, inconnue (version non déclarée ou illisible), en avance (une
machine n'est jamais rétrogradée sans ordre explicite), à jour, sans cible.

Aucun agent ne se met encore à jour de lui-même : la cible sert pour l'instant
à cette vue. Les services (proxy, Nexus, web) n'y figurent pas.`
}
