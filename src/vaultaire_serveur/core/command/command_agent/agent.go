// Package commandagent expose la version attendue des agents — TO-DO 111.
//
//	vlt agent                              constaté vs attendu, tout le parc
//	vlt agent -g <groupe>                  les agents d'un groupe
//	vlt agent target <version|none>        défaut du parc
//	vlt agent target -g <groupe> <version|none>
//	vlt agent pin <computeur_id> <version|none> [--downgrade]
//	vlt agent update <computeur_id> [--downgrade]
//	vlt agent depot <nom|none>
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
		p := action.Params{}
		switch {
		case len(args) == 3:
		case len(args) == 4 && args[3] == "--downgrade":
			p["downgrade"] = "yes"
		default:
			return demande{}, fmt.Errorf("usage : agent pin <computeur_id> <version|none> [--downgrade]")
		}
		p["computeur_id"], p["version"] = args[1], args[2]
		return demande{action: "agent.pin", params: p}, nil

	case "update":
		p := action.Params{}
		switch {
		case len(args) == 2:
		case len(args) == 3 && args[2] == "--downgrade":
			p["downgrade"] = "yes"
		default:
			return demande{}, fmt.Errorf("usage : agent update <computeur_id> [--downgrade]")
		}
		p["computeur_id"] = args[1]
		return demande{action: "agent.update", params: p}, nil

	case "depot":
		if len(args) != 2 {
			return demande{}, fmt.Errorf("usage : agent depot <nom|none>")
		}
		return demande{action: "agent.set_repository", params: action.Params{"depot": args[1]}}, nil
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
	fmt.Fprintf(&b, "Dépôt            : %s\n", v.Depot)
	if r := v.Rotation; r != nil {
		jeu := "clé de l'installation"
		if r.Jeu > 0 {
			jeu = fmt.Sprintf("jeu n°%d (%d clé(s))", r.Jeu, r.ClesDuJeu)
		}
		fmt.Fprintf(&b, "Clés des paquets : %s, rotation %s — %d agent(s) Linux sur %d le tiennent\n",
			jeu, r.Phase, r.AJour, r.Agents)
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

	t := display.NouvelleTable("MACHINE", "COMPUTEUR ID", "DÉCLARÉE", "ATTENDUE", "ÉTAT", "DERNIER COMPTE RENDU",
		"CONFIGURATION")
	var ecarts []string
	for _, l := range v.Machines {
		etat := string(l.Etat)
		if l.Etat.AUnEcart() {
			etat = "⚠ " + etat
		}
		attendue := l.Attendue.Lisible()
		if l.Retrogradation {
			attendue += " ↓ rétrogradation"
		}
		t.Ajouter(l.Nom(), l.ComputeurID, l.VersionLisible, attendue, etat, compteRendu(l),
			configuration(l))
		if l.ConfigurationEnEcart() {
			ecarts = append(ecarts, "  "+l.Nom()+" : "+l.Configuration.Motif)
		}
	}
	b.WriteString(t.String())
	b.WriteString("\n" + v.Bilan() + "\n")
	if len(ecarts) > 0 {
		b.WriteString("\nÉcarts de configuration système (à traiter sur la machine — vaultaire_client --config-status) :\n" +
			strings.Join(ecarts, "\n") + "\n")
	}

	if v.Compteurs[parcversion.EtatSansCible] == len(v.Machines) {
		b.WriteString("Aucune cible ne s'applique : aucun agent ne sera mis à jour.\n")
	}
	return b.String()
}

// compteRendu rend « 2.4.0 echec : socket PAM muet », tronqué pour la table.
func compteRendu(l action.LigneAgent) string {
	c := l.CompteRendu
	if c.Vide() {
		return "—"
	}
	s := c.Version + " " + c.Resultat
	if c.Motif != "" {
		s += " : " + c.Motif
	}
	if r := []rune(s); len(r) > 60 {
		s = string(r[:59]) + "…"
	}
	return s
}

// configuration rend l'état du dernier 09_07 (TO-DO 117), « — » sans compte
// rendu : un agent d'avant le 117, ou face à un core qui ne l'annonçait pas.
//
// Le libellé est celui du portail (LigneAgent.ConfigurationLisible).
func configuration(l action.LigneAgent) string {
	switch {
	case l.ConfigurationLisible() == "":
		return "—"
	case l.ConfigurationEnEcart():
		return "⚠ " + l.ConfigurationLisible()
	}
	return l.ConfigurationLisible()
}

func aide() string {
	return `Version attendue des agents : ce que chaque agent déclare, face à ce qu'on attend de lui.

  agent                                    tout le parc (read:log)
  agent -g <groupe>                        les agents d'un groupe (read:log)
  agent target <version|none>              défaut du parc (write:server)
  agent target -g <groupe> <version|none>  cible d'un groupe — un anneau (write:server)
  agent pin <computeur_id> <version|none> [--downgrade]
                                           dérogation d'une machine ; --downgrade l'autorise
                                           à la ramener plus bas, durablement (write:server)
  agent update <computeur_id> [--downgrade]
                                           relance une machine : efface son dernier compte
                                           rendu et lui pousse l'ordre (write:server)
  agent depot <nom|none>                   dépôt Nexus nommé dans les ordres (write:server)

Résolution, pour chaque agent : sa dérogation, sinon LA PLUS HAUTE des cibles de
ses groupes, sinon le défaut du parc, sinon aucune — et aucune cible veut dire
aucune mise à jour automatique. C'est le défaut.

Une version s'écrit en trois nombres (2.3.1) ; « none » retire la cible.
Figer un poste : « agent pin <id> <sa version actuelle> ».

États : en retard, inconnue (version non déclarée ou illisible), en avance (une
machine n'est jamais rétrogradée sans ordre explicite), à jour, sans cible.

L'ordre part vers chaque agent qui en a un : à sa connexion (il le demande), et
poussé par le core qui le tient. Un agent ne retente pas une version sur laquelle
il a échoué : « agent update » l'y renvoie. Il ne rétrograde jamais sans ordre
explicite : « agent pin <id> <version> --downgrade » le pose durablement (la
machine le reçoit à sa prochaine connexion, depuis n'importe quel core, et le
drapeau tombe quand elle a rendu « installe ») ; « agent update <id> --downgrade »
ne vaut que poussé maintenant, à une machine connectée à ce core. Jamais par une
cible de groupe ni de parc.

Un agent Linux qui reçoit l'ordre étale son départ (moins de 2 min), télécharge
le paquet, vérifie la signature et les modules, bascule, puis passe une porte de
santé (service stable, tunnel rétabli, socket PAM qui répond) ; sinon il revient
en arrière et répond « echec ». L'agent Windows répond « non pris en charge ».
Les services (proxy, Nexus, web) n'y figurent pas.

CONFIGURATION : à chaque démarrage, l'agent Linux remet ses piles PAM,
sshd_config et nsswitch.conf à la version de son code (sauvegarde à côté,
sshd -t avant d'écrire) et en rend compte — conforme, réconciliée, ou écart
(rien n'a été écrit pour le fichier en cause ; détail sous la table).`
}
