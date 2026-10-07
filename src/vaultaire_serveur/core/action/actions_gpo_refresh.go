package action

import (
	"errors"
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	gpomanager "vaultaire/ducky-network/gpo_manager"
)

// Déclenchement d'un cycle GPO hors du tour périodique.
//
// # Pourquoi le droit porte sur la MACHINE et non sur la GPO
//
// L'action ne modifie aucune politique : elle demande à un poste de réappliquer
// celle qu'il aurait reçue de toute façon. Ce qu'elle engage, c'est donc la
// machine — son processeur, ses services redémarrés par les modules, sa
// disponibilité pendant le cycle.
//
// Exiger `write:update:gpo` aurait donné à quiconque peut éditer une GPO le
// pouvoir de lancer un cycle sur N'IMPORTE QUEL poste du parc, y compris hors
// de sa délégation. `write:update:client` sur les domaines de la machine dit
// exactement ce qui se passe : j'agis sur cette machine-là.
//
// # Sur TOUS les domaines de la machine (TO-DO 150)
//
// L'action déclarait UnDomaineSuffit : le droit sur un seul des domaines de la
// machine ouvrait le geste. C'était la seule écriture du catalogue dans ce cas,
// avec `cluster.refresh_nodes` — et la suite `--test` le signalait depuis
// toujours, sans que personne ne la lance. Un poste rangé à la fois dans paris
// et dans lyon se faisait relancer par le délégué de paris seul ; or ce qu'un
// cycle engage — des services redémarrés, un poste occupé — touche aussi lyon.
//
// La règle du registre n'a pas d'exception : une écriture exige le droit sur
// tous les domaines de sa cible. Ce délégué ne pouvait déjà ni modifier ni
// retirer ce poste ; il ne le fait plus rafraîchir non plus, et la boucle le
// compte parmi les machines hors de son périmètre.
//
// # Pourquoi il n'y a pas d'action « tout le parc »
//
// Une action unique qui rafraîchirait tout ne pourrait porter qu'un droit
// global, et le délégué qui administre dix postes n'aurait rien. La ligne de
// commande fait donc la boucle et appelle cette action une fois par machine :
// chaque poste est contrôlé pour lui-même, et un parc mixte donne un résultat
// partiel qui s'annonce comme tel.

//
// # Trois façons de la demander, une seule boucle (TO-DO 169)
//
// Une machine, tout le parc connecté, ou les machines d'une GPO : la ligne de
// commande faisait la boucle elle-même, et le portail ne proposait rien — alors
// que c'est là qu'on modifie un module, et là qu'on attend ensuite de le voir
// appliqué. La boucle vit maintenant ICI (RafraichirMachines), et les deux
// façades l'empruntent : un bouton et une commande qui ne compteraient pas
// pareil ce qu'ils ont joint finiraient par ne plus dire la même chose.

// EnregistrerActionsRafraichissementGPO ajoute le déclenchement de cycle.
func EnregistrerActionsRafraichissementGPO(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "gpo.refresh",
		CleRBAC:  "write:update:client",
		Portee:   PorteeClient,
		Resume:   "demande à une machine de rafraîchir sa politique maintenant",
		Executer: rafraichirMachine,
	})
}

// rafraichirMachine pousse 05_18 à une machine.
//
// Une machine hors ligne n'est PAS une erreur : elle fera un cycle en
// revenant. Rendre une erreur aurait fait échouer un rafraîchissement de parc
// à cause d'un portable fermé, et poussé à ignorer les erreurs de cette action
// — donc aussi les vraies.
func rafraichirMachine(a Appelant, p Params) (Resultat, error) {
	id := strings.TrimSpace(p.Get("computeur_id"))
	if id == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}

	motif := strings.TrimSpace(p.Get("motif"))
	if motif == "" {
		motif = "demande de " + a.Username
	}

	remis, err := gpomanager.DemanderRafraichissement(id, motif)
	if err != nil {
		// Connectée, mais la trame n'est pas partie. Ce n'est PAS « hors
		// ligne » : le dire ferait attendre une reconnexion qui n'aura pas
		// lieu, puisque la machine est déjà là (TO-DO 89).
		return Resultat{
			Message: fmt.Sprintf("Machine %s connectée, mais la demande n'a pas pu lui être remise (%v). "+
				"Réessayez ; à défaut, elle rafraîchira sa politique à son prochain tour.", id, err),
			Donnees: false,
		}, nil
	}
	if !remis {
		return Resultat{
			Message: fmt.Sprintf("Machine %s hors ligne : elle rafraîchira sa politique à sa reconnexion.", id),
			Donnees: false,
		}, nil
	}
	return Resultat{
		Message: fmt.Sprintf("Rafraîchissement demandé à %s.", id),
		Donnees: true,
	}, nil
}

// BilanRafraichissement compte ce qu'une demande de cycle faite à plusieurs
// machines a donné.
type BilanRafraichissement struct {
	// Visees : machines à qui la demande devait être faite.
	Visees int
	// Jointes : la trame est partie.
	Jointes int
	// NonJointes : hors ligne, ou connectée sans que la trame ait pu partir.
	// Elles rafraîchiront à leur reconnexion, ou à leur tour.
	NonJointes int
	// Refusees : hors du périmètre de l'appelant, ou inconnues de l'annuaire.
	Refusees int
}

// RafraichirMachines demande un cycle à chaque machine donnée, par l'action
// `gpo.refresh` — donc avec SON contrôle de droits, machine par machine.
//
// Les machines refusées sont comptées, pas nommées : lister celles qu'on n'a
// pas le droit de toucher renseignerait sur un parc qu'on n'a pas le droit de
// voir.
func RafraichirMachines(a Appelant, ids []string, motif string) BilanRafraichissement {
	bilan := BilanRafraichissement{Visees: len(ids)}
	for _, id := range ids {
		res, err := executerLeRafraichissement(a, Params{"computeur_id": id, "motif": motif})
		if err != nil {
			bilan.Refusees++
			continue
		}
		if envoye, _ := res.Donnees.(bool); envoye {
			bilan.Jointes++
		} else {
			bilan.NonJointes++
		}
	}
	return bilan
}

// executerLeRafraichissement est remplaçable par les tests : l'action pousse
// une trame à une session, ce qui demande un core.
var executerLeRafraichissement = func(a Appelant, p Params) (Resultat, error) {
	return Executer("gpo.refresh", a, p)
}

// lireLaGPO et machinesDeLaGPO sont remplaçables par les tests : les deux
// lisent la base.
var (
	lireLaGPO = func(a Appelant, nom string) (*gpo.Policy, error) {
		// Par l'action de lecture : le droit de LIRE cette GPO est exigé avant
		// d'en énumérer les machines.
		res, err := Executer("gpo.get", a, Params{"gpo": nom})
		if err != nil {
			return nil, err
		}
		policy, ok := res.Donnees.(*gpo.Policy)
		if !ok || policy == nil {
			return nil, fmt.Errorf("GPO %q introuvable", nom)
		}
		return policy, nil
	}
	machinesDeLaGPO = func(policyID int) ([]string, error) {
		return dbgpo.MachinesLieesA(database.GetDatabase(), policyID)
	}
)

// ErrGPODeCompte : on a demandé un cycle pour une GPO de portée utilisateur.
var ErrGPODeCompte = errors.New("une GPO de compte s'applique à l'ouverture de session de chaque compte : " +
	"il n'y a pas de cycle à demander, et une session déjà ouverte ne change pas")

// RafraichirMachinesDeLaGPO demande un cycle aux machines liées à une GPO.
//
// # Ce qu'elle refuse
//
// Une GPO de COMPTE. Sa politique n'est pas appliquée par le cycle d'une
// machine mais à l'ouverture de session de chaque personne : demander un cycle
// ferait travailler tous les postes pour rien, et laisserait croire que la
// modification est partie. On le dit, au lieu de le faire.
func RafraichirMachinesDeLaGPO(a Appelant, nom string) (BilanRafraichissement, error) {
	nom = strings.TrimSpace(nom)
	if nom == "" {
		return BilanRafraichissement{}, fmt.Errorf("nom de GPO requis")
	}
	policy, err := lireLaGPO(a, nom)
	if err != nil {
		return BilanRafraichissement{}, err
	}
	if policy.Scope == gpo.ScopeUser {
		return BilanRafraichissement{}, ErrGPODeCompte
	}
	ids, err := machinesDeLaGPO(policy.ID)
	if err != nil {
		return BilanRafraichissement{}, err
	}
	return RafraichirMachines(a, ids, "GPO "+nom+", demande de "+a.Username), nil
}

// Lisible dit le bilan en clair. « quoi » nomme ce qui était visé : « liée(s) à
// la GPO base », « connectée(s) ».
func (b BilanRafraichissement) Lisible(quoi string) string {
	if b.Visees == 0 {
		return "Aucune machine " + quoi + " : il n'y a personne à qui demander un cycle."
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Cycle demandé à %d machine(s) sur %d %s.", b.Jointes, b.Visees, quoi)
	if b.NonJointes > 0 {
		fmt.Fprintf(&sb, " %d hors ligne ou non jointe(s) : elles rafraîchiront à leur reconnexion, ou à leur tour.", b.NonJointes)
	}
	if b.Refusees > 0 {
		fmt.Fprintf(&sb, " %d hors de votre périmètre n'ont pas été touchées.", b.Refusees)
	}
	return sb.String()
}
