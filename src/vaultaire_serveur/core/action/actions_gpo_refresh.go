package action

import (
	"fmt"
	"strings"

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
// # Pourquoi il n'y a pas d'action « tout le parc »
//
// Une action unique qui rafraîchirait tout ne pourrait porter qu'un droit
// global, et le délégué qui administre dix postes n'aurait rien. La ligne de
// commande fait donc la boucle et appelle cette action une fois par machine :
// chaque poste est contrôlé pour lui-même, et un parc mixte donne un résultat
// partiel qui s'annonce comme tel.

// EnregistrerActionsRafraichissementGPO ajoute le déclenchement de cycle.
func EnregistrerActionsRafraichissementGPO(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:             "gpo.refresh",
		CleRBAC:         "write:update:client",
		Portee:          PorteeClient,
		UnDomaineSuffit: true,
		Resume:          "demande à une machine de rafraîchir sa politique maintenant",
		Executer:        rafraichirMachine,
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

	if !gpomanager.DemanderRafraichissement(id, motif) {
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
