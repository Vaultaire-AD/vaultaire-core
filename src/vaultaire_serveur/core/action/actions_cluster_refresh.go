package action

import (
	"fmt"
	"strings"

	hosthandler "vaultaire/ducky-network/host_handler"
)

// Demander à une machine de redemander sa liste de nœuds (trame 04_17).
//
// # Pourquoi le droit porte sur la MACHINE et non sur le cluster
//
// L'action ne modifie rien du cluster : elle demande à un poste de relire une
// liste qu'il aurait relue de toute façon au tour suivant. Ce qu'elle engage,
// c'est la machine — et, si le nœud qu'elle utilise n'est plus le mieux placé,
// une reconnexion de son tunnel.
//
// Exiger `write:cluster` aurait donné à quiconque administre le cluster le
// pouvoir de faire reconnecter n'importe quel poste du parc, y compris hors de
// sa délégation. `write:update:client` sur les domaines de la machine dit
// exactement ce qui se passe : j'agis sur cette machine-là.
//
// C'est la même décision que pour `gpo.refresh`, et pour la même raison.
//
// # Pourquoi il n'y a pas d'action « tout le parc »
//
// Elle ne pourrait porter qu'un droit global, et le délégué qui administre dix
// postes n'aurait rien. La ligne de commande fait donc la boucle et appelle
// cette action une fois par machine : chacune est contrôlée pour elle-même, et
// un parc mixte donne un résultat partiel qui s'annonce comme tel.

// EnregistrerActionsRafraichissementCluster ajoute la demande d'actualisation.
func EnregistrerActionsRafraichissementCluster(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:             "cluster.refresh_nodes",
		CleRBAC:         "write:update:client",
		Portee:          PorteeClient,
		UnDomaineSuffit: true,
		Resume:          "demande à une machine de redemander la liste des nœuds joignables",
		Executer:        actualiserListeDeLaMachine,
	})
}

// actualiserListeDeLaMachine pousse 04_17 à une machine.
//
// Une machine hors ligne n'est PAS une erreur : elle redemandera sa liste à sa
// reconnexion, puisque la boucle de découverte commence par un passage
// immédiat. Rendre une erreur aurait fait échouer un rafraîchissement de parc à
// cause d'un portable fermé, et poussé à ignorer les erreurs de cette action —
// donc aussi les vraies.
func actualiserListeDeLaMachine(a Appelant, p Params) (Resultat, error) {
	id := strings.TrimSpace(p.Get("computeur_id"))
	if id == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}

	motif := strings.TrimSpace(p.Get("motif"))
	if motif == "" {
		motif = "demande de " + a.Username
	}

	remis, err := hosthandler.DemanderActualisationListe(id, motif)
	if err != nil {
		// Connectée, mais la trame n'est pas partie. Ce n'est pas « hors
		// ligne » : le dire ferait attendre une reconnexion qui n'aura pas lieu,
		// puisque la machine est déjà là.
		return Resultat{
			Message: fmt.Sprintf("Machine %s connectée, mais la demande n'a pas pu lui être remise (%v). "+
				"Réessayez ; à défaut, elle relira sa liste à son prochain tour.", id, err),
			Donnees: false,
		}, nil
	}
	if !remis {
		return Resultat{
			Message: fmt.Sprintf("Machine %s hors ligne : elle relira sa liste à sa reconnexion.", id),
			Donnees: false,
		}, nil
	}
	return Resultat{
		Message: fmt.Sprintf("Actualisation de la liste demandée à %s.", id),
		Donnees: true,
	}, nil
}
