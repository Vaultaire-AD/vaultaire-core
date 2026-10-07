package action

import (
	"fmt"
	"time"

	"vaultaire/core/gpo"
	"vaultaire/core/reglages"
)

// Quand une GPO modifiée atteint-elle le parc ? — TO-DO 86.
//
// # Le symptôme
//
// Recette du 24/09 : « une GPO mise à jour ne semble rien changer chez un client
// qui l'avait déjà appliquée ». Le banc du 07/10 ne l'a pas reproduit — un
// module modifié est bien réappliqué, en enforce comme en audit, dans les deux
// portées — mais il a montré ce qui y ressemble à s'y méprendre :
//
//   - rien ne part quand on modifie une GPO. Une machine l'apprend à son
//     prochain CYCLE (une cadence, une heure par défaut) ; un compte à sa
//     prochaine OUVERTURE DE SESSION, et une session déjà ouverte ne change pas ;
//   - et le message rendu disait « Module … mis à jour. », point. Devant un
//     poste qui ne bouge pas, rien ne distinguait « pas encore » de « jamais ».
//
// Ce fichier ne change pas QUAND la politique s'applique : pousser un cycle à
// tout un parc à chaque case cochée serait une autre décision, et elle
// appartient à qui exploite — « vlt gpo refresh » existe pour cela. Il fait dire
// aux actions ce qu'il va se passer, et comment ne pas attendre.

// cadenceDesGPO est remplaçable par les tests : la lire demande la base.
var cadenceDesGPO = func() time.Duration { return reglages.Duree(reglages.CleRafraichissementGPO) }

// priseEnCompte dit quand une modification de GPO atteindra ce qu'elle vise.
//
// Une phrase, ajoutée au message de chaque écriture sur une GPO. Les deux
// façades l'affichent telle quelle, puisqu'elle vient de l'action.
//
// Depuis le TO-DO 169 elle nomme les deux gestes qui évitent d'attendre, un par
// façade : le bouton de la fiche de la GPO, et la commande qui fait la même
// chose. Tous deux ne visent que les machines de CETTE GPO — « --all » ferait
// travailler tout le parc pour une modification qui n'en concerne qu'une part.
func priseEnCompte(portee gpo.Scope, nom string) string {
	if portee == gpo.ScopeUser {
		return "Chaque compte la recevra à sa prochaine ouverture de session ; " +
			"une session déjà ouverte ne change pas."
	}
	return fmt.Sprintf("Les machines liées l'appliqueront à leur prochain cycle, dans %s au plus — "+
		"ou tout de suite : « Demander un cycle » sur la fiche de la GPO, ou « vlt gpo refresh --gpo %s ».",
		cadenceLisible(cadenceDesGPO()), nom)
}

// cadenceLisible rend une durée comme on la dit : « 1 h », « 15 min », « 1 h 30 ».
func cadenceLisible(d time.Duration) string {
	minutes := int(d.Round(time.Minute) / time.Minute)
	switch {
	case minutes <= 0:
		return "une heure"
	case minutes < 60:
		return fmt.Sprintf("%d min", minutes)
	case minutes%60 == 0:
		return fmt.Sprintf("%d h", minutes/60)
	default:
		return fmt.Sprintf("%d h %02d", minutes/60, minutes%60)
	}
}
