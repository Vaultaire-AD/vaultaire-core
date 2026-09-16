package action

import (
	"fmt"

	"vaultaire/core/revocation"
	revocationmanager "vaultaire/ducky-network/revocation_manager"
)

// Suppression d'un compte utilisateur.
//
// # Pourquoi ce n'est pas une suppression en base
//
// L'appel direct à Command_DELETE_UserWithUsername ne retire le compte que de
// l'annuaire. Le compte LOCAL reste vivant sur chaque machine où il a été
// provisionné, avec son mot de passe dans /etc/shadow et ses clés dans
// authorized_keys.
//
// Autrement dit, le compte survivait à sa propre suppression : l'utilisateur
// disparaissait de l'interface mais pouvait continuer à se connecter à tout le
// parc. C'est le contraire de ce qu'un administrateur croit faire en cliquant
// sur « supprimer ».
//
// La suppression passe donc par revocationmanager.Trigger, qui apporte trois
// choses que la suppression en base n'a pas : le nettoyage des machines en
// ligne, le rejeu vers celles qui sont hors ligne, et la trace d'audit.
//
// # Sur le double contrôle des droits
//
// Trigger vérifie lui-même write:killswitch ET write:delete:user sur tous les
// domaines de la cible. L'action déclare en plus write:delete:user.
//
// Ce n'est pas un oubli : le registre refuse une action sans contrôle déclaré,
// et déclarer une clé factice pour contourner cette règle reviendrait à mentir
// sur ce qui est exigé. La clé déclarée est la vraie, Trigger en exige une de
// plus, et le cumul est plus strict — jamais moins.

// EnregistrerActionsSuppressionUtilisateur ajoute l'action au registre.
func EnregistrerActionsSuppressionUtilisateur(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "user.delete",
		CleRBAC:  "write:delete:user",
		Portee:   PorteeUtilisateur,
		Resume:   "supprime un compte et le révoque sur tout le parc",
		Executer: supprimerUtilisateur,
	})
}

func supprimerUtilisateur(a Appelant, p Params) (Resultat, error) {
	cible := p.Get("username")
	if cible == "" {
		return Resultat{}, fmt.Errorf("utilisateur cible requis")
	}

	// Ne pas se supprimer soi-même.
	//
	// Ni la commande ni l'interface web ne le vérifiaient. Un administrateur
	// qui supprime son propre compte perd l'accès immédiatement, et si c'est le
	// dernier détenteur d'un droit, ce droit devient inatteignable — il faut
	// alors intervenir en base pour rétablir la situation.
	if estLeMemeCompte(a.Username, cible) {
		return Resultat{}, fmt.Errorf(
			"suppression de votre propre compte refusée : vous perdriez l'accès immédiatement, " +
				"et les droits que vous seul détenez deviendraient inatteignables. " +
				"Faites-le supprimer par un autre administrateur")
	}

	out, err := revocationmanager.Trigger(a.Username, a.GroupIDs, cible,
		revocation.ModeHard, revocation.ReasonOffboarding)
	if err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression de %q : %w", cible, err)
	}

	// Le message dit ce qui a été fait ET ce qui reste en attente. Une machine
	// hors ligne au moment de la suppression garde le compte local jusqu'à sa
	// reconnexion : le taire laisserait croire le parc nettoyé alors qu'il ne
	// l'est qu'en partie.
	message := fmt.Sprintf(
		"Utilisateur %s supprimé (ordre de révocation %d). Machines visées : %d, nettoyées : %d.",
		cible, out.OrderID, out.TargetCount, out.PushedNow)
	if restantes := out.TargetCount - out.PushedNow; restantes > 0 {
		message += fmt.Sprintf(
			" %d machine(s) hors ligne : le compte local y sera supprimé à leur reconnexion.",
			restantes)
	}

	return Resultat{
		Message: message,
		Donnees: map[string]any{
			"username":     cible,
			"order_id":     out.OrderID,
			"target_count": out.TargetCount,
			"pushed_now":   out.PushedNow,
		},
	}, nil
}

// estLeMemeCompte compare deux identifiants en tolérant la forme complète.
//
// L'annuaire connaît « alice », les machines « alice@vaultaire.fr ». Comparer
// littéralement laisserait passer la suppression de son propre compte dès que
// les deux formes diffèrent — c'est-à-dire presque toujours, puisque la session
// web porte la forme courte et le formulaire peut porter la longue.
func estLeMemeCompte(a, b string) bool {
	return partieLocale(a) == partieLocale(b) && partieLocale(a) != ""
}

func partieLocale(nom string) string {
	for i, r := range nom {
		if r == '@' {
			return nom[:i]
		}
	}
	return nom
}
