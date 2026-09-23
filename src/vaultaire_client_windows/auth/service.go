package auth

import (
	"fmt"

	"duckynetworkclient/V1/duckynetwork/logs"

	"vaultaire_client_windows/compte"
	"vaultaire_client_windows/ipc"
)

// Traiter répond à une requête du Credential Provider.
//
// # L'ordre : le core d'abord, la machine ensuite
//
// Le mot de passe est soumis au core AVANT que quoi que ce soit ne soit écrit
// sur la machine. C'est ce qui empêche un poste isolé de devenir une porte
// dérobée : sans core joignable, aucun compte n'est créé, aucun mot de passe
// n'est posé, et la réponse dit « indisponible » plutôt que « refusé ».
//
// Le provisionnement vient donc après, et seulement sur acceptation — il a
// besoin du mot de passe, qui n'existe qu'ici et n'est jamais journalisé.
func Traiter(req ipc.Requete) ipc.Reponse {
	switch req.Type {

	case ipc.TypeEtat:
		raccorde := Raccorde()
		message := "aucun core joignable"
		if raccorde {
			message = "raccordé au domaine"
		}
		return ipc.Reponse{Statut: ipc.StatutSucces, Raccorde: raccorde, Message: message}

	case ipc.TypeAuth, ipc.TypeCheck:
		return authentifier(req)

	default:
		return ipc.Reponse{Statut: ipc.StatutRefus, Message: "requête non gérée"}
	}
}

func authentifier(req ipc.Requete) ipc.Reponse {
	// Le domaine est EXIGÉ, et son absence se dit : un nom sans domaine ne
	// désigne aucun compte de l'annuaire, et « refusé » ferait chercher du côté
	// du mot de passe.
	if _, domaine := SeparerDomaine(req.Utilisateur); domaine == "" {
		logs.Write_log("WARNING", "requête sans domaine pour "+req.Utilisateur)
		return ipc.Reponse{
			Statut:  ipc.StatutRefus,
			Message: "identifiant attendu sous la forme utilisateur@domaine",
		}
	}

	verdict := Authentifier(req.Utilisateur, req.MotDePasse)
	switch {
	case verdict.Indisponible:
		return ipc.Reponse{Statut: ipc.StatutIndisponible, Message: verdict.Motif}
	case verdict.Delai:
		return ipc.Reponse{Statut: ipc.StatutDelai, Message: verdict.Motif}
	case !verdict.Accepte:
		// Le motif du refus n'est PAS détaillé au poste : le dire renseignerait
		// qui essaie des mots de passe sur l'existence du compte. Le core, lui,
		// le journalise.
		return ipc.Reponse{Statut: ipc.StatutRefus, Message: "identifiants refusés"}
	}

	// « check » : vérifier sans rien écrire. C'est ce que demande un
	// déverrouillage d'écran, où le compte local existe forcément déjà.
	if req.Type == ipc.TypeCheck {
		return ipc.Reponse{
			Statut:         ipc.StatutSucces,
			Administrateur: verdict.Administrateur,
			CompteLocal:    compte.NomLocal(req.Utilisateur),
		}
	}

	nomLocal, err := compte.Provisionner(req.Utilisateur, req.MotDePasse, verdict.Administrateur)
	if err != nil {
		// Le mot de passe était bon, mais la session ne s'ouvrira pas : mieux
		// vaut le dire que rendre un succès sur lequel Windows butera ensuite
		// sans expliquer pourquoi.
		logs.Write_log("ERROR", fmt.Sprintf("provisionnement refusé pour %s : %v", req.Utilisateur, err))
		return ipc.Reponse{
			Statut:  ipc.StatutRefus,
			Message: "compte local indisponible sur ce poste",
		}
	}

	return ipc.Reponse{
		Statut:         ipc.StatutSucces,
		Administrateur: verdict.Administrateur,
		CompteLocal:    nomLocal,
	}
}
