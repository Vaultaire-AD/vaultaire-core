package pamcommunication

import "vaultaire_client/pamstate"

// Le verdict d'authentification, isolé pour être éprouvable.
//
// # Le défaut que ce fichier ferme
//
// Un mot de passe REFUSÉ par le serveur central ouvrait la session.
//
// Le refus (trame 03_03) se signalait en FERMANT le canal de réponse. Le
// gestionnaire PAM lisait `result := <-finalChan` — sans le second retour. Or
// lire un canal fermé rend le ZÉRO du type, immédiatement et sans erreur :
// `AuthResult{}`, dont le `Type` vaut « ».
//
// Le test qui suivait était :
//
//	if result.Type != "" && result.Type != "AUTH" { échec } else { succès }
//
// La chaîne vide tombait donc dans le SUCCÈS. Le module PAM recevait
// « status: success », ouvrait la session, et `ensure_local_user_with_password`
// réécrivait `/etc/shadow` avec le mot de passe essayé — d'où la ligne
// « Local password updated (differed from central) » sur un mot de passe faux.
//
// Le serveur, lui, faisait son travail : son journal disait « SSH: mot de passe
// incorrect » à la seconde même où l'agent rendait « success ». Tout s'est joué
// entre sa réponse et sshd.
//
// # Pourquoi une fonction séparée
//
// `processPamRequest` ouvre une session Ducky, émet une trame et attend. Rien
// de cela ne s'éprouve sans serveur — et c'est justement la partie qui décide
// qui n'en a pas besoin.
//
// Deux entrées, un verdict. Trois lignes de test suffisent alors à couvrir le
// cas qui a échappé : le canal fermé.

// VerdictRefuse dit POURQUOI une réponse doit être refusée.
//
// Rend la chaîne vide quand — et seulement quand — l'authentification est
// acceptée. Le motif n'est pas décoratif : sans lui, le journal dit « échec »
// sans distinguer un refus du serveur d'un canal fermé ou d'un type inattendu,
// et ces trois-là n'appellent pas le même diagnostic.
//
// # Fail-closed, par construction
//
// Chaque contrôle REFUSE. L'acceptation est ce qui reste quand aucun n'a
// mordu — et non une branche qu'on atteint par défaut. Un contrôle ajouté
// demain ne peut donc pas ouvrir par oubli.
func VerdictRefuse(result pamstate.AuthResult, recu bool) string {
	// 1. Canal fermé sans message. C'EST LE CAS QUI A OUVERT LA PORTE.
	//
	// `recu` vaut faux uniquement ici : sur un canal fermé et vide. Aucune
	// autre situation ne le produit, et `result` ne vaut alors rien.
	if !recu {
		return "canal de réponse fermé sans verdict — le serveur central a " +
			"refusé, ou la session est tombée"
	}

	// 2. Le VERDICT explicite du serveur.
	//
	// Le zéro de la structure vaut « refusé » : un chemin qui oublierait de
	// remplir le résultat refuse au lieu d'accepter.
	if !result.Accepte {
		return "le serveur central a refusé l'authentification"
	}

	// 3. Le type de réponse.
	//
	// Comparaison POSITIVE — « doit être AUTH » — et non plus négative. La
	// version précédente refusait ce qui n'était « ni vide ni AUTH » : la
	// chaîne vide y était donc acceptée, ce qui est précisément le zéro du
	// type. Une réponse FETCH arrivant sur ce chemin serait une confusion de
	// canaux, pas une authentification.
	if result.Type != "AUTH" {
		return "type de réponse inattendu (" + typeLisible(result.Type) +
			"), une authentification était attendue"
	}

	return ""
}

// typeLisible évite un « type de réponse inattendu () » illisible.
func typeLisible(t string) string {
	if t == "" {
		return "vide"
	}
	return t
}
