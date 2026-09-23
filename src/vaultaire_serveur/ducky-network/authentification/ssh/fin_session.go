package sshclient

import (
	"strings"

	"vaultaire/core/database"
	dbsessions "vaultaire/core/database/db_sessions"
	"vaultaire/core/domain"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Fin d'une session utilisateur — trame 03_11.
//
// # Le trou que cette trame ferme
//
// L'agent n'avait aucun moyen de dire « cette personne s'est déconnectée ».
// La fermeture PAM coupait autrefois le tunnel `02_05`, ce qui a été retiré
// (point 64) parce qu'elle emportait le tunnel de la MACHINE avec elle :
// depuis, elle ne fait plus rien du tout côté réseau. Une session ouverte
// restait donc affichée jusqu'à son expiration.
//
// 03_11 dit exactement une chose : efface la ligne de session de cet
// utilisateur sur cette machine. Elle ne ferme aucune connexion, et c'est la
// raison d'être d'une trame distincte — `02_05` signifie « ferme cette
// connexion », et la réutiliser aurait ramené le défaut du point 64.
//
// # Pourquoi aucune réponse
//
// Rien ne dépend de l'issue côté agent : la session locale est déjà fermée par
// le système quand PAM appelle son `close_session`, et l'agent n'a aucune
// décision à prendre selon ce que répond le core. Un accusé que personne ne lit
// est une trame de plus à router, à documenter et à tester. Les échecs partent
// dans le journal du core, où l'on regarde quand `status -u` affiche quelqu'un
// qui n'est plus là.
//
// # Ce que le core ne croit pas sur parole
//
// L'agent nomme l'utilisateur, mais la MACHINE vient de l'en-tête authentifié
// de la trame. Un agent ne peut donc fermer que des sessions ouvertes CHEZ LUI.
// Prendre l'identifiant de machine dans le contenu aurait laissé n'importe quel
// poste effacer les sessions du parc entier — une porte de déni de service
// ouverte sur un simple affichage.

// SSH_Fin_De_Session traite 03_11.
//
//	Contenu attendu : <utilisateur@domaine>
func SSH_Fin_De_Session(trames_content storage.Trames_struct_client) string {
	brut := strings.TrimSpace(lignePremiere(trames_content.Content))
	if brut == "" {
		logs.Write_Log("WARNING", "SSH: fin de session sans utilisateur depuis "+trames_content.ClientSoftwareID)
		return ""
	}

	// Le nom arrive sous sa forme complète, celle que l'agent a employée pour
	// s'authentifier ; l'annuaire, lui, ne connaît que la forme courte.
	utilisateur, _ := domain.ExctractDomainFromUsername(brut)
	utilisateur = strings.TrimSpace(utilisateur)
	if utilisateur == "" || utilisateur == "vaultaire" {
		// `vaultaire` est le compte du TUNNEL machine. Effacer sa ligne ferait
		// disparaître la machine de `status -c` alors qu'elle est bien là —
		// exactement le défaut du point 64, par un autre chemin.
		logs.Write_Log("WARNING", "SSH: fin de session refusée pour "+brut+
			" depuis "+trames_content.ClientSoftwareID)
		return ""
	}

	db := database.GetDatabase()
	if db == nil {
		logs.Write_Log("ERROR", "SSH: fin de session non enregistrée, base indisponible")
		return ""
	}

	if err := dbsessions.DeleteDidLogin(db, utilisateur, trames_content.ClientSoftwareID); err != nil {
		// Journalisé sans être renvoyé : la personne est partie de toute façon,
		// et la ligne finira par expirer. On veut seulement pouvoir expliquer
		// une session fantôme dans `status -u`.
		logs.Write_Log("WARNING", "SSH: fin de session de "+utilisateur+" sur "+
			trames_content.ClientSoftwareID+" non enregistrée : "+err.Error())
		return ""
	}

	logs.Write_Log("INFO", "SSH: session de "+utilisateur+" fermée sur "+trames_content.ClientSoftwareID)
	return ""
}

// lignePremiere rend la première ligne d'un contenu, ou "".
func lignePremiere(contenu string) string {
	if contenu == "" {
		return ""
	}
	return strings.SplitN(contenu, "\n", 2)[0]
}
