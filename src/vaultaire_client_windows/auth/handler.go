package auth

import (
	"fmt"
	"strings"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_client/pamstate"
	"vaultaire_client/tools/sshreq"
)

// HandleTrame03 traite les réponses d'authentification du core.
//
// # Ce que ce gestionnaire NE fait pas, contrairement à celui de Linux
//
// Côté Linux, la même trame déclenche le provisionnement du compte, la pose des
// clés SSH dans authorized_keys et l'application des groupes du domaine. Ici,
// rien de tout cela : la goroutine qui lit la connexion ne doit pas s'y
// attarder — c'est elle qui lira la réponse suivante — et surtout, créer le
// compte Windows demande de connaître le MOT DE PASSE, qui n'est pas dans cette
// trame. Le provisionnement a donc lieu là où le mot de passe existe : dans le
// traitement de la requête du Credential Provider, après ce verdict.
//
// Ce gestionnaire ne fait donc qu'une chose : rendre le verdict à qui attend.
func HandleTrame03(trames storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(trames.Message_Order) < 2 {
		return ""
	}
	switch trames.Message_Order[1] {

	case "02": // accepté
		lignes := strings.Split(strings.TrimSpace(trames.Content), "\n")
		if len(lignes) < 2 {
			logs.Write_log("ERROR", "trame 03_02 invalide : contenu incomplet")
			return ""
		}
		utilisateur := lignes[0]
		administrateur := lignes[1] == "true"
		// Les lignes suivantes portent les groupes du domaine et les clés
		// publiques SSH. La V1 Windows ne s'en sert pas : pas de sshd, et les
		// groupes du domaine n'ont pas d'équivalent local tant que les GPO ne
		// sont pas traitées. Elles sont ignorées, pas lues de travers.
		rendre(utilisateur, pamstate.AuthResult{
			Type: "AUTH", Accepte: true, IsAdmin: administrateur,
		})

	case "03": // refusé
		utilisateur := "inconnu"
		if lignes := strings.Split(strings.TrimSpace(trames.Content), "\n"); len(lignes) > 0 && lignes[0] != "" {
			utilisateur = lignes[0]
		}
		logs.Write_log("WARNING", "le core a refusé l'accès pour "+utilisateur)
		// Un refus EXPLICITE, jamais une simple fermeture : le zéro d'AuthResult
		// se lit comme une acceptation pour qui oublie le second retour.
		rendre(utilisateur, pamstate.AuthResult{Type: "AUTH", Accepte: false})

	case "05":
		logs.Write_log("WARNING", "trame 03_05 reçue : le core utilise l'ancienne "+
			"authentification par défi. Mettre à jour vaultaire_serveur.")

	default:
		logs.Write_log("DEBUG", "sous-trame 03_"+trames.Message_Order[1]+" non gérée par l'agent Windows")
	}
	return ""
}

// rendre dépose le verdict dans le canal de l'attente, sans jamais bloquer :
// cette fonction tourne dans la goroutine qui LIT la connexion.
func rendre(utilisateur string, resultat pamstate.AuthResult) {
	canal, ok := sshreq.Pop(utilisateur)
	if !ok {
		logs.Write_log("WARNING", fmt.Sprintf(
			"verdict reçu pour %s, mais plus personne ne l'attend (délai dépassé ?)", utilisateur))
		return
	}
	select {
	case canal <- resultat:
	default:
		logs.Write_log("WARNING", "canal de réponse saturé pour "+utilisateur)
	}
}
