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
		//
		// L'AVERTISSEMENT, lui, est lu (TO-DO 99) : mot de passe provisoire,
		// expiration prochaine. Par son PRÉFIXE et non par son rang — les
		// lignes qui précèdent sont de nombre variable, et compter aurait lié
		// cet agent à une version précise du core.
		rendre(utilisateur, pamstate.AuthResult{
			Type: "AUTH", Accepte: true, IsAdmin: administrateur,
			Avertissement: extraireAvertissement(lignes[2:]),
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

// PrefixeAvertissement ouvre la ligne du message à présenter à l'utilisateur.
//
// La même chaîne que côté core et que côté agent Linux. Les trois vivent dans
// des modules Go distincts, rien ne peut les tenir liées à la compilation, et
// les faire diverger d'un caractère ferait simplement disparaître le message —
// sans erreur, sans journal.
const PrefixeAvertissement = "notice:"

// extraireAvertissement rend le message du core, s'il y en a un.
//
// Le TEXTE vient du core et n'est pas composé ici : lui seul connaît l'état du
// compte, et les trois clients — PAM, GDM, Windows — auraient sinon trois
// formulations, dont deux finiraient périmées.
func extraireAvertissement(lignes []string) string {
	for _, l := range lignes {
		if strings.HasPrefix(l, PrefixeAvertissement) {
			return strings.TrimSpace(strings.TrimPrefix(l, PrefixeAvertissement))
		}
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

// PrefixeOTP ouvre la ligne du code de second facteur dans la trame 03_01.
//
// La même chaîne que côté core et que côté agent Linux. Les trois vivent dans
// des modules Go distincts, rien ne peut les tenir liées à la compilation, et
// les faire diverger d'un caractère ferait simplement ignorer le code par le
// core — donc refuser la session d'un compte à second facteur, sans qu'aucun
// message ne dise pourquoi.
const PrefixeOTP = "otp:"
