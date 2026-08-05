package userauth

import (
	"fmt"

	"duckynetwork/duckynetwork/sendmessage"
	"duckynetwork/duckynetwork/storage"
)

// AskAuthentification envoie 02_01.
//
// # Le basculement de IsSafe se fait ICI, et l'ordre compte
//
// La trame 02_01 part encore en RSA, puisqu'elle porte un mot de passe et que
// c'est la dernière avant l'établissement du tunnel. IsSafe ne passe à vrai
// qu'APRÈS l'envoi.
//
// Le core fait exactement la même bascule à la réception. Inverser les deux
// côtés produit un échec de déchiffrement qui ressemble en tout point à une
// mauvaise clé, et envoie chercher au mauvais endroit.
func AskAuthentification(session *storage.DuckySession, username, password string) error {
	if username == "" {
		return fmt.Errorf("identifiant vide")
	}
	message := sendmessage.BuildClientTrame(
		AskAuth, "serveur_central", string(session.SessionKey),
		username, session.ComputeurID, password)

	session.IsSafe = false
	if err := sendmessage.SendMessage(message, session, ""); err != nil {
		return fmt.Errorf("envoi de 02_01 : %w", err)
	}
	session.Username = username
	session.IsSafe = true
	return nil
}

// LoginAsService authentifie le PROGRAMME sous le compte de service.
//
// Le mot de passe vaut le nom du compte : le core ne le vérifie pas pour
// « vaultaire », l'identité de la machine ayant déjà été prouvée en 01_02. Le
// champ ne peut pas être vide pour autant, le format de trame l'attend.
func LoginAsService(session *storage.DuckySession) error {
	return AskAuthentification(session, ServiceAccount, ServiceAccount)
}
