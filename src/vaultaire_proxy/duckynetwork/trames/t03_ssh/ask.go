package ssh

import (
	"fmt"

	"vaultaire_proxy/duckynetwork/sendmessage"
	"vaultaire_proxy/duckynetwork/storage"
)

// AskSalt envoie 03_04 : réclame le sel et l'aléa d'un utilisateur.
//
// Enregistre l'attente AVANT l'envoi — voir Pending.Register.
func (p *Pending) AskSalt(session *storage.DuckySession, username string) (<-chan Answer, error) {
	ch := p.Register(username)
	message := sendmessage.BuildClientTrame(
		AskSalt, "serveur_central", session.SessionID,
		"vaultaire", session.ComputeurID, username)
	if err := sendmessage.SendMessage(message, session, ""); err != nil {
		p.Pop(username)
		return nil, fmt.Errorf("envoi de 03_04 : %w", err)
	}
	return ch, nil
}

// AskCanLogin envoie 03_01 : soumet la preuve et demande le verdict.
//
// La preuve vient de GenerateChallengeProof, à partir du sel et de l'aléa
// obtenus par AskSalt. Le username doit être EXACTEMENT celui utilisé pour
// calculer la preuve, domaine compris.
func (p *Pending) AskCanLogin(session *storage.DuckySession, username, proof string) (<-chan Answer, error) {
	if proof == "" {
		return nil, fmt.Errorf("preuve vide")
	}
	ch := p.Register(username)
	message := sendmessage.BuildClientTrame(
		AskCanLogin, "serveur_central", session.SessionID,
		"vaultaire", session.ComputeurID, username, proof)
	if err := sendmessage.SendMessage(message, session, ""); err != nil {
		p.Pop(username)
		return nil, fmt.Errorf("envoi de 03_01 : %w", err)
	}
	return ch, nil
}

// AskUserPublicKeys envoie 03_06 : réclame les clés publiques d'un utilisateur.
//
// # Le core ne répond pas toujours
//
// Sur un compte inexistant, révoqué, ou sans droit sur cette machine, il se tait
// délibérément : répondre « refusé » distinguerait un compte absent d'un compte
// présent mais interdit, et ferait de cette trame un moyen d'énumérer
// l'annuaire.
//
// L'appelant DOIT donc borner son attente par un délai. Attendre sans limite
// bloque sur le cas le plus courant : un nom qui n'existe pas.
func (p *Pending) AskUserPublicKeys(session *storage.DuckySession, username string) (<-chan Answer, error) {
	ch := p.Register(username)
	message := sendmessage.BuildClientTrame(
		AskUserKeys, "serveur_central", session.SessionID,
		"vaultaire", session.ComputeurID, username)
	if err := sendmessage.SendMessage(message, session, ""); err != nil {
		p.Pop(username)
		return nil, fmt.Errorf("envoi de 03_06 : %w", err)
	}
	return ch, nil
}
