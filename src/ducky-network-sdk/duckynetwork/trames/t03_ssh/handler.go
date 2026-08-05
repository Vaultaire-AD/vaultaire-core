package ssh

import (
	"strings"

	"duckynetwork/duckynetwork/logs"
	"duckynetwork/duckynetwork/storage"
)

// Handler aiguille les réponses 03 vers les demandes en attente.
//
// Il ne répond jamais rien au core : la catégorie 03 est une suite de questions
// posées par le programme, pas d'ordres reçus.
func (p *Pending) Handler(trames storage.Trames_struct_client, session *storage.DuckySession) string {
	switch trames.Code() {
	case LoginOK:
		p.handleLoginOK(trames)
	case LoginFailed:
		p.handleDenied(trames)
	case SaltResp:
		p.handleSalt(trames)
	case UserKeys:
		p.handleUserKeys(trames)
	default:
		logs.Write("DEBUG", "trame 03 non traitée : "+trames.Code())
	}
	return ""
}

// handleLoginOK lit 03_02 : username, indicateur admin, puis les clés.
func (p *Pending) handleLoginOK(trames storage.Trames_struct_client) {
	lines := strings.Split(strings.TrimSpace(trames.Content), "\n")
	if len(lines) < 2 {
		logs.Write("ERROR", "trame 03_02 incomplète")
		return
	}
	answer := Answer{
		Kind:     AnswerLogin,
		Username: strings.TrimSpace(lines[0]),
		IsAdmin:  strings.TrimSpace(lines[1]) == "true",
	}
	if len(lines) > 2 {
		answer.PublicKeys = strings.Join(lines[2:], "\n")
	}
	if !p.deliver(answer.Username, answer) {
		logs.Write("WARNING", "03_02 reçue pour "+answer.Username+" sans demande en attente")
	}
}

// handleDenied lit 03_03 : username puis motif.
//
// Le motif est journalisé mais ne doit pas être renvoyé tel quel à un
// utilisateur : « user not found » et « permission denied » lui apprendraient
// quels comptes existent.
func (p *Pending) handleDenied(trames storage.Trames_struct_client) {
	lines := strings.Split(strings.TrimSpace(trames.Content), "\n")
	answer := Answer{Kind: AnswerDenied}
	if len(lines) > 0 {
		answer.Username = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		answer.Reason = strings.TrimSpace(lines[1])
	}
	logs.Write("WARNING", "accès refusé pour "+answer.Username+" : "+answer.Reason)
	p.deliver(answer.Username, answer)
}

// handleSalt lit 03_05 : « vaultaire », username, sel, aléa.
//
// La première ligne est le compte de service et non l'utilisateur concerné : le
// lire comme tel ferait chercher une attente au nom de « vaultaire », qui n'en a
// pas.
func (p *Pending) handleSalt(trames storage.Trames_struct_client) {
	lines := strings.Split(strings.TrimSpace(trames.Content), "\n")
	if len(lines) < 4 {
		logs.Write("ERROR", "trame 03_05 incomplète")
		return
	}
	answer := Answer{
		Kind:     AnswerSalt,
		Username: strings.TrimSpace(lines[1]),
		Salt:     strings.TrimSpace(lines[2]),
		Nonce:    strings.TrimSpace(lines[3]),
	}
	if !p.deliver(answer.Username, answer) {
		logs.Write("WARNING", "03_05 reçue pour "+answer.Username+" sans demande en attente")
	}
}

// handleUserKeys lit 03_07 : « vaultaire », ligne vide, username, puis les clés.
//
// La ligne vide en position 1 vient de la construction de la trame côté core.
// Elle n'a pas de sens, mais elle est là : décaler les indices pour l'ignorer
// ferait lire le nom au mauvais endroit.
func (p *Pending) handleUserKeys(trames storage.Trames_struct_client) {
	lines := strings.Split(strings.TrimSpace(trames.Content), "\n")
	if len(lines) < 3 {
		logs.Write("ERROR", "trame 03_07 incomplète")
		return
	}
	answer := Answer{
		Kind:     AnswerKeys,
		Username: strings.TrimSpace(lines[2]),
	}
	if len(lines) > 3 {
		answer.PublicKeys = strings.Join(lines[3:], "\n")
	}
	if !p.deliver(answer.Username, answer) {
		logs.Write("WARNING", "03_07 reçue pour "+answer.Username+" sans demande en attente")
	}
}
