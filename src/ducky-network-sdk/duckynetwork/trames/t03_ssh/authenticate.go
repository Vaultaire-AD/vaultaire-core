package ssh

import (
	"context"
	"fmt"

	"duckynetwork/duckynetwork/storage"
)

// Authenticate vérifie le mot de passe d'un utilisateur auprès du core.
//
// Enchaîne les deux allers-retours de la catégorie :
//
//	03_04 → 03_05   obtenir le sel et l'aléa
//	   calcul local du HMAC — le mot de passe ne part pas
//	03_01 → 03_02   soumettre la preuve
//
// Le contexte borne les DEUX attentes. Sans lui, un core qui se tait — ce qu'il
// fait délibérément sur certains refus — bloquerait l'appelant indéfiniment.
func Authenticate(ctx context.Context, p *Pending, session *storage.DuckySession, username, password string) (Answer, error) {
	saltCh, err := p.AskSalt(session, username)
	if err != nil {
		return Answer{}, err
	}
	salt, err := await(ctx, saltCh)
	if err != nil {
		return Answer{}, fmt.Errorf("attente du sel : %w", err)
	}
	if salt.Kind != AnswerSalt {
		return salt, fmt.Errorf("refusé avant le calcul de la preuve : %s", salt.Reason)
	}

	// Le nom renvoyé par le core est utilisé pour le HMAC, pas celui demandé.
	//
	// Le core recalcule avec la forme qu'il connaît — « alice@vaultaire.fr » là
	// où l'appelant a pu écrire « alice ». Utiliser sa forme à lui est la seule
	// façon d'obtenir le même condensé des deux côtés.
	fullUsername := salt.Username
	if fullUsername == "" {
		fullUsername = username
	}

	proof, err := GenerateChallengeProof(fullUsername, password, salt.Salt, salt.Nonce, session.SessionID)
	if err != nil {
		return Answer{}, err
	}

	loginCh, err := p.AskCanLogin(session, fullUsername, proof)
	if err != nil {
		return Answer{}, err
	}
	verdict, err := await(ctx, loginCh)
	if err != nil {
		return Answer{}, fmt.Errorf("attente du verdict : %w", err)
	}
	if verdict.Kind != AnswerLogin {
		return verdict, fmt.Errorf("authentification refusée")
	}
	return verdict, nil
}

// await attend une réponse, ou l'expiration du contexte.
func await(ctx context.Context, ch <-chan Answer) (Answer, error) {
	select {
	case <-ctx.Done():
		return Answer{}, ctx.Err()
	case answer, ok := <-ch:
		if !ok {
			return Answer{}, fmt.Errorf("demande abandonnée")
		}
		return answer, nil
	}
}
