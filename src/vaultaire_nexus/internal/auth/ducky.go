package auth

import (
	"errors"
	"strings"
	"time"
)

// DuckyVerifier est ce que l'authentification attend du raccordement au
// cluster : faire vérifier un compte par le core (trame 08_01) et le relire
// (08_04). Implémenté par internal/clusterlink ; injecté par main pour que ce
// paquet ne dépende pas du réseau.
type DuckyVerifier interface {
	VerifyUser(user, password, otp, from string) (Identity, error)
	RefreshUser(user string) (Identity, error)
}

// Erreurs de relecture qui mettent fin aux droits d'un compte. Toute autre
// erreur (réseau, indisponibilité) laisse l'identité précédente en place.
var (
	ErrRevoked = errors.New("compte révoqué")
	ErrDeleted = errors.New("compte supprimé")
	ErrUnknown = errors.New("compte inconnu du core pour ce service")
)

// Ducky vérifie les comptes Vaultaire par le réseau Ducky.
type Ducky struct {
	v     DuckyVerifier
	roles roleSource
}

type roleSource interface {
	role(groups, rights []string) string
}

// endsRights dit si une erreur de relecture retire tout droit au compte.
func endsRights(err error) bool {
	return errors.Is(err, ErrRevoked) || errors.Is(err, ErrDeleted) ||
		errors.Is(err, ErrDenied) || errors.Is(err, ErrExpired) || errors.Is(err, ErrUnknown)
}

// Authenticate vérifie un compte ; otp peut être vide.
func (d *Ducky) Authenticate(username, password, otp, from string) (*Principal, error) {
	if !validUsername.MatchString(username) || password == "" || strings.ContainsAny(password, "\r\n") {
		return nil, ErrBadCredentials
	}
	id, err := d.v.VerifyUser(username, password, otp, from)
	if err != nil {
		return nil, err
	}
	p := &Principal{
		Username: id.User, Display: id.Name, Source: SourceDucky,
		Groups: id.Groups, Rights: id.Rights, AuthAt: time.Now(),
	}
	if p.Username == "" {
		p.Username, _, _ = strings.Cut(username, "@")
	}
	if strings.TrimSpace(p.Display) == "" {
		p.Display = p.Username
	}
	p.Role = d.roles.role(p.Groups, p.Rights)
	if p.Role == "" {
		return nil, ErrNoRole
	}
	return p, nil
}
