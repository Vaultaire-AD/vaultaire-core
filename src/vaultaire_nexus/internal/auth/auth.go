// Package auth décide QUI parle et CE QU'IL PEUT FAIRE.
//
// # Trois sources d'identité
//
//	compte local     l'administrateur de secours, indépendant de Vaultaire
//	LDAP(S)          les comptes Vaultaire, vérifiés par un bind sur le core
//	jetons           pour les machines et la CI : docker login, dnf, curl
//
// Une quatrième, le réseau Ducky, est décrite dans DUCKY_AUTH.md : elle
// remplacera LDAP quand le core exposera les trames 08.
//
// # Deux niveaux de droits
//
// Le rôle global (reader < publisher < admin) vient des groupes Vaultaire, par
// la table auth.roles de la configuration. Un dépôt peut ouvrir la lecture ou
// la publication à des groupes supplémentaires. Quand le core portera les clés
// RBAC « nexus » (CORE_CHANGEMENTS.md), Authorizer sera remplacé sans toucher
// aux appelants.
package auth

import (
	"errors"
	"strings"
	"time"

	"vaultaire_nexus/internal/config"
)

// Erreurs.
var (
	ErrBadCredentials = errors.New("identifiant ou mot de passe incorrect")
	ErrLocked         = errors.New("trop d'échecs, réessayez plus tard")
	ErrUnavailable    = errors.New("annuaire injoignable")
)

// Sources d'identité.
const (
	SourceLocal = "local"
	SourceLDAP  = "ldap"
	SourceToken = "token"
)

// Principal est l'appelant authentifié.
type Principal struct {
	Username string
	Display  string
	Source   string
	Groups   []string
	Role     string // rôle global
	TokenID  string // si authentifié par jeton
	// Scope d'un jeton : il ne peut jamais dépasser le rôle de son titulaire.
	TokenScope string
	AuthAt     time.Time
}

// Anonymous est l'appelant non authentifié.
var Anonymous = &Principal{Username: "anonyme", Source: "anonyme"}

// IsAnonymous dit si l'appelant n'est pas authentifié.
func (p *Principal) IsAnonymous() bool { return p == nil || p.Source == "anonyme" }

func rank(role string) int {
	switch role {
	case config.RoleAdmin:
		return 3
	case config.RolePublisher:
		return 2
	case config.RoleReader:
		return 1
	}
	return 0
}

// AtLeast dit si le rôle effectif atteint min.
func (p *Principal) AtLeast(min string) bool {
	if p.IsAnonymous() {
		return false
	}
	return rank(p.effectiveRole()) >= rank(min)
}

func (p *Principal) effectiveRole() string {
	if p.TokenScope != "" && rank(p.TokenScope) < rank(p.Role) {
		return p.TokenScope
	}
	return p.Role
}

// EffectiveRole rend le rôle réellement appliqué.
func (p *Principal) EffectiveRole() string {
	if p.IsAnonymous() {
		return ""
	}
	return p.effectiveRole()
}

// InGroup dit si l'appelant appartient à l'un des groupes (« * » = tout compte).
func (p *Principal) InGroup(groups []string) bool {
	if p.IsAnonymous() {
		return false
	}
	for _, g := range groups {
		if g == "*" {
			return true
		}
		for _, mine := range p.Groups {
			if strings.EqualFold(g, mine) {
				return true
			}
		}
	}
	return false
}

// RoleFor calcule le rôle global depuis les groupes.
func RoleFor(m config.RoleMapping, groups []string) string {
	p := &Principal{Source: SourceLDAP, Groups: groups}
	switch {
	case p.InGroup(m.Admin):
		return config.RoleAdmin
	case p.InGroup(m.Publisher):
		return config.RolePublisher
	case p.InGroup(m.Reader):
		return config.RoleReader
	}
	return ""
}

// RepoView est ce que l'autorisation doit savoir d'un dépôt.
type RepoView struct {
	Public     bool
	Readers    []string
	Publishers []string
}

// CanRead : télécharger et parcourir.
func CanRead(p *Principal, r RepoView) bool {
	if r.Public {
		return true
	}
	if p.IsAnonymous() {
		return false
	}
	if p.AtLeast(config.RoleReader) {
		return true
	}
	return p.InGroup(r.Readers) || p.InGroup(r.Publishers)
}

// CanPublish : envoyer et supprimer des versions.
func CanPublish(p *Principal, r RepoView) bool {
	if p.IsAnonymous() {
		return false
	}
	if p.AtLeast(config.RolePublisher) {
		return true
	}
	// Un jeton en lecture seule ne publie jamais, même pour un groupe publieur.
	if p.TokenScope == config.RoleReader {
		return false
	}
	return p.InGroup(r.Publishers)
}

// CanAdmin : créer et supprimer des dépôts, ramasse-miettes, jetons d'autrui.
func CanAdmin(p *Principal) bool { return p.AtLeast(config.RoleAdmin) }
