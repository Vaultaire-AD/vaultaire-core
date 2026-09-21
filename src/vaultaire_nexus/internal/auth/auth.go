// Package auth décide QUI parle et CE QU'IL PEUT FAIRE.
//
// # Trois sources d'identité
//
//	compte local     l'administrateur de secours, indépendant de Vaultaire
//	LDAP(S)          les comptes Vaultaire, vérifiés par un bind sur le core
//	jetons           pour les machines et la CI : docker login, dnf, curl
//
//	réseau Ducky     les comptes Vaultaire, vérifiés par la trame 08_01 (TOTP compris)
//
// # Deux niveaux de droits
//
// Le rôle global (reader < publisher < admin) vient de deux sources, et le
// plus élevé l'emporte :
//
//   - les clés RBAC du core — read:nexus, write:nexus, write:nexus_admin —
//     transmises par la trame 08_02 ou par l'attribut LDAP
//     vaultaireServiceRights ;
//   - la table auth.roles de la configuration, par noms de groupe.
//
// Un dépôt peut ouvrir la lecture ou la publication à des groupes
// supplémentaires.
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

	// Refus explicites, rendus après un mot de passe correct (mode ducky).
	ErrMFARequired = errors.New("code du second facteur requis")
	ErrMFAInvalid  = errors.New("code du second facteur invalide")
	ErrMFAEnroll   = errors.New("second facteur à enrôler sur le portail Vaultaire")
	ErrExpired     = errors.New("mot de passe expiré — changez-le sur le portail Vaultaire")
	ErrDenied      = errors.New("accès refusé")
	ErrNoRole      = errors.New("aucun rôle Nexus pour ce compte")
)

// Sources d'identité.
const (
	SourceLocal = "local"
	SourceLDAP  = "ldap"
	SourceDucky = "ducky"
	SourceToken = "token"
)

// Principal est l'appelant authentifié.
type Principal struct {
	Username string
	Display  string
	Source   string
	Groups   []string // « groupe » (LDAP) ou « groupe@domaine » (Ducky)
	Rights   []string // clés RBAC de service transmises par le core
	Role     string   // rôle global
	TokenID  string   // si authentifié par jeton
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
//
// Un groupe configuré « Infra » reconnaît « Infra » et « Infra@infra.acme.lan » ;
// un groupe configuré « Infra@infra.acme.lan » ne reconnaît que ce domaine.
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
			if !strings.Contains(g, "@") {
				if name, _, ok := strings.Cut(mine, "@"); ok && strings.EqualFold(g, name) {
					return true
				}
			}
		}
	}
	return false
}

// Clés RBAC du core pour Nexus.
const (
	RightRead  = "read:nexus"
	RightWrite = "write:nexus"
	RightAdmin = "write:nexus_admin"
)

// roleFromRights traduit les clés du core en rôle.
func roleFromRights(rights []string) string {
	best := ""
	for _, r := range rights {
		role := ""
		switch strings.ToLower(strings.TrimSpace(r)) {
		case RightAdmin:
			role = config.RoleAdmin
		case RightWrite:
			role = config.RolePublisher
		case RightRead:
			role = config.RoleReader
		}
		if rank(role) > rank(best) {
			best = role
		}
	}
	return best
}

// RoleFor calcule le rôle global depuis les groupes seuls.
func RoleFor(m config.RoleMapping, groups []string) string {
	return RoleFrom(m, groups, nil, false)
}

// RoleFrom calcule le rôle global : le plus élevé entre les clés du core et la
// table des groupes. Avec rightsOnly, la table est ignorée — seul le core
// décide.
func RoleFrom(m config.RoleMapping, groups, rights []string, rightsOnly bool) string {
	best := roleFromRights(rights)
	if rightsOnly {
		return best
	}
	p := &Principal{Source: SourceLDAP, Groups: groups}
	byGroup := ""
	switch {
	case p.InGroup(m.Admin):
		byGroup = config.RoleAdmin
	case p.InGroup(m.Publisher):
		byGroup = config.RolePublisher
	case p.InGroup(m.Reader):
		byGroup = config.RoleReader
	}
	if rank(byGroup) > rank(best) {
		best = byGroup
	}
	return best
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
