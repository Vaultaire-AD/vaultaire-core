package auth

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/ldapclient"
)

// LDAP vérifie les comptes Vaultaire auprès du serveur LDAP du core.
//
// # Déroulé
//
//  1. bind avec le compte de l'utilisateur : c'est le core qui vérifie le mot
//     de passe, la permission « auth » et le verrouillage (kill) ;
//  2. recherche de l'entrée du compte pour lire memberOf et le nom affiché —
//     avec le compte de service s'il est configuré, sinon avec la session de
//     l'utilisateur (qui doit alors porter « search ») ;
//  3. calcul du rôle depuis les clés RBAC du core (attribut opérationnel
//     vaultaireServiceRights, demandé nommément) et depuis les groupes.
//
// Le core accepte comme DN de bind « uid=<compte>,dc=… », « <compte>@<domaine> »
// ou le seul identifiant. On présente la première forme, construite sur la base
// DN configurée.
type LDAP struct {
	cfg        config.LDAPConfig
	roles      config.RoleMapping
	rightsOnly bool
}

// AttrRights est l'attribut opérationnel du core qui porte les clés de service.
const AttrRights = "vaultaireServiceRights"

// NewLDAP prépare l'authentification LDAP.
func NewLDAP(cfg config.LDAPConfig, roles config.RoleMapping) *LDAP {
	return &LDAP{cfg: cfg, roles: roles}
}

// Identity est ce qu'une relecture rend d'un compte.
type Identity struct {
	User   string
	Name   string
	Groups []string
	Rights []string
}

var validUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

func (l *LDAP) dial() (*ldapclient.Conn, error) {
	c, err := ldapclient.Dial(ldapclient.Options{
		URL:                l.cfg.URL,
		CAFile:             l.cfg.CAFile,
		InsecureSkipVerify: l.cfg.InsecureSkipVerify,
		Timeout:            time.Duration(l.cfg.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrUnavailable, err)
	}
	return c, nil
}

func (l *LDAP) userDN(username string) string {
	if strings.Contains(username, "@") {
		return username // forme « compte@domaine », comprise telle quelle par le core
	}
	return "uid=" + ldapclient.EscapeDN(username) + "," + l.cfg.BaseDN
}

// Authenticate vérifie un compte et rend son identité.
func (l *LDAP) Authenticate(username, password string) (*Principal, error) {
	if !validUsername.MatchString(username) || password == "" {
		return nil, ErrBadCredentials
	}
	conn, err := l.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(l.userDN(username), password); err != nil {
		if ldapclient.IsCode(err, ldapclient.ResultInvalidCredentials) ||
			ldapclient.IsCode(err, ldapclient.ResultInsufficientAccess) {
			return nil, ErrBadCredentials
		}
		return nil, fmt.Errorf("%w : %v", ErrUnavailable, err)
	}

	lookup := conn
	if l.cfg.BindDN != "" {
		svc, err := l.dial()
		if err != nil {
			return nil, err
		}
		defer svc.Close()
		if err := svc.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("%w : compte de service refusé : %v", ErrUnavailable, err)
		}
		lookup = svc
	}

	short := username
	if i := strings.IndexByte(short, '@'); i > 0 {
		short = short[:i]
	}
	filter := fmt.Sprintf(l.cfg.UserFilter, ldapclient.EscapeFilter(short))
	entries, err := lookup.Search(l.cfg.BaseDN, filter, []string{"uid", "cn", "displayName", "mail", "memberOf", AttrRights}, 2)
	if err != nil && len(entries) == 0 {
		// Bind réussi mais lecture impossible : le compte est valide, sans
		// groupes connus. Il n'aura que les droits de « * ».
		entries = nil
	}
	p := &Principal{Username: short, Display: short, Source: SourceLDAP, AuthAt: time.Now()}
	if len(entries) > 0 {
		e := entries[0]
		if d := e.Get("displayName"); strings.TrimSpace(d) != "" {
			p.Display = d
		}
		p.Groups = groupNames(e.Attrs["memberof"])
		p.Rights = e.Attrs[strings.ToLower(AttrRights)]
	}
	p.Role = RoleFrom(l.roles, p.Groups, p.Rights, l.rightsOnly)
	if p.Role == "" {
		return nil, ErrNoRole
	}
	return p, nil
}

// Refresh relit les groupes et les clés d'un compte avec le compte de
// service, pour qu'une session ou un jeton reflète un retrait sans attendre.
// Sans compte de service, l'identité du dernier login reste valable (ok=false).
//
// Le compte de service doit porter read:get:user sur le domaine des comptes
// pour lire leurs clés : sans ce droit, le core omet l'attribut et seuls les
// groupes comptent.
func (l *LDAP) Refresh(username string) (id Identity, ok bool, err error) {
	if l.cfg.BindDN == "" {
		return Identity{}, false, nil
	}
	conn, err := l.dial()
	if err != nil {
		return Identity{}, false, err
	}
	defer conn.Close()
	if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
		return Identity{}, false, err
	}
	filter := fmt.Sprintf(l.cfg.UserFilter, ldapclient.EscapeFilter(username))
	entries, err := conn.Search(l.cfg.BaseDN, filter, []string{"memberOf", AttrRights}, 2)
	if err != nil {
		return Identity{}, false, err
	}
	if len(entries) == 0 {
		return Identity{User: username}, true, nil // compte disparu : ni groupe ni clé
	}
	e := entries[0]
	return Identity{
		User:   username,
		Groups: groupNames(e.Attrs["memberof"]),
		Rights: e.Attrs[strings.ToLower(AttrRights)],
	}, true, nil
}

// groupNames extrait le nom d'un groupe, qu'il soit donné en DN
// (cn=Infra,ou=groups,dc=…) ou nu.
func groupNames(vals []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vals {
		name := v
		if strings.Contains(v, "=") {
			first := strings.SplitN(v, ",", 2)[0]
			if i := strings.IndexByte(first, '='); i >= 0 {
				name = first[i+1:]
			}
		}
		name = strings.TrimSpace(name)
		if name != "" && !seen[strings.ToLower(name)] {
			seen[strings.ToLower(name)] = true
			out = append(out, name)
		}
	}
	return out
}
