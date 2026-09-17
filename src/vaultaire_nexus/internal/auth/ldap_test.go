package auth

import (
	"net"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	"vaultaire_nexus/internal/config"
)

// fakeLDAP imite ce que le serveur LDAP du core répond : bind simple sur
// « uid=<compte>,dc=… », recherche renvoyant memberOf en DN de groupe.
type fakeLDAP struct {
	ln       net.Listener
	users    map[string]string   // uid -> mot de passe
	groups   map[string][]string // uid -> groupes
	svcDN    string
	svcPass  string
	mu       sync.Mutex
	binds    []string
	searches []string
}

func startFake(t *testing.T) *fakeLDAP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeLDAP{ln: ln,
		users:  map[string]string{"alice.martin": "bon-mot-de-passe", "chloe": "autre"},
		groups: map[string][]string{"alice.martin": {"cn=Infra,ou=groups,dc=infra,dc=acme,dc=lan", "cn=Dev,ou=groups,dc=dev,dc=acme,dc=lan"}},
		svcDN:  "uid=svc_nexus,dc=acme,dc=lan", svcPass: "svc",
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func uidOf(dn string) string {
	first := strings.SplitN(dn, ",", 2)[0]
	_, v, _ := strings.Cut(first, "=")
	return v
}

func (f *fakeLDAP) serve(c net.Conn) {
	defer c.Close()
	bound := ""
	for {
		p, err := ber.ReadPacket(c)
		if err != nil {
			return
		}
		id := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case 0: // bind
			dn := op.Children[1].Value.(string)
			pw := op.Children[2].Data.String()
			f.mu.Lock()
			f.binds = append(f.binds, dn)
			f.mu.Unlock()
			code := int64(49)
			if dn == f.svcDN && pw == f.svcPass {
				code, bound = 0, "svc"
			} else if want, ok := f.users[uidOf(dn)]; ok && want == pw {
				code, bound = 0, uidOf(dn)
			}
			c.Write(response(id, 1, code))
		case 2: // unbind
			return
		case 3: // search
			if bound == "" {
				c.Write(response(id, 5, 50))
				continue
			}
			// filtre (uid=<valeur>) : égalité, enfants attr/valeur
			filter := op.Children[6]
			uid := filter.Children[1].Data.String()
			f.mu.Lock()
			f.searches = append(f.searches, bound+":"+uid)
			f.mu.Unlock()
			if _, ok := f.users[uid]; ok {
				c.Write(entry(id, "uid="+uid+",ou=users,dc=acme,dc=lan", map[string][]string{
					"uid": {uid}, "displayName": {"Alice Martin"}, "memberOf": f.groups[uid],
				}))
			}
			c.Write(response(id, 5, 0))
		}
	}
}

func envelope(id int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	return p
}

func response(id int64, tag ber.Tag, code int64) []byte {
	p := envelope(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	p.AppendChild(op)
	return p.Bytes()
}

func entry(id int64, dn string, attrs map[string][]string) []byte {
	p := envelope(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	for k, vs := range attrs {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, ""))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, v := range vs {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
		}
		a.AppendChild(set)
		list.AppendChild(a)
	}
	op.AppendChild(list)
	p.AppendChild(op)
	return p.Bytes()
}

func TestLDAPAuthenticate(t *testing.T) {
	f := startFake(t)
	cfg := config.LDAPConfig{URL: "ldap://" + f.ln.Addr().String(), BaseDN: "dc=acme,dc=lan", UserFilter: "(uid=%s)", TimeoutSeconds: 3}
	roles := config.RoleMapping{Admin: []string{"vaultaire"}, Publisher: []string{"Dev"}, Reader: []string{"*"}}

	// Sans compte de service : la recherche se fait avec la session de l'utilisateur.
	l := NewLDAP(cfg, roles)
	p, err := l.Authenticate("alice.martin", "bon-mot-de-passe")
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != config.RolePublisher || p.Display != "Alice Martin" || strings.Join(p.Groups, ",") != "Infra,Dev" {
		t.Fatalf("identité : %+v", p)
	}
	if f.binds[0] != "uid=alice.martin,dc=acme,dc=lan" {
		t.Errorf("DN de bind : %s", f.binds[0])
	}
	if _, err := l.Authenticate("alice.martin", "faux"); err == nil {
		t.Error("mauvais mot de passe accepté")
	}
	if _, err := l.Authenticate("alice.martin", ""); err == nil {
		t.Error("mot de passe vide accepté (bind anonyme)")
	}
	if _, err := l.Authenticate("a*)(uid=*", "x"); err == nil {
		t.Error("identifiant hostile accepté")
	}

	// Avec compte de service : c'est lui qui lit les groupes.
	cfg.BindDN, cfg.BindPassword = f.svcDN, f.svcPass
	l = NewLDAP(cfg, roles)
	p, err = l.Authenticate("alice.martin", "bon-mot-de-passe")
	if err != nil || p.Role != config.RolePublisher {
		t.Fatalf("avec compte de service : %v %+v", err, p)
	}
	if last := f.searches[len(f.searches)-1]; last != "svc:alice.martin" {
		t.Errorf("recherche faite par %s", last)
	}
	groups, ok, err := l.Refresh("alice.martin")
	if err != nil || !ok || len(groups) != 2 {
		t.Errorf("Refresh : %v %v %v", groups, ok, err)
	}

	// Sans aucun rôle : refus, même avec un bon mot de passe.
	roles.Reader = nil
	l = NewLDAP(cfg, roles)
	if _, err := l.Authenticate("chloe", "autre"); err == nil {
		t.Error("compte sans rôle accepté")
	}

	// Annuaire injoignable : erreur distincte d'un mauvais mot de passe.
	f.ln.Close()
	if _, err := l.Authenticate("alice.martin", "bon-mot-de-passe"); err == nil || !strings.Contains(err.Error(), "injoignable") {
		t.Errorf("annuaire coupé : %v", err)
	}
}
