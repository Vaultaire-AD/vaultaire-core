package newmodule

import (
	"fmt"
	"net"
	"testing"
	"time"

	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/pagination"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Pagination des recherches, vue du fil — point 130.
//
// Le paquet pagination éprouve ce qui est gardé entre deux pages. Ici, c'est ce
// que le CLIENT reçoit : les entrées, le code, et le contrôle de réponse tel
// qu'il est encodé.

func comptes(n int) []ldapinterface.LDAPEntry {
	entrees := make([]ldapinterface.LDAPEntry, n)
	for i := range entrees {
		entrees[i] = candidate.UserEntry{
			User:   ldapstorage.User{Username: fmt.Sprintf("u%05d", i), Firstname: "P", Lastname: "N"},
			BaseDN: "acme.lan", Rattachements: []string{"acme.lan"},
		}
	}
	return entrees
}

// reponse est ce qu'un client lit en retour d'UNE requête de recherche.
type reponse struct {
	dns  []string
	code int
	// page est nil quand le SearchResultDone ne porte pas le contrôle.
	page *ldapstorage.PagedResults
}

// lireReponse lit les entrées puis le SearchResultDone, et décode le contrôle
// de pagination avec un décodeur écrit ICI — pas celui du serveur : c'est
// l'encodage du serveur qu'on éprouve.
func lireReponse(t *testing.T, client net.Conn) reponse {
	t.Helper()
	var r reponse
	for {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		p, err := ber.ReadPacket(client)
		if err != nil {
			t.Fatalf("lecture de la réponse : %v (après %d entrée(s))", err, len(r.dns))
		}
		if len(p.Children) < 2 {
			t.Fatalf("message LDAP malformé : %d enfant(s)", len(p.Children))
		}
		op := p.Children[1]
		switch int(op.Tag) {
		case 4: // SearchResultEntry
			r.dns = append(r.dns, op.Children[0].Value.(string))
		case ldapstorage.AppSearchResultDone:
			r.code = int(op.Children[0].Value.(int64))
			if len(p.Children) == 3 {
				controles := p.Children[2]
				if controles.ClassType != ber.ClassContext || controles.Tag != 0 {
					t.Fatalf("troisième élément du message : classe %d étiquette %d, attendu [0] Controls",
						controles.ClassType, controles.Tag)
				}
				if len(controles.Children) != 1 || len(controles.Children[0].Children) != 2 {
					t.Fatalf("contrôle de réponse malformé (la criticité ne doit pas y figurer)")
				}
				ctrl := controles.Children[0]
				if oid := ctrl.Children[0].Value.(string); oid != "1.2.840.113556.1.4.319" {
					t.Fatalf("contrôle de réponse %q, attendu la pagination", oid)
				}
				valeur, err := ber.DecodePacketErr(ctrl.Children[1].ByteValue)
				if err != nil || len(valeur.Children) != 2 {
					t.Fatalf("valeur du contrôle illisible : %v", err)
				}
				r.page = &ldapstorage.PagedResults{
					Size:   int(valeur.Children[0].Value.(int64)),
					Cookie: append([]byte(nil), valeur.Children[1].ByteValue...),
				}
			}
			return r
		default:
			t.Fatalf("étiquette de réponse inattendue : %d", op.Tag)
		}
	}
}

func paire(t *testing.T) (client, serveur net.Conn) {
	t.Helper()
	client, serveur = net.Pipe()
	t.Cleanup(func() {
		pagination.OublierConnexion(serveur)
		client.Close()
		serveur.Close()
	})
	return client, serveur
}

func recherche(taille int, cookie []byte) ldapstorage.SearchRequest {
	return ldapstorage.SearchRequest{
		BaseObject: "dc=acme,dc=lan", Scope: 2, Attributes: []string{"uid"},
		Filter: &ldapstorage.LDAPFilter{Type: ldapstorage.FilterPresent, Attribute: "objectClass"},
		Page:   &ldapstorage.PagedResults{Size: taille, Cookie: cookie},
	}
}

// Une lecture paginée complète, telle qu'un client la mène : chaque entrée une
// fois, le total annoncé dès la première page, et un cookie vide pour finir.
func TestUneLecturePagineeRendToutUneFois(t *testing.T) {
	const total, taille = 2345, 500
	client, serveur := paire(t)

	op := recherche(taille, nil)
	go servirPremierePage(serveur, 1, op, "alice", "acme.lan", comptes(total), taille, time.Now())

	vus := map[string]bool{}
	pages := 0
	for {
		r := lireReponse(t, client)
		pages++
		if r.code != ldapstorage.ResultSuccess {
			t.Fatalf("page %d : code %d", pages, r.code)
		}
		if r.page == nil {
			t.Fatalf("page %d : SearchResultDone sans contrôle de pagination — le client croirait la lecture finie", pages)
		}
		if r.page.Size != total {
			t.Errorf("page %d : total annoncé %d, attendu %d", pages, r.page.Size, total)
		}
		if len(r.dns) > taille {
			t.Fatalf("page %d : %d entrées pour une page de %d", pages, len(r.dns), taille)
		}
		for _, dn := range r.dns {
			if vus[dn] {
				t.Fatalf("page %d : %s servi DEUX fois", pages, dn)
			}
			vus[dn] = true
		}
		if len(r.page.Cookie) == 0 {
			break
		}
		if pages > 100 {
			t.Fatal("la lecture ne se termine pas")
		}
		suite := recherche(taille, r.page.Cookie)
		go servirPageSuivante(serveur, 1+pages, suite, "alice", "acme.lan")
	}

	if len(vus) != total {
		t.Fatalf("%d entrées lues sur %d : il en manque", len(vus), total)
	}
	if pages != 5 {
		t.Errorf("%d pages pour %d entrées par %d, attendu 5", pages, total, taille)
	}
	if ouverts, tenues := pagination.Etat(); ouverts != 0 || tenues != 0 {
		t.Errorf("lecture finie : %d curseur(s), %d entrée(s) encore tenues", ouverts, tenues)
	}
}

// Une recherche que le sizeLimit du client tronque : il reçoit ce qu'il a
// demandé, puis sizeLimitExceeded sur la DERNIÈRE page — avec le contrôle et
// un cookie vide, pour qu'il sache à la fois que c'est fini et que c'est
// incomplet.
func TestUneRecherchePagineeTronqueeLeDitALaFin(t *testing.T) {
	client, serveur := paire(t)
	op := recherche(10, nil)
	op.SizeLimit = 25
	go servirPremierePage(serveur, 1, op, "alice", "acme.lan", comptes(100), 10, time.Now())

	lues, codes := 0, []int{}
	for {
		r := lireReponse(t, client)
		lues += len(r.dns)
		codes = append(codes, r.code)
		if r.page == nil {
			t.Fatal("contrôle absent")
		}
		if len(r.page.Cookie) == 0 {
			break
		}
		suite := recherche(10, r.page.Cookie)
		suite.SizeLimit = 25
		go servirPageSuivante(serveur, 2, suite, "alice", "acme.lan")
	}
	if lues != 25 {
		t.Errorf("%d entrées lues, le client en demandait 25 au plus", lues)
	}
	if len(codes) != 3 || codes[0] != 0 || codes[1] != 0 || codes[2] != ldapstorage.ResultSizeLimitExceeded {
		t.Errorf("codes %v : attendu succès, succès, puis sizeLimitExceeded (4) à la dernière page", codes)
	}
}

// Un cookie qui ne vaut rien : un refus net, sans une seule entrée. Le pire
// serait de resservir la première page — le client bouclerait.
func TestUnCookieInvalideEstRefuseSansEntree(t *testing.T) {
	client, serveur := paire(t)

	go servirPageSuivante(serveur, 1, recherche(10, []byte("jamais émis")), "alice", "acme.lan")
	r := lireReponse(t, client)
	if r.code != ldapstorage.ResultUnwillingToPerform || len(r.dns) != 0 {
		t.Fatalf("cookie inventé : code %d, %d entrée(s) — attendu 53 et aucune", r.code, len(r.dns))
	}

	// Un vrai cookie, présenté avec un AUTRE filtre : même refus.
	go servirPremierePage(serveur, 2, recherche(10, nil), "alice", "acme.lan", comptes(30), 10, time.Now())
	cookie := lireReponse(t, client).page.Cookie
	autre := recherche(10, cookie)
	autre.Filter = &ldapstorage.LDAPFilter{Type: ldapstorage.FilterEquality, Attribute: "uid", Value: "bob"}
	go servirPageSuivante(serveur, 3, autre, "alice", "acme.lan")
	if r := lireReponse(t, client); r.code != ldapstorage.ResultUnwillingToPerform || len(r.dns) != 0 {
		t.Fatalf("cookie d'une autre recherche : code %d, %d entrée(s)", r.code, len(r.dns))
	}

	// Et sous un autre compte, après un nouveau bind sur la même connexion.
	go servirPremierePage(serveur, 4, recherche(10, nil), "alice", "acme.lan", comptes(30), 10, time.Now())
	cookie = lireReponse(t, client).page.Cookie
	go servirPageSuivante(serveur, 5, recherche(10, cookie), "bob", "acme.lan")
	if r := lireReponse(t, client); r.code != ldapstorage.ResultUnwillingToPerform || len(r.dns) != 0 {
		t.Fatalf("cookie d'alice présenté par bob : code %d, %d entrée(s) — bob lirait la suite de ce qu'alice a le droit de voir",
			r.code, len(r.dns))
	}
}

// Taille de page zéro AVEC un cookie : le client abandonne (RFC 2696 §3).
func TestLAbandonRendLaMemoire(t *testing.T) {
	client, serveur := paire(t)
	go servirPremierePage(serveur, 1, recherche(10, nil), "alice", "acme.lan", comptes(30), 10, time.Now())
	cookie := lireReponse(t, client).page.Cookie
	if _, tenues := pagination.Etat(); tenues != 20 {
		t.Fatalf("%d entrées tenues après la première page, attendu 20", tenues)
	}

	go servirPageSuivante(serveur, 2, recherche(0, cookie), "alice", "acme.lan")
	r := lireReponse(t, client)
	if r.code != 0 || len(r.dns) != 0 || r.page == nil || len(r.page.Cookie) != 0 {
		t.Fatalf("abandon : code %d, %d entrée(s), page %+v — attendu succès, rien, cookie vide", r.code, len(r.dns), r.page)
	}
	if ouverts, tenues := pagination.Etat(); ouverts != 0 || tenues != 0 {
		t.Fatalf("après abandon : %d curseur(s), %d entrée(s) tenues", ouverts, tenues)
	}
}

// Le serveur ne peut pas garder la suite : il refuse AVANT d'envoyer une seule
// entrée. Une première page sans suite possible passerait pour le résultat
// entier.
func TestTropDeRecherchesEnCoursRendBusySansEntree(t *testing.T) {
	ancien := ldapstorage.MaxPagedEntriesHeld
	ldapstorage.MaxPagedEntriesHeld = 15
	defer func() { ldapstorage.MaxPagedEntriesHeld = ancien }()

	client, serveur := paire(t)
	go servirPremierePage(serveur, 1, recherche(10, nil), "alice", "acme.lan", comptes(30), 10, time.Now())
	r := lireReponse(t, client)
	if r.code != ldapstorage.ResultBusy || len(r.dns) != 0 {
		t.Fatalf("code %d, %d entrée(s) : attendu busy (51) et aucune entrée", r.code, len(r.dns))
	}
}

func TestTaillePage(t *testing.T) {
	ancien := ldapstorage.MaxPageSize
	ldapstorage.MaxPageSize = 1000
	defer func() { ldapstorage.MaxPageSize = ancien }()

	cas := []struct {
		page      *ldapstorage.PagedResults
		sizeLimit int
		liée      bool
		taille    int
		paginée   bool
		pourquoi  string
	}{
		{nil, 0, true, 0, false, "pas de contrôle : recherche ordinaire"},
		{&ldapstorage.PagedResults{Size: 100}, 0, true, 100, true, "le cas courant"},
		{&ldapstorage.PagedResults{Size: 5000}, 0, true, 1000, true, "au-delà du plafond : le serveur rend moins, la RFC le permet"},
		{&ldapstorage.PagedResults{Size: 0}, 0, true, 0, false, "taille zéro sans cookie : aucune page n'est demandée"},
		{&ldapstorage.PagedResults{Size: 100}, 50, true, 0, false, "page ≥ sizeLimit : RFC 2696 §3, le contrôle est ignoré"},
		{&ldapstorage.PagedResults{Size: 100}, 100, true, 0, false, "page = sizeLimit : idem"},
		{&ldapstorage.PagedResults{Size: 100}, 500, true, 100, true, "page < sizeLimit : paginée, bornée à 500 en tout"},
		{&ldapstorage.PagedResults{Size: 100}, 0, false, 0, false, "session non liée : aucun état n'est gardé pour un inconnu"},
	}
	for _, c := range cas {
		op := ldapstorage.SearchRequest{Page: c.page, SizeLimit: c.sizeLimit}
		taille, paginée := taillePage(op, c.liée)
		if taille != c.taille || paginée != c.paginée {
			t.Errorf("taillePage = (%d, %v), attendu (%d, %v) — %s", taille, paginée, c.taille, c.paginée, c.pourquoi)
		}
	}
}

// La borne d'une recherche paginée n'est PAS MaxSearchEntries : c'est tout
// l'objet du point — lire au-delà de dix mille entrées.
func TestLaBornePagineeDepasseLaBorneOrdinaire(t *testing.T) {
	if ldapstorage.MaxPagedSearchEntries <= ldapstorage.MaxSearchEntries {
		t.Fatalf("MaxPagedSearchEntries (%d) ≤ MaxSearchEntries (%d) : paginer ne permettrait pas de lire plus",
			ldapstorage.MaxPagedSearchEntries, ldapstorage.MaxSearchEntries)
	}
	if got := bornePaginee(0); got != ldapstorage.MaxPagedSearchEntries {
		t.Errorf("sans sizeLimit : borne %d, attendu %d", got, ldapstorage.MaxPagedSearchEntries)
	}
	if got := bornePaginee(50); got != 50 {
		t.Errorf("sizeLimit 50 : borne %d", got)
	}
	if got := bornePaginee(ldapstorage.MaxPagedSearchEntries * 2); got != ldapstorage.MaxPagedSearchEntries {
		t.Errorf("un sizeLimit plus large que la borne du serveur l'a élargie : %d", got)
	}
}

func TestLEmpreinteSuitCeQuiDefinitLaRecherche(t *testing.T) {
	base := recherche(10, nil)
	ref := empreinteRecherche(base)

	meme := recherche(500, []byte("peu importe"))
	meme.BaseObject = " DC=Acme,DC=Lan "
	meme.Attributes = []string{"UID"}
	meme.SizeLimit, meme.TimeLimit = 40, 12
	if empreinteRecherche(meme) != ref {
		t.Error("la casse, la taille de page, le cookie ou les limites changent l'empreinte : " +
			"un client qui ajuste sa taille de page en route serait refusé")
	}

	for titre, change := range map[string]func(*ldapstorage.SearchRequest){
		"base":      func(o *ldapstorage.SearchRequest) { o.BaseObject = "ou=users,dc=acme,dc=lan" },
		"portée":    func(o *ldapstorage.SearchRequest) { o.Scope = 1 },
		"attributs": func(o *ldapstorage.SearchRequest) { o.Attributes = []string{"uid", "mail"} },
		"typesOnly": func(o *ldapstorage.SearchRequest) { o.TypesOnly = true },
		"filtre": func(o *ldapstorage.SearchRequest) {
			o.Filter = &ldapstorage.LDAPFilter{Type: ldapstorage.FilterEquality, Attribute: "uid", Value: "x"}
		},
		"sous-filtre": func(o *ldapstorage.SearchRequest) {
			o.Filter = &ldapstorage.LDAPFilter{Type: ldapstorage.FilterAnd, SubFilters: []*ldapstorage.LDAPFilter{
				{Type: ldapstorage.FilterPresent, Attribute: "objectClass"}}}
		},
	} {
		autre := recherche(10, nil)
		change(&autre)
		if empreinteRecherche(autre) == ref {
			t.Errorf("changer %s ne change pas l'empreinte : la suite de l'ancienne recherche serait servie pour la nouvelle", titre)
		}
	}
}
