package pagination

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

type entree string

func (e entree) DN() string                                       { return string(e) }
func (e entree) GetAttribute(string) []string                     { return nil }
func (e entree) GetAttributes([]string, bool) map[string][]string { return nil }
func (e entree) ObjectClasses() []string                          { return nil }
func (e entree) Domaines() []string                               { return nil }
func (e entree) Restreinte(func(string) bool) ldapinterface.LDAPEntry {
	return e
}

func jeu(n int) []ldapinterface.LDAPEntry {
	entrees := make([]ldapinterface.LDAPEntry, n)
	for i := range entrees {
		entrees[i] = entree(fmt.Sprintf("uid=u%05d,ou=users,dc=acme,dc=lan", i))
	}
	return entrees
}

// surveilles retient les tests dont la vérification finale est déjà inscrite.
var surveilles = map[*testing.T]bool{}

// connexion rend une connexion de test, et vérifie à la FIN du test que le
// magasin est revenu à zéro : une fuite de mémoire se verrait sinon dans le
// test suivant, loin de sa cause.
//
// La vérification est inscrite une seule fois, au premier appel : les
// nettoyages se déroulent en ordre inverse, elle passe donc après la fermeture
// de toutes les connexions du test.
func connexion(t *testing.T) net.Conn {
	t.Helper()
	if !surveilles[t] {
		surveilles[t] = true
		t.Cleanup(func() {
			delete(surveilles, t)
			if ouverts, tenues := Etat(); ouverts != 0 || tenues != 0 {
				t.Errorf("après le test : %d curseur(s) ouvert(s), %d entrée(s) tenue(s) — la mémoire n'est pas rendue", ouverts, tenues)
			}
		})
	}
	a, b := net.Pipe()
	t.Cleanup(func() {
		OublierConnexion(a)
		a.Close()
		b.Close()
	})
	return a
}

// lireTout enchaîne les pages jusqu'au cookie vide et rend les DN dans l'ordre.
func lireTout(t *testing.T, conn net.Conn, total, taille int) []string {
	t.Helper()
	page, err := Servir(conn, "alice", "r1", jeu(total), taille, false)
	if err != nil {
		t.Fatal(err)
	}
	var lus []string
	for tours := 0; ; tours++ {
		if tours > total+2 {
			t.Fatal("la pagination ne se termine pas : le client bouclerait")
		}
		for _, e := range page.Entrees {
			lus = append(lus, e.DN())
		}
		if page.Total != total {
			t.Fatalf("total annoncé %d, attendu %d", page.Total, total)
		}
		if len(page.Cookie) == 0 {
			return lus
		}
		if page, err = Reprendre(conn, page.Cookie, "alice", "r1", taille); err != nil {
			t.Fatalf("page suivante : %v", err)
		}
	}
}

// LA promesse : chaque entrée une fois, dans l'ordre, quelle que soit la façon
// dont le total se divise par la taille de page.
func TestChaqueEntreeEstServieUneFoisEtUneSeule(t *testing.T) {
	for _, c := range []struct{ total, taille int }{
		{0, 10}, {1, 10}, {10, 10}, {11, 10}, {25, 10}, {30, 10}, {1000, 1}, {12345, 1000},
	} {
		conn := connexion(t)
		lus := lireTout(t, conn, c.total, c.taille)
		if len(lus) != c.total {
			t.Fatalf("total=%d taille=%d : %d entrées lues", c.total, c.taille, len(lus))
		}
		attendu := jeu(c.total)
		for i, dn := range lus {
			if dn != attendu[i].DN() {
				t.Fatalf("total=%d taille=%d : entrée %d = %s, attendu %s — doublon ou trou",
					c.total, c.taille, i, dn, attendu[i].DN())
			}
		}
		if ouverts, tenues := Etat(); ouverts != 0 || tenues != 0 {
			t.Fatalf("total=%d taille=%d : lecture finie, mais %d curseur(s) et %d entrée(s) restent tenus",
				c.total, c.taille, ouverts, tenues)
		}
	}
}

// Un résultat qui tient dans une page ne laisse AUCUN état : pas de cookie, pas
// de mémoire tenue.
func TestUnePageSuffitSansRienGarder(t *testing.T) {
	conn := connexion(t)
	page, err := Servir(conn, "alice", "r1", jeu(5), 100, false)
	if err != nil || len(page.Cookie) != 0 || len(page.Entrees) != 5 {
		t.Fatalf("5 entrées, page de 100 : cookie=%x entrées=%d err=%v", page.Cookie, len(page.Entrees), err)
	}
	if ouverts, _ := Etat(); ouverts != 0 {
		t.Fatalf("%d curseur(s) ouvert(s) pour un résultat d'une page", ouverts)
	}
}

// Un cookie ne sert qu'UNE fois. Un client qui rejoue une requête après une
// réponse perdue recevait sinon la page SUIVANTE, et en sautait une sans le
// savoir.
func TestUnCookieNeSertQuUneFois(t *testing.T) {
	conn := connexion(t)
	p1, _ := Servir(conn, "alice", "r1", jeu(30), 10, false)
	p2, err := Reprendre(conn, p1.Cookie, "alice", "r1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if string(p1.Cookie) == string(p2.Cookie) {
		t.Fatal("le cookie n'a pas changé d'une page à l'autre")
	}
	if _, err := Reprendre(conn, p1.Cookie, "alice", "r1", 10); !errors.Is(err, ErrCookieInconnu) {
		t.Fatalf("un cookie déjà consommé est accepté (%v) : la relance d'une requête sauterait une page", err)
	}
	// Le curseur, lui, vit toujours : le bon cookie donne la bonne suite.
	p3, err := Reprendre(conn, p2.Cookie, "alice", "r1", 10)
	if err != nil || len(p3.Entrees) != 10 || p3.Entrees[0].DN() != jeu(30)[20].DN() {
		t.Fatalf("après un rejeu refusé, la suite est perdue : %v", err)
	}
}

// Un cookie ne vaut que sur la connexion qui l'a reçu, pour le compte qui a
// ouvert la recherche, et pour la même recherche.
func TestUnCookieNeVautQuePourSaRecherche(t *testing.T) {
	cas := []struct {
		titre                   string
		autreConn               bool
		proprietaire, empreinte string
		attendu                 error
	}{
		{"autre connexion", true, "alice", "r1", ErrCookieInconnu},
		{"autre compte, après un nouveau bind", false, "bob", "r1", ErrAutreCompte},
		{"autre recherche", false, "alice", "r2", ErrAutreRecherche},
	}
	for _, c := range cas {
		t.Run(c.titre, func(t *testing.T) {
			conn := connexion(t)
			page, _ := Servir(conn, "alice", "r1", jeu(30), 10, false)

			cible := conn
			if c.autreConn {
				cible = connexion(t)
			}
			if _, err := Reprendre(cible, page.Cookie, c.proprietaire, c.empreinte, 10); !errors.Is(err, c.attendu) {
				t.Fatalf("erreur %v, attendu %v", err, c.attendu)
			}
			if !c.autreConn {
				// Refusé pour une raison de fond : le cookie est brûlé, il ne
				// peut pas être rejoué jusqu'à trouver ce qui passe.
				if _, err := Reprendre(conn, page.Cookie, "alice", "r1", 10); !errors.Is(err, ErrCookieInconnu) {
					t.Fatalf("après un refus, le même cookie repasse avec les bons paramètres (%v)", err)
				}
			}
		})
	}
}

func TestUnCurseurExpire(t *testing.T) {
	horloge := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	maintenant = func() time.Time { return horloge }
	defer func() { maintenant = time.Now }()

	conn := connexion(t)
	page, _ := Servir(conn, "alice", "r1", jeu(30), 10, false)

	horloge = horloge.Add(dureeDeVie() - time.Second)
	page, err := Reprendre(conn, page.Cookie, "alice", "r1", 10)
	if err != nil {
		t.Fatalf("refusé avant l'échéance : %v", err)
	}

	// Chaque page repousse l'échéance : c'est un délai d'INACTIVITÉ.
	horloge = horloge.Add(dureeDeVie() + time.Second)
	if _, err := Reprendre(conn, page.Cookie, "alice", "r1", 10); !errors.Is(err, ErrCookieInconnu) {
		t.Fatalf("accepté après l'échéance (%v)", err)
	}
	if ouverts, tenues := Etat(); ouverts != 0 || tenues != 0 {
		t.Fatalf("curseur expiré : %d ouvert(s), %d entrée(s) encore tenues", ouverts, tenues)
	}
}

// Le plafond global : au-delà, une nouvelle recherche est refusée AVANT d'avoir
// rien gardé — et les recherches en cours ne sont pas touchées.
func TestLePlafondGlobalRefuseSansRienGarder(t *testing.T) {
	ancien := ldapstorage.MaxPagedEntriesHeld
	ldapstorage.MaxPagedEntriesHeld = 100
	defer func() { ldapstorage.MaxPagedEntriesHeld = ancien }()

	a, b := connexion(t), connexion(t)
	enCours, err := Servir(a, "alice", "r1", jeu(90), 10, false) // tient 80
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Servir(b, "bob", "r2", jeu(50), 10, false); !errors.Is(err, ErrTropTenu) { // en tiendrait 40
		t.Fatalf("erreur %v, attendu ErrTropTenu", err)
	}
	if _, tenues := Etat(); tenues != 80 {
		t.Fatalf("%d entrées tenues après un refus, attendu 80 : le refus a gardé quelque chose", tenues)
	}
	if _, err := Reprendre(a, enCours.Cookie, "alice", "r1", 10); err != nil {
		t.Fatalf("la recherche en cours a été abîmée par le refus d'une autre : %v", err)
	}
	// Une recherche qui tient dans UNE page passe toujours : elle ne garde rien.
	if _, err := Servir(b, "bob", "r3", jeu(5), 10, false); err != nil {
		t.Fatalf("une recherche d'une seule page est refusée au plafond : %v", err)
	}
}

func TestUneConnexionNeTientPasPlusDeCurseursQuePermis(t *testing.T) {
	ancien := ldapstorage.MaxPagedCursorsPerConnection
	ldapstorage.MaxPagedCursorsPerConnection = 2
	defer func() { ldapstorage.MaxPagedCursorsPerConnection = ancien }()

	horloge := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	maintenant = func() time.Time { return horloge }
	defer func() { maintenant = time.Now }()

	conn := connexion(t)
	var pages []Page
	for i := 0; i < 3; i++ {
		p, err := Servir(conn, "alice", fmt.Sprintf("r%d", i), jeu(30), 10, false)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, p)
		horloge = horloge.Add(time.Second)
	}
	if ouverts, tenues := Etat(); ouverts != 2 || tenues != 40 {
		t.Fatalf("%d curseur(s), %d entrée(s) tenues ; attendu 2 et 40", ouverts, tenues)
	}
	if _, err := Reprendre(conn, pages[0].Cookie, "alice", "r0", 10); !errors.Is(err, ErrCookieInconnu) {
		t.Fatalf("la plus ancienne recherche devait être abandonnée (%v)", err)
	}
	if _, err := Reprendre(conn, pages[2].Cookie, "alice", "r2", 10); err != nil {
		t.Fatalf("la plus récente a été abandonnée à la place de la plus ancienne : %v", err)
	}
}

func TestAbandonEtFermetureRendentLaMemoire(t *testing.T) {
	conn := connexion(t)
	page, _ := Servir(conn, "alice", "r1", jeu(30), 10, false)
	Abandonner(conn, page.Cookie)
	if ouverts, tenues := Etat(); ouverts != 0 || tenues != 0 {
		t.Fatalf("après abandon : %d ouvert(s), %d tenue(s)", ouverts, tenues)
	}
	Abandonner(conn, []byte("inconnu")) // sans effet, sans panique

	Servir(conn, "alice", "r1", jeu(30), 10, false)
	Servir(conn, "alice", "r2", jeu(50), 10, false)
	OublierConnexion(conn)
	if ouverts, tenues := Etat(); ouverts != 0 || tenues != 0 {
		t.Fatalf("après fermeture : %d ouvert(s), %d tenue(s)", ouverts, tenues)
	}
}

// Une recherche tronquée par une borne le reste jusqu'à sa dernière page :
// c'est là que le client doit l'apprendre.
func TestLaTroncatureEstPorteeJusquALaDernierePage(t *testing.T) {
	conn := connexion(t)
	page, _ := Servir(conn, "alice", "r1", jeu(25), 10, true)
	for len(page.Cookie) > 0 {
		if !page.Tronque {
			t.Fatal("la troncature s'est perdue en route")
		}
		var err error
		if page, err = Reprendre(conn, page.Cookie, "alice", "r1", 10); err != nil {
			t.Fatal(err)
		}
	}
	if !page.Tronque {
		t.Fatal("la dernière page ne dit plus que la recherche est tronquée : le client croirait avoir tout lu")
	}
}
