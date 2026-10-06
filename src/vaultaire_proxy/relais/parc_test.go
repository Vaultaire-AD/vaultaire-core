package relais

import (
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Le parc de relais change pendant qu'il tourne (TO-DO 141).

func portLibre(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// cibleMarquee ouvre une cible qui renvoie ce qu'elle reçoit, précédé d'une marque :
// c'est ce qui dit, côté client, VERS QUI le relais a transporté la connexion.
func cibleMarquee(t *testing.T, marque string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write([]byte(marque))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func ducky(port int, cibles ...string) Relais {
	return Relais{Nom: "ducky", Type: TypeDucky, Ecoute: "127.0.0.1:" + strconv.Itoa(port),
		Cibles: Cibles{Source: SourceListe, Adresses: cibles}}
}

func https(nom string, port int, cibles ...string) Relais {
	return Relais{Nom: nom, Type: TypeHTTPS, Ecoute: "127.0.0.1:" + strconv.Itoa(port),
		Cibles: Cibles{Source: SourceListe, Adresses: cibles}}
}

func parcDEssai(t *testing.T, portAnnonce int) *Parc {
	t.Helper()
	p := NouveauParc(portAnnonce, func(r Relais) Resolveur {
		liste := append([]string(nil), r.Cibles.Adresses...)
		return func() []string { return liste }
	}, nil)
	t.Cleanup(p.Fermer)
	return p
}

// marqueRecue ouvre une connexion et rend la marque que la cible a envoyée.
func marqueRecue(t *testing.T, adresse string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", adresse, 2*time.Second)
	if err != nil {
		return "connexion impossible : " + err.Error()
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil {
		return "rien reçu : " + err.Error()
	}
	return string(buf)
}

func etatDe(t *testing.T, etats []Etat, nom string) Etat {
	t.Helper()
	for _, e := range etats {
		if e.Relais.Nom == nom {
			return e
		}
	}
	t.Fatalf("relais %q absent des états %+v", nom, etats)
	return Etat{}
}

// Ajouter un relais ne touche pas à ceux qui tournent : le tunnel ouvert avant
// l'ajout vit encore après.
func TestAjouterUnRelaisNeCoupeRien(t *testing.T) {
	port := portLibre(t)
	p := parcDEssai(t, port)
	cibleA := cibleMarquee(t, "A")

	if _, err := p.Appliquer([]Relais{ducky(port, cibleA)}); err != nil {
		t.Fatal(err)
	}
	tunnel, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	lire1 := func() byte {
		b := make([]byte, 1)
		_ = tunnel.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(tunnel, b); err != nil {
			t.Fatalf("le tunnel ouvert avant le changement ne répond plus : %v", err)
		}
		return b[0]
	}
	if lire1() != 'A' {
		t.Fatal("le relais Ducky ne mène pas à sa cible")
	}

	portHTTPS := portLibre(t)
	etats, err := p.Appliquer([]Relais{ducky(port, cibleA), https("nexus", portHTTPS, cibleMarquee(t, "N"))})
	if err != nil {
		t.Fatal(err)
	}
	if len(etats) != 2 || etatDe(t, etats, "nexus").Statut != StatutActif {
		t.Fatalf("états après l'ajout : %+v", etats)
	}
	if got := marqueRecue(t, "127.0.0.1:"+strconv.Itoa(portHTTPS)); got != "N" {
		t.Fatalf("le relais ajouté ne relaie pas : %s", got)
	}

	// Le tunnel d'avant : toujours là, toujours vers A.
	if _, err := tunnel.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if lire1() != 'x' {
		t.Fatal("le tunnel ouvert avant l'ajout a été coupé ou détourné")
	}
}

// Changer les cibles d'un relais se fait EN PLACE : même port, compteurs
// gardés, et la connexion suivante part vers la nouvelle cible.
func TestChangerLesCiblesNeFermePasLePort(t *testing.T) {
	port := portLibre(t)
	p := parcDEssai(t, port)
	adresse := "127.0.0.1:" + strconv.Itoa(port)

	if _, err := p.Appliquer([]Relais{ducky(port, cibleMarquee(t, "A"))}); err != nil {
		t.Fatal(err)
	}
	if got := marqueRecue(t, adresse); got != "A" {
		t.Fatalf("avant : %s", got)
	}
	avant := p.Serveurs()[0]

	if _, err := p.Appliquer([]Relais{ducky(port, cibleMarquee(t, "B"))}); err != nil {
		t.Fatal(err)
	}
	if got := marqueRecue(t, adresse); got != "B" {
		t.Fatalf("après le changement de cible, la connexion suivante reçoit %s, attendu B", got)
	}
	apres := p.Serveurs()[0]
	if avant != apres {
		t.Fatal("le relais a été remplacé au lieu d'être reconfiguré : son port a été fermé puis rouvert")
	}
	if total := apres.Stats().Total; total != 2 {
		t.Fatalf("compteur « total » à %d après deux connexions : la reconfiguration l'a remis à zéro", total)
	}
}

// Un relais retiré cesse d'écouter ; celui qui reste n'est pas touché.
func TestRetirerUnRelaisFermeSonPort(t *testing.T) {
	port, portHTTPS := portLibre(t), portLibre(t)
	p := parcDEssai(t, port)
	d := ducky(port, cibleMarquee(t, "A"))

	if _, err := p.Appliquer([]Relais{d, https("nexus", portHTTPS, cibleMarquee(t, "N"))}); err != nil {
		t.Fatal(err)
	}
	etats, err := p.Appliquer([]Relais{d})
	if err != nil {
		t.Fatal(err)
	}
	if len(etats) != 1 || etats[0].Relais.Nom != "ducky" {
		t.Fatalf("états après le retrait : %+v", etats)
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(portHTTPS), time.Second); err == nil {
		_ = c.Close()
		t.Fatal("le port du relais retiré écoute encore")
	}
	if got := marqueRecue(t, "127.0.0.1:"+strconv.Itoa(port)); got != "A" {
		t.Fatalf("le relais gardé ne relaie plus : %s", got)
	}
}

// Un port que le proxy n'obtient pas donne un relais REFUSÉ, avec le motif —
// et les autres tournent. C'est l'état que le core affichera.
func TestUnPortPrisEstUnRefusEtPasUnePanne(t *testing.T) {
	port := portLibre(t)
	p := parcDEssai(t, port)

	occupant, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupant.Close()
	portPris := occupant.Addr().(*net.TCPAddr).Port

	etats, err := p.Appliquer([]Relais{ducky(port, cibleMarquee(t, "A")), https("nexus", portPris, "10.0.0.9:443")})
	if err != nil {
		t.Fatalf("un seul relais refusé ne doit pas refuser la liste : %v", err)
	}
	if e := etatDe(t, etats, "ducky"); e.Statut != StatutActif {
		t.Fatalf("le relais Ducky devait tourner : %+v", e)
	}
	e := etatDe(t, etats, "nexus")
	if e.Statut != StatutRefuse || !strings.Contains(e.Motif, strconv.Itoa(portPris)) {
		t.Fatalf("le relais sur un port pris devait être refusé en nommant le port : %+v", e)
	}
	if n := len(p.Serveurs()); n != 1 {
		t.Fatalf("%d relais comptés comme tournant, attendu 1", n)
	}
}

// Déplacer un relais vers un port qu'on n'obtient pas laisse l'ANCIEN en
// service : on ne coupe pas ce qui marche pour une demande impossible.
func TestUnDeplacementImpossibleGardeLAncienneEcoute(t *testing.T) {
	port, portHTTPS := portLibre(t), portLibre(t)
	p := parcDEssai(t, port)
	d := ducky(port, cibleMarquee(t, "A"))
	cibleN := cibleMarquee(t, "N")

	if _, err := p.Appliquer([]Relais{d, https("nexus", portHTTPS, cibleN)}); err != nil {
		t.Fatal(err)
	}
	occupant, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupant.Close()

	etats, err := p.Appliquer([]Relais{d, https("nexus", occupant.Addr().(*net.TCPAddr).Port, cibleN)})
	if err != nil {
		t.Fatal(err)
	}
	e := etatDe(t, etats, "nexus")
	if e.Statut != StatutRefuse || !strings.Contains(e.Motif, "reste en service") {
		t.Fatalf("déplacement impossible : état %+v", e)
	}
	if got := marqueRecue(t, "127.0.0.1:"+strconv.Itoa(portHTTPS)); got != "N" {
		t.Fatalf("l'ancienne écoute a été fermée alors que la nouvelle n'a pas été obtenue : %s", got)
	}
}

// Un déplacement qui réussit ouvre le nouveau port et ferme l'ancien.
func TestDeplacerUnRelais(t *testing.T) {
	port, ancien, nouveau := portLibre(t), portLibre(t), portLibre(t)
	p := parcDEssai(t, port)
	d := ducky(port, cibleMarquee(t, "A"))
	cibleN := cibleMarquee(t, "N")

	if _, err := p.Appliquer([]Relais{d, https("nexus", ancien, cibleN)}); err != nil {
		t.Fatal(err)
	}
	etats, err := p.Appliquer([]Relais{d, https("nexus", nouveau, cibleN)})
	if err != nil {
		t.Fatal(err)
	}
	if e := etatDe(t, etats, "nexus"); e.Statut != StatutActif || !strings.HasSuffix(e.Ecoute, ":"+strconv.Itoa(nouveau)) {
		t.Fatalf("état après déplacement : %+v", e)
	}
	if got := marqueRecue(t, "127.0.0.1:"+strconv.Itoa(nouveau)); got != "N" {
		t.Fatalf("le nouveau port ne relaie pas : %s", got)
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(ancien), time.Second); err == nil {
		_ = c.Close()
		t.Fatal("l'ancien port écoute encore après un déplacement réussi")
	}
}

// Une liste sans relais Ducky est refusée EN ENTIER, et rien ne bouge : le
// proxy est annoncé aux agents sur ce port.
func TestUneListeSansRelaisDuckyNeChangeRien(t *testing.T) {
	port, portHTTPS := portLibre(t), portLibre(t)
	p := parcDEssai(t, port)
	if _, err := p.Appliquer([]Relais{ducky(port, cibleMarquee(t, "A"))}); err != nil {
		t.Fatal(err)
	}

	for nom, liste := range map[string][]Relais{
		"aucun relais ducky":             {https("nexus", portHTTPS, "10.0.0.9:443")},
		"relais ducky sur un autre port": {ducky(portHTTPS, "10.0.0.1:6666")},
		"liste vide":                     nil,
	} {
		_, err := p.Appliquer(liste)
		var sansDucky ErrSansRelaisDucky
		if !errors.As(err, &sansDucky) {
			t.Fatalf("%s : attendu un refus de la liste entière, reçu %v", nom, err)
		}
		if got := marqueRecue(t, "127.0.0.1:"+strconv.Itoa(port)); got != "A" {
			t.Fatalf("%s : la liste refusée a quand même touché au relais Ducky (%s)", nom, got)
		}
		if n := len(p.Etats()); n != 1 {
			t.Fatalf("%s : %d états après un refus, attendu l'unique relais d'avant", nom, n)
		}
	}
}

// Une nouvelle version INVALIDE d'un relais qui tourne ne le retire pas.
func TestUneVersionInvalideGardeLeRelaisQuiTourne(t *testing.T) {
	port, portHTTPS := portLibre(t), portLibre(t)
	p := parcDEssai(t, port)
	d := ducky(port, cibleMarquee(t, "A"))
	if _, err := p.Appliquer([]Relais{d, https("nexus", portHTTPS, cibleMarquee(t, "N"))}); err != nil {
		t.Fatal(err)
	}

	invalide := Relais{Nom: "nexus", Type: TypeLDAP, Ecoute: "127.0.0.1:" + strconv.Itoa(portHTTPS),
		Cibles: Cibles{Source: SourceListe, Adresses: []string{"10.0.0.9:389"}}}
	etats, err := p.Appliquer([]Relais{d, invalide})
	if err != nil {
		t.Fatal(err)
	}
	e := etatDe(t, etats, "nexus")
	if e.Statut != StatutRefuse || !strings.Contains(e.Motif, "ldaps") || !strings.Contains(e.Motif, "reste en service") {
		t.Fatalf("LDAP en clair devait être refusé, et l'ancien relais gardé : %+v", e)
	}
	if got := marqueRecue(t, "127.0.0.1:"+strconv.Itoa(portHTTPS)); got != "N" {
		t.Fatalf("le relais qui tournait a été retiré par une demande invalide : %s", got)
	}
}

// « :6666 » et « 0.0.0.0:6666 » sont la même écoute : les prendre pour deux
// ferait rouvrir un port déjà ouvert, contre soi-même.
func TestMemeEcoute(t *testing.T) {
	for _, c := range []struct {
		a, b string
		meme bool
	}{
		{":6666", ":6666", true},
		{":6666", "0.0.0.0:6666", true},
		{"[::]:6666", ":6666", true},
		{"127.0.0.1:6666", ":6666", false},
		{":6666", ":6667", false},
		{"10.0.0.1:6666", "10.0.0.2:6666", false},
	} {
		if got := memeEcoute(c.a, c.b); got != c.meme {
			t.Errorf("memeEcoute(%q, %q) = %v, attendu %v", c.a, c.b, got, c.meme)
		}
	}
}

// L'inactivité d'un relais Ducky suit la cadence du core (TO-DO 110), et
// seulement la sienne : un relais HTTPS garde son délai.
func TestLInactiviteDuRelaisDuckySuitLaCadence(t *testing.T) {
	port, portHTTPS := portLibre(t), portLibre(t)
	p := parcDEssai(t, port)
	p.InactiviteMinDucky = func() time.Duration { return 121 * time.Minute }

	if _, err := p.Appliquer([]Relais{ducky(port, "10.0.0.1:6666"), https("nexus", portHTTPS, "10.0.0.9:443")}); err != nil {
		t.Fatal(err)
	}
	for _, srv := range p.Serveurs() {
		cfg := srv.Config()
		got := srv.inactivite(cfg)
		switch cfg.Type {
		case TypeDucky:
			if got != 121*time.Minute {
				t.Errorf("relais Ducky : inactivité %s, attendu les 121 min de la cadence", got)
			}
		default:
			if got != InactiviteParDefaut {
				t.Errorf("relais %s : inactivité %s, attendu le défaut %s", cfg.Type, got, InactiviteParDefaut)
			}
		}
	}

	// Un délai configuré PLUS LONG que la cadence l'emporte.
	p.InactiviteMinDucky = func() time.Duration { return 5 * time.Minute }
	if _, err := p.Appliquer([]Relais{ducky(port, "10.0.0.1:6666")}); err != nil {
		t.Fatal(err)
	}
	if got := p.Serveurs()[0].inactivite(p.Serveurs()[0].Config()); got != InactiviteParDefaut {
		t.Errorf("le minimum a ABAISSÉ l'inactivité à %s", got)
	}
}
