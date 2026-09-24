package relais

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- configuration ---------------------------------------------------------

func ecrire(t *testing.T, contenu string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSansSectionUnRelaisDuckySurLePortAnnonce(t *testing.T) {
	l, err := Charger(ecrire(t, "servers:\n  - ip: 10.0.0.1\n    port: 6666\n"), 7777)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0].Type != TypeDucky || l[0].Ecoute != ":7777" || l[0].Cibles.Source != SourceCores {
		t.Fatalf("%+v", l)
	}
}

// TestLDAPEnClairResteRefuse.
//
// Relayé, LDAP en clair ferait voyager les mots de passe en clair du site
// jusqu'au core — le lien le plus long, le moins bien protégé. Le refus doit
// dire quoi employer à la place.
func TestLDAPEnClairResteRefuse(t *testing.T) {
	_, err := Charger(ecrire(t, "relais:\n  - type: ldap\n    cibles: {source: liste, adresses: [\"10.0.0.9:389\"]}\n"), 6666)
	var prevu ErrTypePrevu
	if !errors.As(err, &prevu) || !strings.Contains(err.Error(), "ldaps") {
		t.Fatalf("ldap : attendu un refus qui renvoie vers ldaps, reçu %v", err)
	}
	if _, err := Charger(ecrire(t, "relais:\n  - type: ftp\n"), 6666); err == nil || !strings.Contains(err.Error(), "inconnu") {
		t.Errorf("type inconnu accepté : %v", err)
	}
}

// TestHTTPSEtLDAPSSontActifs (TO-DO 72).
func TestHTTPSEtLDAPSSontActifs(t *testing.T) {
	l, err := Charger(ecrire(t, `relais:
  - nom: ducky
    type: ducky
    ecoute: ":6666"
  - nom: nexus
    type: https
    ecoute: ":8843"
    cibles: {source: "service:vaultaire_nexus"}
  - nom: nexus-secours
    type: https
    ecoute: ":8844"
    cibles: {source: "service:vaultaire_nexus"}
  - nom: ldaps
    type: ldaps
    ecoute: ":1636"
`), 6666)
	if err != nil {
		t.Fatal(err)
	}
	if l[3].Cibles.Source != SourceCores || !l[3].EnvoieEnteteProxy() {
		t.Errorf("ldaps : source %q, en-tête %v — attendu les cores, avec l'adresse du client",
			l[3].Cibles.Source, l[3].EnvoieEnteteProxy())
	}
	if l[0].EnvoieEnteteProxy() || l[1].EnvoieEnteteProxy() {
		t.Error("en-tête PROXY envoyé à Ducky ou à un Nexus : ils le prendraient pour le début du protocole")
	}
	if got := ServicesSuivis(l); len(got) != 1 || got[0] != "vaultaire_nexus" {
		t.Errorf("services suivis = %v, attendu un seul vaultaire_nexus", got)
	}
}

// TestLDAPSJointLePortLDAPSDesCores.
//
// La découverte n'annonce que le port DUCKY des cores : un relais LDAPS qui
// les reprendrait tels quels enverrait LDAPS sur 6666. C'est le défaut que
// l'essai de bout en bout a montré.
func TestLDAPSJointLePortLDAPSDesCores(t *testing.T) {
	l, err := Charger(ecrire(t, "relais:\n  - type: ldaps\n  - nom: autre\n    type: ldaps\n    ecoute: \":1636\"\n    cibles: {source: cores, port: 10636}\n"), 6666)
	if err != nil {
		t.Fatal(err)
	}
	if l[0].PortCible() != PortLDAPSParDefaut || l[1].PortCible() != 10636 {
		t.Fatalf("ports cibles %d et %d", l[0].PortCible(), l[1].PortCible())
	}
	d, _ := Charger(ecrire(t, "relais:\n  - type: ducky\n    ecoute: \":6666\"\n"), 6666)
	if d[0].PortCible() != 0 {
		t.Fatalf("ducky : port cible %d, attendu le port annoncé (0)", d[0].PortCible())
	}
	if _, err := Charger(ecrire(t, "relais:\n  - type: ldaps\n    cibles: {source: liste, adresses: [\"10.0.0.1:636\"], port: 636}\n"), 6666); err == nil {
		t.Fatal("port accepté avec une liste, qui porte déjà ses ports")
	}
}

func TestLesSourcesDependentDuType(t *testing.T) {
	cas := map[string]string{
		"https sans source":    "relais:\n  - type: https\n    ecoute: \":8843\"\n",
		"https vers les cores": "relais:\n  - type: https\n    ecoute: \":8843\"\n    cibles: {source: cores}\n",
		"service pour ducky":   "relais:\n  - type: ducky\n    ecoute: \":6666\"\n    cibles: {source: \"service:vaultaire_nexus\"}\n",
		"service pour ldaps":   "relais:\n  - type: ldaps\n    cibles: {source: \"service:vaultaire_nexus\"}\n",
		"service sans type":    "relais:\n  - type: https\n    ecoute: \":8843\"\n    cibles: {source: \"service:\"}\n",
	}
	for nom, conf := range cas {
		if _, err := Charger(ecrire(t, conf), 6666); err == nil {
			t.Errorf("%s : accepté", nom)
		}
	}
}

func TestLeRelaisDuckyDoitEcouterSurLePortAnnonce(t *testing.T) {
	_, err := Charger(ecrire(t, "relais:\n  - type: ducky\n    ecoute: \":7000\"\n"), 6666)
	if err == nil || !strings.Contains(err.Error(), "port annoncé") {
		t.Fatalf("%v", err)
	}
}

func TestListeExplicite(t *testing.T) {
	l, err := Charger(ecrire(t, "relais:\n  - nom: vers-a\n    type: ducky\n    ecoute: \"127.0.0.1:6666\"\n    cibles:\n      source: liste\n      adresses: [\"10.0.0.10:6666\", \"10.0.0.11:6666\"]\n"), 6666)
	if err != nil {
		t.Fatal(err)
	}
	if l[0].Nom != "vers-a" || len(l[0].Cibles.Adresses) != 2 {
		t.Fatalf("%+v", l[0])
	}
	if _, err := Charger(ecrire(t, "relais:\n  - type: ducky\n    cibles: {source: liste}\n"), 6666); err == nil {
		t.Fatal("liste vide acceptée")
	}
}

// --- relais -------------------------------------------------------------------

// echo démarre un serveur qui renvoie ce qu'il reçoit, préfixé.
func echo(t *testing.T, prefixe string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if _, err := c.Write([]byte(prefixe + l)); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// adresseMorte rend une adresse où rien n'écoute.
func adresseMorte(t *testing.T) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	a := ln.Addr().String()
	ln.Close()
	return a
}

func demarrer(t *testing.T, cfg Relais, cibles Resolveur) *Serveur {
	t.Helper()
	cfg.Ecoute = "127.0.0.1:0"
	if cfg.Type == "" {
		cfg.Type = TypeDucky
	}
	s := Nouveau(cfg, cibles, nil)
	if err := s.Ecouter(); err != nil {
		t.Fatal(err)
	}
	go s.Servir()
	t.Cleanup(func() { s.Fermer() })
	return s
}

func TestLesOctetsPassentDansLesDeuxSens(t *testing.T) {
	cible := echo(t, "core:")
	s := demarrer(t, Relais{Nom: "t"}, func() []string { return []string{cible} })

	c, err := net.Dial("tcp", s.Adresse())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Des octets arbitraires, y compris nuls : le relais ne lit rien.
	msg := "01_01\x00\xff binaire\n"
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || got != "core:"+msg {
		t.Fatalf("reçu %q, %v", got, err)
	}
	st := s.Stats()
	if st.Total != 1 || st.ParCible[cible] != 1 {
		t.Fatalf("%+v", st)
	}
}

// capture démarre un serveur qui garde les premiers octets reçus.
func capture(t *testing.T) (string, chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	recus := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 64)
		n, _ := io.ReadAtLeast(c, b, 1)
		time.Sleep(100 * time.Millisecond)
		m, _ := c.Read(b[n:])
		recus <- b[:n+m]
	}()
	return ln.Addr().String(), recus
}

// TestLDAPSEnvoieLAdresseDuClient.
//
// Le core compte les échecs de bind par adresse : sans l'en-tête, tout le
// site derrière le proxy partagerait un compteur. L'en-tête doit précéder le
// premier octet du client, et porter SON adresse.
func TestLDAPSEnvoieLAdresseDuClient(t *testing.T) {
	cible, recus := capture(t)
	s := demarrer(t, Relais{Nom: "l", Type: TypeLDAPS}, func() []string { return []string{cible} })

	c, err := net.Dial("tcp", s.Adresse())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatal(err)
	}
	var b []byte
	select {
	case b = <-recus:
	case <-time.After(3 * time.Second):
		t.Fatal("rien reçu")
	}
	if len(b) < 28+3 || string(b[:12]) != string(signatureV2) {
		t.Fatalf("reçu %x : l'en-tête PROXY v2 doit précéder les octets du client", b)
	}
	if b[12] != 0x21 || b[13] != 0x11 {
		t.Fatalf("version/commande %x, famille %x : attendu v2 PROXY, TCP/IPv4", b[12], b[13])
	}
	client := c.LocalAddr().(*net.TCPAddr)
	if !net.IP(b[16:20]).Equal(client.IP) || int(b[24])<<8|int(b[25]) != client.Port {
		t.Fatalf("source %s:%d, attendu le client %s", net.IP(b[16:20]), int(b[24])<<8|int(b[25]), client)
	}
	if string(b[28:31]) != string([]byte{0x16, 0x03, 0x01}) {
		t.Fatalf("octets du client altérés : %x", b[28:])
	}
}

func TestDuckyNEnvoieAucunEntete(t *testing.T) {
	cible, recus := capture(t)
	s := demarrer(t, Relais{Nom: "d", Type: TypeDucky}, func() []string { return []string{cible} })
	c, err := net.Dial("tcp", s.Adresse())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("01_01\n"))
	select {
	case b := <-recus:
		if string(b) != "01_01\n" {
			t.Fatalf("reçu %q : Ducky prendrait l'en-tête pour le début d'une trame", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rien reçu")
	}
}

func TestLaCibleSuivanteEstEssayee(t *testing.T) {
	vivante := echo(t, "b:")
	s := demarrer(t, Relais{Nom: "t", DelaiConnexionSecondes: 1}, func() []string {
		return []string{adresseMorte(t), vivante}
	})
	c, err := net.Dial("tcp", s.Adresse())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x\n"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, _ := bufio.NewReader(c).ReadString('\n')
	if got != "b:x\n" {
		t.Fatalf("%q", got)
	}
}

// Aucune cible : la connexion est FERMÉE tout de suite, pas laissée en attente.
func TestRefusFrancSansCible(t *testing.T) {
	s := demarrer(t, Relais{Nom: "t", DelaiConnexionSecondes: 1}, func() []string { return []string{adresseMorte(t)} })
	c, err := net.Dial("tcp", s.Adresse())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	debut := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) && !strings.Contains(fmtErr(err), "reset") {
		t.Fatalf("attendu une fermeture, reçu %v", err)
	}
	if time.Since(debut) > 3*time.Second {
		t.Fatalf("refus en %s : le client a été fait attendre", time.Since(debut))
	}
	waitFor(t, func() bool { return s.Stats().Refusees == 1 })
}

func TestPlafondParSource(t *testing.T) {
	cible := echo(t, "")
	s := demarrer(t, Relais{Nom: "t", MaxParSource: 1}, func() []string { return []string{cible} })
	a, err := net.Dial("tcp", s.Adresse())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.Write([]byte("a\n"))
	_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := bufio.NewReader(a).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	b, err := net.Dial("tcp", s.Adresse())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("seconde connexion de la même source acceptée")
	}
	waitFor(t, func() bool { return s.Stats().Rejetees == 1 })
}

func TestLaFermetureDuClientLibereLaPlace(t *testing.T) {
	cible := echo(t, "")
	s := demarrer(t, Relais{Nom: "t"}, func() []string { return []string{cible} })
	c, _ := net.Dial("tcp", s.Adresse())
	c.Write([]byte("a\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	bufio.NewReader(c).ReadString('\n')
	c.Close()
	waitFor(t, func() bool { return s.Stats().Actives == 0 })
}

func fmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition jamais atteinte")
}
