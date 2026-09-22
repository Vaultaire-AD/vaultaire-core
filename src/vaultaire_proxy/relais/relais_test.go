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

func TestLesTypesPrevusSontRefuses(t *testing.T) {
	for _, typ := range []string{"https", "ldap", "ldaps"} {
		_, err := Charger(ecrire(t, "relais:\n  - type: "+typ+"\n    cibles: {source: liste, adresses: [\"10.0.0.9:443\"]}\n"), 6666)
		var prevu ErrTypePrevu
		if !errors.As(err, &prevu) {
			t.Errorf("%s : attendu ErrTypePrevu, reçu %v", typ, err)
		}
	}
	if _, err := Charger(ecrire(t, "relais:\n  - type: ftp\n"), 6666); err == nil || !strings.Contains(err.Error(), "inconnu") {
		t.Errorf("type inconnu accepté : %v", err)
	}
}

func TestLaSourceServiceEstPrevue(t *testing.T) {
	_, err := Charger(ecrire(t, "relais:\n  - type: ducky\n    ecoute: \":6666\"\n    cibles: {source: \"service:vaultaire_nexus\"}\n"), 6666)
	if err == nil || !strings.Contains(err.Error(), "TO-DO 72") {
		t.Fatalf("%v", err)
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
