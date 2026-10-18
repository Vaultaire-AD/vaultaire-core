package miseajour

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// horloge simulée : Dormir avance le temps.
type horloge struct {
	mu sync.Mutex
	t  time.Time
}

func (h *horloge) Maintenant() time.Time  { h.mu.Lock(); defer h.mu.Unlock(); return h.t }
func (h *horloge) Dormir(d time.Duration) { h.mu.Lock(); h.t = h.t.Add(d); h.mu.Unlock() }

// banc : une installation, un plan préparé, un faux systemd.
type banc struct {
	c        Chemins
	plan     Plan
	sys      *fauxSysteme
	h        *horloge
	paquet   paquetDeTest
	retour   bool // daemon-reload vu : on est dans le retour arrière
	service  func(retour bool, n int) (Service, error)
	sonde    func(retour bool) (Pong, error)
	lectures int
}

func nouveauBanc(t *testing.T) *banc {
	t.Helper()
	b := &banc{c: installationDeTest(t), h: &horloge{t: time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)}}
	b.paquet = fabriquerPaquet(t, "2.3.1", "rocky", "")
	plan, err := Preparer(preparationDeTest(t, b.c, b.paquet, &fauxSysteme{}), Ordre{Version: "2.3.1"})
	if err != nil {
		t.Fatal(err)
	}
	b.plan = plan
	if !PrendreVerrou(b.c, "2.3.1") {
		t.Fatal("verrou")
	}
	b.sys = &fauxSysteme{}
	b.sys.reponses = func(nom string, args []string) ([]byte, error) {
		switch {
		case nom == b.c.Binaire && len(args) == 1 && args[0] == "--install-unit":
			// Le NOUVEAU binaire écrit son unité.
			return nil, os.WriteFile(b.c.Unite, []byte("nouvelle-unite"), 0o644)
		case nom == "systemctl" && len(args) > 0 && args[0] == "daemon-reload":
			b.retour = true
		}
		return nil, nil
	}
	b.service = func(bool, int) (Service, error) { return Service{Actif: true, PID: 100}, nil }
	b.sonde = func(bool) (Pong, error) { return Pong{Version: "2.3.1", Tunnel: true}, nil }
	return b
}

func (b *banc) bascule() Bascule {
	return Bascule{
		Chemins: b.c, Systeme: b.sys.Systeme,
		Service: func() (Service, error) { b.lectures++; return b.service(b.retour, b.lectures) },
		Sonde:   func() (Pong, error) { return b.sonde(b.retour) },
		Dormir:  b.h.Dormir, Horloge: b.h.Maintenant,
	}
}

func (b *banc) verifierEnPlace(t *testing.T, nouvelle bool) {
	t.Helper()
	for nom, dest := range destinations(b.c) {
		attendu := "ancien-" + nom
		if nouvelle {
			attendu = b.paquet.contenus[nom]
		}
		if got := lire(t, dest); got != attendu {
			t.Errorf("%s : %q, attendu %q", nom, got, attendu)
		}
	}
	unite := "ancienne-unite"
	if nouvelle {
		unite = "nouvelle-unite"
	}
	if got := lire(t, b.c.Unite); got != unite {
		t.Errorf("unité : %q, attendu %q", got, unite)
	}
}

func (b *banc) verifierEtat(t *testing.T, resultat, contient string) {
	t.Helper()
	e, ok := LireEtat(b.c)
	if !ok || e.Version != "2.3.1" || e.Resultat != resultat || !strings.Contains(e.Motif, contient) || e.Rapporte {
		t.Errorf("état %+v, attendu %s / %q", e, resultat, contient)
	}
	if _, err := os.Stat(cheminVerrou(b.c)); err == nil {
		t.Error("verrou non rendu")
	}
}

func TestBasculeReussie(t *testing.T) {
	b := nouveauBanc(t)
	r, m := b.bascule().Executer(b.plan)
	if r != ResultatInstalle || !strings.Contains(m, "porte de santé franchie en 3") {
		t.Fatalf("%s : %s", r, m)
	}
	b.verifierEnPlace(t, true)
	b.verifierEtat(t, ResultatInstalle, "porte de santé")
	for _, attendu := range []string{"vaultaire_client --install-unit", "systemctl reset-failed vaultaire_client",
		"systemctl restart vaultaire_client", "restorecon -F " + b.c.Binaire} {
		if !b.sys.aAppele(attendu) {
			t.Errorf("%q non joué : %v", attendu, b.sys.appels)
		}
	}
	if b.sys.aAppele("systemctl daemon-reload") {
		t.Error("retour arrière joué sur une réussite")
	}
	// La version précédente reste gardée ; la préparée est nettoyée.
	if lire(t, filepath.Join(b.plan.Repertoire, "precedent", "vaultaire_client")) != "ancien-vaultaire_client" {
		t.Error("garde perdue")
	}
	if _, err := os.Stat(filepath.Join(b.plan.Repertoire, "nouveau")); err == nil {
		t.Error("nouveau/ non nettoyé")
	}
	// Les modes de la pose.
	for _, f := range b.plan.Fichiers {
		info, _ := os.Stat(f.Destination)
		if info.Mode().Perm() != f.Mode {
			t.Errorf("%s : %v", f.Nom, info.Mode().Perm())
		}
	}
}

// Le service tient, mais le tunnel ne revient pas : retour arrière, et
// l'ancienne version est jugée SANS la sonde.
func TestBasculeTunnelAbsent(t *testing.T) {
	b := nouveauBanc(t)
	sondesApresRetour := 0
	b.sonde = func(retour bool) (Pong, error) {
		if retour {
			sondesApresRetour++
		}
		return Pong{Version: "2.3.1"}, nil
	}
	r, m := b.bascule().Executer(b.plan)
	if r != ResultatEchec || !strings.Contains(m, "revenue en arrière : le tunnel n'est pas rétabli") ||
		strings.Contains(m, "NE TIENT PAS") {
		t.Fatalf("%s : %s", r, m)
	}
	b.verifierEnPlace(t, false)
	b.verifierEtat(t, ResultatEchec, "tunnel")
	if sondesApresRetour != 0 {
		t.Errorf("l'ancienne version sondée %d fois", sondesApresRetour)
	}
	if b.h.Maintenant().Sub(time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)) < DelaiSante {
		t.Error("échéance non attendue")
	}
}

// Un service qui redémarre en boucle n'est pas « actif » : le PID change.
func TestBasculeServiceEnBoucle(t *testing.T) {
	b := nouveauBanc(t)
	b.service = func(retour bool, n int) (Service, error) {
		if retour {
			return Service{Actif: true, PID: 7}, nil
		}
		return Service{Actif: true, PID: 1000 + n}, nil
	}
	sondee := false
	b.sonde = func(bool) (Pong, error) { sondee = true; return Pong{Tunnel: true}, nil }
	r, m := b.bascule().Executer(b.plan)
	if r != ResultatEchec || !strings.Contains(m, "vient de (re)démarrer") {
		t.Fatalf("%s : %s", r, m)
	}
	if sondee {
		t.Error("sonde jouée avant la stabilité")
	}
	b.verifierEnPlace(t, false)
}

// Et si l'ancienne ne tient pas non plus, le motif le dit.
func TestBasculeAncienneNeTientPas(t *testing.T) {
	b := nouveauBanc(t)
	b.service = func(bool, int) (Service, error) { return Service{Actif: false}, nil }
	r, m := b.bascule().Executer(b.plan)
	if r != ResultatEchec || !strings.Contains(m, "NE TIENT PAS") {
		t.Fatalf("%s : %s", r, m)
	}
	b.verifierEnPlace(t, false)
}

func TestBasculeUniteRefusee(t *testing.T) {
	b := nouveauBanc(t)
	avant := b.sys.reponses
	b.sys.reponses = func(nom string, args []string) ([]byte, error) {
		if len(args) == 1 && args[0] == "--install-unit" {
			_ = os.WriteFile(b.c.Unite, []byte("unite-a-moitie"), 0o644)
			return []byte("unité refusée\n"), errors.New("exit status 1")
		}
		return avant(nom, args)
	}
	r, m := b.bascule().Executer(b.plan)
	if r != ResultatEchec || !strings.Contains(m, "l'unité n'a pas pu être écrite : unité refusée") {
		t.Fatalf("%s : %s", r, m)
	}
	b.verifierEnPlace(t, false)
	if b.sys.aAppele("systemctl restart vaultaire_client") && !b.retour {
		t.Error("redémarrage avant le retour arrière")
	}
}

func TestBasculeRedemarrageRefuse(t *testing.T) {
	b := nouveauBanc(t)
	avant := b.sys.reponses
	b.sys.reponses = func(nom string, args []string) ([]byte, error) {
		if nom == "systemctl" && len(args) > 0 && args[0] == "restart" && !b.retour {
			return []byte("Job failed\n"), errors.New("exit status 1")
		}
		return avant(nom, args)
	}
	if r, m := b.bascule().Executer(b.plan); r != ResultatEchec || !strings.Contains(m, "redémarrage refusé") {
		t.Fatalf("%s : %s", r, m)
	}
	b.verifierEnPlace(t, false)
}

// Disque plein au troisième fichier : les deux premiers sont remis, rien ne
// redémarre.
func TestBasculePoseInterrompue(t *testing.T) {
	b := nouveauBanc(t)
	n := 0
	avant := poserFichier
	t.Cleanup(func() { poserFichier = avant })
	poserFichier = func(src, dst string, mode os.FileMode) error {
		n++
		if n == 3 {
			return errors.New("no space left on device")
		}
		return poser(src, dst, mode)
	}
	r, m := b.bascule().Executer(b.plan)
	if r != ResultatEchec || !strings.Contains(m, "no space left on device — rien n'a changé") {
		t.Fatalf("%s : %s", r, m)
	}
	b.verifierEnPlace(t, false)
	if b.sys.aAppele("systemctl restart") || b.sys.aAppele("vaultaire_client --install-unit") {
		t.Errorf("%v", b.sys.appels)
	}
}

// Un fichier en place absent : sans lui, pas de retour arrière — on refuse
// avant de toucher quoi que ce soit.
func TestBasculeInstallationIncomplete(t *testing.T) {
	b := nouveauBanc(t)
	_ = os.Remove(destinations(b.c)["pam_ssh_auth_module.so"])
	r, m := b.bascule().Executer(b.plan)
	if r != ResultatRefuse || !strings.Contains(m, "version en place incomplète") {
		t.Fatalf("%s : %s", r, m)
	}
	if lire(t, b.c.Binaire) != "ancien-vaultaire_client" || len(b.sys.appels) != 0 {
		t.Errorf("installation touchée : %v", b.sys.appels)
	}
	b.verifierEtat(t, ResultatRefuse, "incomplète")
}

// Entre la préparation et la bascule, un fichier préparé a changé.
func TestBasculeSourceModifiee(t *testing.T) {
	b := nouveauBanc(t)
	ecrire(t, b.plan.Fichiers[2].Source, "remplacé", 0o755)
	r, m := b.bascule().Executer(b.plan)
	if r != ResultatRefuse || !strings.Contains(m, "fichier préparé modifié") {
		t.Fatalf("%s : %s", r, m)
	}
	b.verifierEnPlace(t, false)
}

func TestLirePlanIncomplet(t *testing.T) {
	d := t.TempDir()
	if _, err := LirePlan(d); err == nil {
		t.Error("plan absent lu")
	}
	ecrire(t, filepath.Join(d, NomPlan), `{"version":"2.3.1","binaire":"/usr/bin/vaultaire_client","fichiers":[]}`, 0o600)
	if _, err := LirePlan(d); err == nil {
		t.Error("plan sans fichiers lu")
	}
}
