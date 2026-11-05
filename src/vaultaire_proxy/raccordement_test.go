package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Le proxy sans core — TO-DO 158.

// LE TEST DEMANDÉ : un proxy démarré sans aucun core, sans session, relaie par
// son relais « liste ». Aucune session n'existe dans ce test, et rien n'en
// simule une : les relais s'ouvrent seuls.
func TestSansCoreUnRelaisListeRelaie(t *testing.T) {
	// La cible LOCALE : elle n'a pas besoin du core pour répondre.
	cible, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cible.Close()
	go func() {
		for {
			c, err := cible.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("service-local"))
			_ = c.Close()
		}
	}()

	portDucky, portRelais := portLibre(t), portLibre(t)
	suite := ""
	fichier := fichierDEssai(portDucky, suite) + fmt.Sprintf(
		"  - nom: intranet\n    type: https\n    ecoute: \"127.0.0.1:%d\"\n    cibles: {source: liste, adresses: [\"%s\"]}\n",
		portRelais, cible.Addr().String())
	p := demarrerProxyDEssai(t, portDucky, t.TempDir(), fichier)

	if n := p.relaisActifs(); n != 2 {
		t.Fatalf("%d relais actif(s) sans core, attendu 2 (ducky et intranet)", n)
	}

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", portRelais), 2*time.Second)
	if err != nil {
		t.Fatalf("le relais « liste » n'écoute pas sans core : %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	recu, _ := io.ReadAll(c)
	if string(recu) != "service-local" {
		t.Fatalf("le relais « liste » n'a pas relayé sans core : reçu %q", recu)
	}

	// Le relais Ducky écoute lui aussi, et refuse franchement : sa cible (le
	// core du fichier) ne répond pas. L'agent passe au nœud suivant.
	d, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", portDucky), 2*time.Second)
	if err != nil {
		t.Fatalf("le relais Ducky n'écoute pas sans core : %v", err)
	}
	defer d.Close()
	_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := d.Read(make([]byte, 16)); err == nil {
		t.Fatalf("le relais Ducky a rendu %d octet(s) sans core vers qui relayer", n)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("le relais Ducky sans core laisse la connexion pendue au lieu de refuser")
	}
}

// journalDEssai garde les lignes émises.
type journalDEssai struct{ lignes []string }

func (j *journalDEssai) ecrire(niveau, message string) {
	j.lignes = append(j.lignes, niveau+" "+message)
}

func (j *journalDEssai) compter(niveau string) int {
	n := 0
	for _, l := range j.lignes {
		if strings.HasPrefix(l, niveau+" ") {
			n++
		}
	}
	return n
}

// L'absence de core n'arrête plus le proxy : il attend, sans limite, et le
// DIT. Le raccordement et le compte rendu n'ont lieu qu'une fois la session là.
func TestLeRaccordementAttendLeCoreSansLimite(t *testing.T) {
	var (
		j       journalDEssai
		delais  []time.Duration
		ordre   []string
		horloge = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	)
	const echecs = 4

	raccordement{
		attendre: func(d time.Duration) (string, error) {
			delais = append(delais, d)
			horloge = horloge.Add(d)
			if len(delais) <= echecs {
				if len(ordre) != 0 {
					t.Errorf("essai %d : le proxy s'est raccordé sans session (%v)", len(delais), ordre)
				}
				return "", errors.New("aucune session authentifiée")
			}
			return "session-42", nil
		},
		rejoindre:    func() error { ordre = append(ordre, "rejoindre"); return nil },
		ensuite:      func() { ordre = append(ordre, "ensuite") },
		relaisActifs: func() int { return 2 },
		journal:      j.ecrire,
		premiere:     30 * time.Second,
		rappel:       5 * time.Minute,
		maintenant:   func() time.Time { return horloge },
	}.executer()

	// Le premier délai est celui au bout duquel le proxy S'ARRÊTAIT ; les
	// suivants sont le rappel. Aucun abandon.
	attendus := []time.Duration{30 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	if fmt.Sprint(delais) != fmt.Sprint(attendus) {
		t.Errorf("délais d'attente %v, attendu %v", delais, attendus)
	}
	if n := j.compter("ERROR"); n != echecs {
		t.Errorf("%d ligne(s) ERROR pour %d attente(s) sans core : chaque échéance doit se lire\n%s",
			n, echecs, strings.Join(j.lignes, "\n"))
	}
	premiere := j.lignes[0]
	for _, attendu := range []string{"aucun core joint depuis 30s", "2 relais", "sans fin", "PAS annoncé"} {
		if !strings.Contains(premiere, attendu) {
			t.Errorf("la première alarme ne dit pas %q : %s", attendu, premiere)
		}
	}
	if !strings.Contains(j.lignes[echecs-1], "15m30s") {
		t.Errorf("l'alarme ne dit pas depuis combien de temps le core manque : %s", j.lignes[echecs-1])
	}
	if strings.Join(ordre, ",") != "rejoindre,ensuite" {
		t.Errorf("après la session : %v — attendu le raccordement, puis le compte rendu, une fois chacun", ordre)
	}
	if dernier := j.lignes[len(j.lignes)-1]; !strings.Contains(dernier, "INFO proxy en ligne, session session-42") {
		t.Errorf("l'arrivée de la session n'est pas journalisée : %s", dernier)
	}
}

// Avec un core présent, rien ne change : raccordé tout de suite, sans alarme.
func TestAvecUnCoreLeRaccordementEstImmediat(t *testing.T) {
	var j journalDEssai
	var ordre []string
	raccordement{
		attendre:     func(time.Duration) (string, error) { return "s", nil },
		rejoindre:    func() error { ordre = append(ordre, "rejoindre"); return nil },
		ensuite:      func() { ordre = append(ordre, "ensuite") },
		relaisActifs: func() int { return 1 },
		journal:      j.ecrire,
		premiere:     time.Second, rappel: time.Second, maintenant: time.Now,
	}.executer()
	if j.compter("ERROR") != 0 || strings.Join(ordre, ",") != "rejoindre,ensuite" {
		t.Fatalf("core présent : %v\n%s", ordre, strings.Join(j.lignes, "\n"))
	}
}

// Un raccordement au cluster qui échoue n'arrête rien : le proxy est connecté,
// ses relais sont ouverts, et il rend compte.
func TestUnRaccordementRefuseNArretePasLeProxy(t *testing.T) {
	var j journalDEssai
	ensuite := 0
	raccordement{
		attendre:     func(time.Duration) (string, error) { return "s", nil },
		rejoindre:    func() error { return errors.New("aucune adresse non locale") },
		ensuite:      func() { ensuite++ },
		relaisActifs: func() int { return 1 },
		journal:      j.ecrire,
		premiere:     time.Second, rappel: time.Second, maintenant: time.Now,
	}.executer()
	if ensuite != 1 {
		t.Errorf("le compte rendu des relais n'est pas lancé après un raccordement refusé (%d)", ensuite)
	}
	if j.compter("ERROR") != 1 || !strings.Contains(strings.Join(j.lignes, "\n"), "aucune adresse non locale") {
		t.Errorf("le refus du raccordement n'est pas journalisé :\n%s", strings.Join(j.lignes, "\n"))
	}
}

// Sentinelle sur main : c'est l'ORDRE qui faisait le défaut, et aucun test ne
// peut jouer main. Les relais s'ouvrent avant toute attente de session, et
// main n'appelle plus la fonction qui attend — et s'arrête — avant de rendre
// la main.
func TestMainOuvreLesRelaisAvantDAttendreLeCore(t *testing.T) {
	brut, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	// Le code seul : les commentaires citent ce qu'on interdit.
	var code strings.Builder
	for _, ligne := range strings.Split(string(brut), "\n") {
		if i := strings.Index(ligne, "//"); i >= 0 {
			ligne = ligne[:i]
		}
		code.WriteString(ligne + "\n")
	}
	source := code.String()

	if strings.Contains(source, "ducky.Start(") {
		t.Error("main appelle ducky.Start : il attend une session trente secondes puis s'arrête, sans avoir ouvert un relais")
	}
	position := func(motif string) int {
		i := strings.Index(source, motif)
		if i < 0 {
			t.Fatalf("main.go ne contient plus %q : la sentinelle ne regarde plus rien", motif)
		}
		return i
	}
	charger, lancer := position("relais.Charger("), position("ducky.Lancer(")
	ouvrir := position("pilote.demarrer(")
	attendre, rejoindre := position("ducky.Attendre("), position("ducky.RejoindreCluster(")

	if !(charger < lancer) {
		t.Error("les relais ne sont plus lus avant le lancement de la session : une faute de configuration n'arrête plus le proxy d'emblée")
	}
	if !(lancer < ouvrir) {
		t.Error("les relais s'ouvrent avant que le répertoire des clés ne soit connu (ducky.Lancer le pose) : la copie locale ne serait pas lue")
	}
	if !(ouvrir < attendre && ouvrir < rejoindre) {
		t.Error("les relais s'ouvrent APRÈS l'attente de la session ou le raccordement : sans core, aucun port ne s'ouvre")
	}
	if !strings.Contains(source, "raccordement{") || !strings.Contains(source, "}.executer)") {
		t.Error("le raccordement n'est plus lancé en fond : main attendrait le core avant de rendre la main")
	}
}
