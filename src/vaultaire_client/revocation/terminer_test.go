//go:build linux

package revocation

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TO-DO 133 — le verrouillage coupe ce que le compte a d'ouvert.
//
// Ce paquet n'avait AUCUN test : c'est ce qui a laissé l'aide de `kill -u`
// affirmer pendant des mois que les sessions étaient fermées, alors que le mode
// par défaut se réduisait à deux écritures dans /etc/shadow.
//
// Ces tests n'exécutent aucune commande et ne tuent aucun processus : ils
// observent CE QUE l'agent lancerait, et dans quel ordre. Le geste réel — une
// session SSH ouverte qui se ferme — est une recette, voir A_TESTER.md.

// compteAutre rend un compte local réel qui n'est ni root ni celui des tests.
func compteAutre(t *testing.T) (nom, uid string) {
	t.Helper()
	for _, candidat := range []string{"nobody", "daemon", "bin"} {
		c, err := user.Lookup(candidat)
		if err != nil || c.Uid == "0" || c.Uid == strconv.Itoa(os.Getuid()) {
			continue
		}
		return candidat, c.Uid
	}
	t.Skip("aucun compte local utilisable pour ce test")
	return "", ""
}

// observer remplace les commandes par un relevé, et fige le système autour.
type observation struct {
	commandes []string
	// vivants est rendu par les comptages successifs ; le dernier se répète.
	vivants []int
	appels  int
}

func observer(t *testing.T, logind bool, vivants ...int) *observation {
	t.Helper()
	o := &observation{vivants: vivants}

	ancienExec, ancienPresente, ancienLogind, ancienCompte := executer, commandePresente, logindActif, processusDe
	ancienneAttente, ancienPas := attenteDeLaFin, pasDeScrutation
	anciensComptes := comptesDuDomaine

	// Les comptes que « l'agent a provisionnés », pour ces tests : ceux que
	// compteAutre peut rendre. /etc/vaultaire/uid.map n'existe pas ici.
	comptesDuDomaine = func() ([]string, error) { return []string{"nobody", "daemon", "bin"}, nil }

	executer = func(nom string, args ...string) error {
		o.commandes = append(o.commandes, nom+" "+strings.Join(args, " "))
		if nom == "pkill" {
			// Ce que rend pkill quand rien ne correspond : pas une erreur.
			return errors.New("exit status 1")
		}
		return nil
	}
	commandePresente = func(string) bool { return true }
	logindActif = func() bool { return logind }
	processusDe = func(string) int {
		i := o.appels
		o.appels++
		if len(o.vivants) == 0 {
			return 0
		}
		if i >= len(o.vivants) {
			i = len(o.vivants) - 1
		}
		return o.vivants[i]
	}
	attenteDeLaFin, pasDeScrutation = 50*time.Millisecond, time.Millisecond

	t.Cleanup(func() {
		executer, commandePresente, logindActif, processusDe = ancienExec, ancienPresente, ancienLogind, ancienCompte
		attenteDeLaFin, pasDeScrutation = ancienneAttente, ancienPas
		comptesDuDomaine = anciensComptes
	})
	return o
}

// LE test du point : le mode par défaut ne se réduit plus à /etc/shadow.
func TestLeVerrouillageCoupeCeQuiEstOuvert(t *testing.T) {
	nom, uid := compteAutre(t)
	o := observer(t, true, 4, 4, 0)

	resultat, err := Apply(ModeSoft, nom)
	if err != nil || resultat != ResultApplied {
		t.Fatalf("Apply = %q, %v", resultat, err)
	}

	attendu := []string{
		"usermod -L " + nom,
		"chage -E 1 " + nom,
		"loginctl terminate-user " + uid,
		"pkill -KILL -U " + uid,
		"pkill -KILL -u " + uid,
	}
	if strings.Join(o.commandes, " ; ") != strings.Join(attendu, " ; ") {
		t.Fatalf("commandes :\n  %s\nattendu :\n  %s\n— le compte doit etre verrouille AVANT d'etre coupe, "+
			"sinon la personne ejectee se reconnecte dans l'intervalle",
			strings.Join(o.commandes, "\n  "), strings.Join(attendu, "\n  "))
	}
}

// Sans systemd-logind — un conteneur, une image minimale — `loginctl` échouerait
// à chaque appel. On ne le lance pas ; `pkill` fait le travail.
func TestSansLogindSeulPkillEstLance(t *testing.T) {
	nom, _ := compteAutre(t)
	o := observer(t, false, 2, 0)

	if _, err := Apply(ModeSoft, nom); err != nil {
		t.Fatalf("%v", err)
	}
	for _, c := range o.commandes {
		if strings.HasPrefix(c, "loginctl") {
			t.Errorf("loginctl lance sans systemd-logind : %s", c)
		}
	}
	if !strings.Contains(strings.Join(o.commandes, ";"), "pkill -KILL") {
		t.Errorf("aucun pkill : %v", o.commandes)
	}
}

// Ce qui RESTE décide, pas les codes de retour. Un ordre qui laisse des
// processus en vie est un échec : le serveur doit le voir et rejouer, au lieu
// d'afficher une machine « traitée » où la personne travaille encore.
func TestDesProcessusEncoreEnVieFontEchouerLOrdre(t *testing.T) {
	nom, _ := compteAutre(t)
	observer(t, true, 3)

	resultat, err := Apply(ModeSoft, nom)
	if err == nil {
		t.Fatalf("Apply = %q sans erreur alors que 3 processus survivent", resultat)
	}
	if !strings.Contains(err.Error(), "verrouillé") || !strings.Contains(err.Error(), "3 processus") {
		t.Errorf("erreur = %q : elle doit dire que le compte EST verrouille, et ce qui reste", err)
	}
}

// Un compte qui n'a rien d'ouvert : c'est le cas de presque toutes les machines
// visées par un ordre, et ce n'est pas un échec.
func TestUnCompteSansProcessusEstUnSucces(t *testing.T) {
	nom, _ := compteAutre(t)
	observer(t, true, 0)
	if resultat, err := Apply(ModeSoft, nom); err != nil || resultat != ResultApplied {
		t.Fatalf("Apply = %q, %v", resultat, err)
	}
}

// Le déverrouillage ne coupe rien, et ne lance aucune des commandes de coupure.
func TestLeDeverrouillageNeCoupeRien(t *testing.T) {
	nom, _ := compteAutre(t)
	o := observer(t, true, 5)
	if _, err := Apply(ModeUnlock, nom); err != nil {
		t.Fatalf("%v", err)
	}
	for _, c := range o.commandes {
		if strings.HasPrefix(c, "pkill") || strings.HasPrefix(c, "loginctl") {
			t.Errorf("le deverrouillage a lance %q", c)
		}
	}
}

// Le mode hard coupe par le même geste, avant `userdel`.
func TestLaSuppressionCoupeAvantDeSupprimer(t *testing.T) {
	nom, uid := compteAutre(t)
	o := observer(t, false, 1, 0)
	if _, err := Apply(ModeHard, nom); err != nil {
		t.Fatalf("%v", err)
	}
	suite := strings.Join(o.commandes, " ; ")
	iKill, iDel := strings.Index(suite, "pkill -KILL -U "+uid), strings.Index(suite, "userdel -r "+nom)
	if iKill < 0 || iDel < 0 || iKill > iDel {
		t.Errorf("commandes = %q : les processus doivent etre tues avant userdel, qui refuse un compte en session", suite)
	}
}

// JAMAIS root. L'ordre vient du réseau, et sur l'uid 0 aucune de ces commandes
// ne se rattrape. Deux barrières : root n'est pas un compte que l'agent a
// provisionné, donc un ordre ne le DÉSIGNE pas ; et s'il y parvenait malgré
// tout, l'application le refuse.
func TestAucunOrdreDestructeurNeToucheRoot(t *testing.T) {
	if _, err := user.Lookup("root"); err != nil {
		t.Skip("pas de compte root sur cette machine")
	}
	for _, mode := range []string{ModeSoft, ModeHard} {
		// Première barrière : l'ordre ne trouve pas root.
		o := observer(t, true, 0)
		if resultat, err := Apply(mode, "root"); err != nil || resultat != ResultAlreadyAbsent {
			t.Errorf("mode %s sur root : %q, %v — attendu « sans objet »", mode, resultat, err)
		}
		if len(o.commandes) != 0 {
			t.Errorf("mode %s : des commandes ont ete lancees sur root : %v", mode, o.commandes)
		}

		// Seconde : même si la carte des comptes le désignait.
		comptesDuDomaine = func() ([]string, error) { return []string{"root"}, nil }
		if resultat, err := Apply(mode, "root"); err == nil {
			t.Errorf("mode %s applique a root : %q", mode, resultat)
		}
		if len(o.commandes) != 0 {
			t.Errorf("mode %s : des commandes ont ete lancees sur root : %v", mode, o.commandes)
		}
	}
}

// LE défaut trouvé sur le banc. `vlt kill -u bob.durand` — la forme de toute la
// documentation — envoyait « bob.durand » ; le compte local s'appelle
// « bob.durand@acme.lan ». L'agent ne trouvait rien, acquittait « sans objet »,
// et rien n'était verrouillé nulle part.
func TestUnNomDAnnuaireDesigneLesComptesLocauxDeLaPersonne(t *testing.T) {
	provisionnes := []string{
		"alice.martin@acme.lan",
		"bob.durand@acme.lan",
		"bob.durand@filiale.lan",
		"bob.durandal@acme.lan", // un autre : le préfixe ne suffit pas
		"bob@acme.lan",
	}

	if got := strings.Join(comptesDeLaPersonne("bob.durand", provisionnes), ","); got != "bob.durand@acme.lan,bob.durand@filiale.lan" {
		t.Errorf("« bob.durand » designe %q, attendu ses deux comptes et aucun autre", got)
	}
	if got := comptesDeLaPersonne("bob.durandal", provisionnes); len(got) != 1 || got[0] != "bob.durandal@acme.lan" {
		t.Errorf("« bob.durandal » designe %v", got)
	}
	if got := comptesDeLaPersonne("inconnu", provisionnes); len(got) != 0 {
		t.Errorf("un nom que personne ne porte designe %v", got)
	}
}

// Un compte que l'agent n'a PAS provisionné n'est jamais touché, même s'il
// porte le nom d'une personne de l'annuaire : c'est un compte de la machine,
// pas le sien.
func TestUnCompteQueLAgentNAPasCreeNEstPasTouche(t *testing.T) {
	nom, _ := compteAutre(t)
	o := observer(t, true, 4)
	comptesDuDomaine = func() ([]string, error) { return nil, nil }

	resultat, err := Apply(ModeSoft, nom)
	if err != nil || resultat != ResultAlreadyAbsent {
		t.Fatalf("Apply = %q, %v — attendu « sans objet »", resultat, err)
	}
	if len(o.commandes) != 0 {
		t.Errorf("un compte local etranger a l'agent a ete vise : %v", o.commandes)
	}
}

// Une carte des comptes illisible : on ne sait plus lesquels sont les nôtres,
// donc on n'en touche aucun.
func TestSansCarteDesComptesRienNEstTouche(t *testing.T) {
	nom, _ := compteAutre(t)
	o := observer(t, true, 4)
	comptesDuDomaine = func() ([]string, error) { return nil, errors.New("uid.map illisible") }

	if resultat, err := Apply(ModeSoft, nom); err != nil || resultat != ResultAlreadyAbsent {
		t.Fatalf("Apply = %q, %v", resultat, err)
	}
	if len(o.commandes) != 0 {
		t.Errorf("des commandes ont ete lancees sans savoir a qui est le compte : %v", o.commandes)
	}
}

// Ni le compte sous lequel tourne l'agent. En production c'est root, déjà
// refusé ; ce contrôle est celui qui tient si l'agent tournait un jour sous un
// autre compte.
func TestLAgentNeSeTuePasLuiMeme(t *testing.T) {
	moi, err := user.Current()
	if err != nil || moi.Uid == "0" {
		t.Skip("ce test demande un compte courant qui ne soit pas root")
	}
	o := observer(t, true, 9)
	if err := terminerLeCompte(moi.Username); err == nil {
		t.Fatal("l'agent a accepte de terminer son propre compte")
	}
	for _, c := range o.commandes {
		if strings.HasPrefix(c, "pkill") || strings.HasPrefix(c, "loginctl") {
			t.Errorf("commande lancee contre le compte de l'agent : %s", c)
		}
	}
}

// --- le comptage -------------------------------------------------------------

func TestAppartientA(t *testing.T) {
	cas := []struct {
		nom, etat, uids string
		attendu         bool
	}{
		{"le compte, en vie", "S (sleeping)", "1001\t1001\t1001\t1001", true},
		{"uid effectif seul", "R (running)", "0\t1001\t0\t0", true},
		{"uid reel seul", "S (sleeping)", "1001\t0\t0\t0", true},
		{"un autre compte", "S (sleeping)", "1002\t1002\t1002\t1002", false},
		{"sauvegarde seul : ne compte pas", "S (sleeping)", "0\t0\t1001\t0", false},
		{"un zombie du compte", "Z (zombie)", "1001\t1001\t1001\t1001", false},
		{"un uid qui en contient un autre", "S (sleeping)", "11001\t11001\t11001\t11001", false},
	}
	for _, c := range cas {
		statut := "Name:\tbash\nState:\t" + c.etat + "\nUid:\t" + c.uids + "\nGid:\t1001\t1001\t1001\t1001\n"
		if got := appartientA(statut, "1001"); got != c.attendu {
			t.Errorf("%s : %v, attendu %v", c.nom, got, c.attendu)
		}
	}
}

// Le comptage réel, sur le seul compte dont on connaît un processus : celui du
// test. Il lit /proc sans lancer aucun binaire.
func TestLeComptageVoitAuMoinsCeProcessus(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("/proc indisponible")
	}
	if n := compterLesProcessus(strconv.Itoa(os.Getuid())); n < 1 {
		t.Errorf("%d processus comptes pour le compte courant, attendu au moins celui du test", n)
	}
	if n := compterLesProcessus("4294967294"); n != 0 {
		t.Errorf("%d processus comptes pour un uid que personne ne porte", n)
	}
}

// La seconde ceinture : appelée directement, la coupure refuse root elle aussi.
func TestLaCoupureRefuseRootMemeAppeleeDirectement(t *testing.T) {
	if _, err := user.Lookup("root"); err != nil {
		t.Skip("pas de compte root sur cette machine")
	}
	o := observer(t, true, 9)
	if err := terminerLeCompte("root"); err == nil {
		t.Fatal("la coupure a accepte root")
	}
	if len(o.commandes) != 0 {
		t.Errorf("commandes lancees contre root : %v", o.commandes)
	}
}

// L'essai RÉEL : de vrais processus, de vraies commandes.
//
// Jamais lancé par défaut — il tue tout ce qui tourne sous un compte, et le
// seul compte dont un test peut disposer est un compte créé pour lui. Pour le
// jouer, en root :
//
//	useradd -m vtessai
//	VAULTAIRE_ESSAI_COMPTE=vtessai go test ./revocation -run TestEssaiReel -v
//	userdel -r vtessai
//
// Il lance trois processus sous ce compte, dont un détaché de tout terminal —
// ce qu'un `nohup` ou un `tmux` laisse derrière une session fermée —, puis
// vérifie qu'il n'en reste aucun.
func TestEssaiReelDeLaCoupure(t *testing.T) {
	nom := os.Getenv("VAULTAIRE_ESSAI_COMPTE")
	if nom == "" {
		t.Skip("VAULTAIRE_ESSAI_COMPTE absent : essai reel non demande")
	}
	if os.Getuid() != 0 {
		t.Skip("l'essai reel demande root")
	}
	compte, err := user.Lookup(nom)
	if err != nil {
		t.Fatalf("compte %s introuvable : %v", nom, err)
	}
	uid, _ := strconv.Atoi(compte.Uid)
	gid, _ := strconv.Atoi(compte.Gid)

	lancer := func(detache bool) *exec.Cmd {
		cmd := exec.Command("sleep", "600")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
			Setsid:     detache,
		}
		if err := cmd.Start(); err != nil {
			t.Fatalf("lancement sous %s : %v", nom, err)
		}
		return cmd
	}
	processus := []*exec.Cmd{lancer(false), lancer(false), lancer(true)}
	// Relevés en arrière-plan : sans cela ils resteraient zombies, et le test
	// ne dirait pas ce que verrait un `ps`.
	for _, p := range processus {
		go func(p *exec.Cmd) { _ = p.Wait() }(p)
	}
	time.Sleep(200 * time.Millisecond)

	if avant := compterLesProcessus(compte.Uid); avant < 3 {
		t.Fatalf("%d processus comptes avant la coupure, attendu au moins 3", avant)
	}
	debut := time.Now()
	if err := terminerLeCompte(nom); err != nil {
		t.Fatalf("coupure : %v", err)
	}
	t.Logf("coupure en %s", time.Since(debut).Round(time.Millisecond))
	if reste := compterLesProcessus(compte.Uid); reste != 0 {
		t.Errorf("%d processus de %s encore en vie", reste, nom)
	}
}
