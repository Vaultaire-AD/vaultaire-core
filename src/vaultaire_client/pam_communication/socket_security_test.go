package pamcommunication

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"vaultaire_client/storage"
)

// Tests de non-exploitabilité du canal PAM.
//
// # La faille dont ces tests protègent
//
// Le socket vivait dans /tmp, en mode 0666. Le mot de passe en clair de chaque
// connexion y transite.
//
// Deux exploitations distinctes :
//
//   - 0666 : tout compte local pouvait émettre des « check », donc tester des
//     mots de passe contre l'annuaire central sans limite ni trace ;
//   - /tmp est accessible en écriture à tous. Quand l'agent ne tournait pas,
//     n'importe quel compte pouvait CRÉER le socket à cette place, capturer les
//     mots de passe et répondre {"status":"success","is_admin":true} — ce dont
//     le module PAM tire un ajout au groupe sudo. Élévation vers root.
//
// # Ce que ces tests peuvent, et ce qu'ils ne peuvent pas
//
// Ils s'exécutent sous un compte ordinaire, pas sous root. C'est une CHANCE
// pour le cas qui compte : la connexion de test est, du point de vue de
// l'agent, exactement celle d'un attaquant non privilégié. Le refus est donc
// vérifié en conditions réelles.
//
// En revanche le chemin nominal — un appelant root accepté — n'est pas
// vérifiable ici. Il l'est indirectement : peerIsRoot rapporte l'UID réel du
// pair, ce que TestPeerCredRapporteLIdentiteReelle contrôle.

// serveurDeTest démarre l'écoute sur un chemin temporaire.
func serveurDeTest(t *testing.T) string {
	t.Helper()

	// t.TempDir() produit un chemin long, et sun_path est limité à 108 octets :
	// le bind échouerait avec « invalid argument », qui ne dit pas que la cause
	// est la longueur. On prend donc un répertoire court, sous /tmp.
	//
	// Le chemin de production, /run/vaultaire/pam.sock, tient largement — mais
	// le module PAM contrôle quand même la longueur explicitement, parce qu'un
	// strncpy tronque sans le dire et désignerait alors un autre fichier.
	base, err := os.MkdirTemp("/tmp", "vlt")
	if err != nil {
		t.Fatalf("répertoire temporaire : %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	chemin := filepath.Join(base, "d", "pam.sock")

	// serveSocket et non UnixSocketServer : le chemin passe en paramètre, et
	// aucune variable globale n'entre en jeu. L'écoute ne s'arrêtant jamais,
	// deux tests successifs qui se seraient partagé une globale auraient couru
	// l'un contre l'autre — ce que -race signale.
	go serveSocket(chemin)

	// Attente active courte : l'écoute démarre dans une goroutine, et tester
	// avant qu'elle ne soit prête donnerait un faux négatif.
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(chemin); err == nil {
			return chemin
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("le socket %s n'a pas été créé", chemin)
	return ""
}

// TestSocketNestPasAccessibleAuxAutres : le mode 0600, vérifié sur le fichier.
//
// C'est l'assertion qui remplace le 0666 d'origine. Un socket en 0666 est
// ouvert à tout compte de la machine.
func TestSocketNestPasAccessibleAuxAutres(t *testing.T) {
	chemin := serveurDeTest(t)

	info, err := os.Stat(chemin)
	if err != nil {
		t.Fatalf("stat : %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("mode du socket = %o, attendu 600", mode)
	}
	// Formulé aussi en termes d'exploitation, pour que l'intention survive à une
	// modification du mode attendu.
	if mode&0o077 != 0 {
		t.Errorf("le socket est accessible au-delà de son propriétaire (mode %o) : "+
			"tout compte local pourrait tester des mots de passe contre l'annuaire", mode)
	}
}

// TestRepertoireNestPasAccessibleAuxAutres : le répertoire en 0700.
//
// C'est LA protection. Même si le socket disparaît — agent arrêté, plantage —
// un non-root ne peut rien créer à sa place. C'est exactement ce que /tmp
// permettait.
func TestRepertoireNestPasAccessibleAuxAutres(t *testing.T) {
	chemin := serveurDeTest(t)

	info, err := os.Stat(filepath.Dir(chemin))
	if err != nil {
		t.Fatalf("stat du répertoire : %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o700 {
		t.Errorf("mode du répertoire = %o, attendu 700", mode)
	}
	if mode&0o022 != 0 {
		t.Errorf("le répertoire est accessible en écriture au-delà de son propriétaire (mode %o) : "+
			"un attaquant pourrait y placer son propre socket quand l'agent ne tourne pas", mode)
	}
}

// TestRepertoireExistantEstResserre : un répertoire déjà là doit être corrigé.
//
// MkdirAll n'ajuste PAS le mode d'un répertoire existant. Sans Chmod explicite,
// une machine où /run/vaultaire aurait été créé en 0755 par un script de
// déploiement garderait ce mode indéfiniment — et la protection principale
// serait absente sans que rien ne le signale.
func TestRepertoireExistantEstResserre(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prealable")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("préparation : %v", err)
	}

	if err := ensureSocketDir(dir); err != nil {
		t.Fatalf("ensureSocketDir : %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat : %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("un répertoire préexistant en 0755 est resté en %o", info.Mode().Perm())
	}
}

// TestAppelantNonRootEstRefuse est le test central.
//
// Le processus de test n'est pas root : sa connexion est, pour l'agent,
// exactement celle d'un attaquant local. Elle doit être fermée sans qu'aucune
// requête ne soit traitée.
//
// Le test est ignoré si les tests tournent en root — auquel cas la connexion
// serait légitimement acceptée, et le test ne mesurerait rien.
func TestAppelantNonRootEstRefuse(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("exécuté en root : le refus d'un appelant non privilégié n'est pas observable")
	}

	avant := ConnexionsRefusees()
	chemin := serveurDeTest(t)

	conn, err := net.Dial("unix", chemin)
	if err != nil {
		// Le refus peut aussi venir des permissions du répertoire : c'est un
		// succès, pas un échec.
		t.Logf("connexion impossible dès l'ouverture (permissions) : %v", err)
		return
	}
	defer func() { _ = conn.Close() }()

	// Une requête qu'un attaquant enverrait : sonder un mot de passe.
	requete := `{"check":{"user":"victime@dom","password":"essai"}}`
	if _, err := conn.Write([]byte(requete)); err != nil {
		t.Logf("écriture refusée : %v", err)
		return
	}

	// L'agent doit fermer sans répondre. Une réponse — même « failed » —
	// signifierait que la requête a été traitée, donc qu'un compte non
	// privilégié dispose d'un oracle de mot de passe.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline : %v", err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)

	if err == nil && n > 0 {
		t.Fatalf("l'agent a répondu %q à un appelant non privilégié : "+
			"le canal est un oracle de mot de passe", string(buf[:n]))
	}
	// Toute fermeture est un succès. Ce qui compte est l'ABSENCE de réponse.
	//
	// EOF si le serveur ferme proprement, ECONNRESET s'il ferme alors que la
	// requête n'a pas été lue — ce qui est le cas ici, et c'est même préférable :
	// la connexion est coupée AVANT que le moindre octet de l'attaquant ne soit
	// analysé.
	switch {
	case err == nil:
		// n == 0 sans erreur : rien reçu, refus effectif.
	case err == io.EOF, errors.Is(err, syscall.ECONNRESET), errors.Is(err, net.ErrClosed):
		// Refus effectif.
	default:
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			// Rien renvoyé mais connexion maintenue : le refus tient, la
			// fermeture immédiate serait plus propre. On le signale sans échouer.
			t.Log("aucune réponse, mais la connexion n'a pas été fermée immédiatement")
		} else {
			t.Fatalf("erreur inattendue : %v", err)
		}
	}

	// L'assertion qui compte vraiment.
	//
	// L'absence de réponse ne prouve RIEN à elle seule : sans le contrôle
	// d'identité, la requête serait traitée puis échouerait faute de core
	// joignable — et le client verrait la même chose. Vérifié par mutation :
	// retirer le contrôle laissait ce test au vert tant que cette ligne
	// manquait.
	if ConnexionsRefusees() <= avant {
		t.Fatalf("aucun refus enregistré : la requête a été TRAITÉE, "+
			"le canal reste un oracle de mot de passe (compteur %d)", ConnexionsRefusees())
	}
}

// TestPeerCredRapporteLIdentiteReelle vérifie le mécanisme lui-même.
//
// Sans cela, TestAppelantNonRootEstRefuse pourrait passer pour une mauvaise
// raison — une erreur qui ferme la connexion avant même la vérification.
func TestPeerCredRapporteLIdentiteReelle(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair : %v", err)
	}

	f := os.NewFile(uintptr(fds[0]), "paire")
	defer func() { _ = f.Close() }()
	defer func() { _ = syscall.Close(fds[1]) }()

	conn, err := net.FileConn(f)
	if err != nil {
		t.Fatalf("FileConn : %v", err)
	}
	defer func() { _ = conn.Close() }()

	root, desc, err := peerIsRoot(conn)
	if err != nil {
		t.Fatalf("peerIsRoot : %v", err)
	}

	attendu := os.Getuid() == 0
	if root != attendu {
		t.Errorf("peerIsRoot = %v pour un pair d'uid %d (%s)", root, os.Getuid(), desc)
	}
	if desc == "" {
		t.Error("la description du pair est vide : le journal ne dirait pas qui a tenté")
	}
}

// TestAncienSocketEstSupprime : le socket résiduel dans /tmp doit disparaître.
//
// Tant qu'il existe, un module PAM non mis à jour continue de s'y connecter —
// et le point de collecte de mots de passe reste ouvert.
func TestAncienSocketEstSupprime(t *testing.T) {
	// LegacySocketPath est une constante ; on ne peut pas la déplacer. On vérifie
	// donc le comportement sur le chemin réel, en ne créant le leurre que si
	// l'emplacement est libre — pour ne pas perturber un agent qui tournerait
	// sur la machine de test.
	if _, err := os.Stat(storage.LegacySocketPath); err == nil {
		t.Skip("un fichier occupe déjà l'ancien emplacement : test non concluant")
	}

	leurre, err := net.Listen("unix", storage.LegacySocketPath)
	if err != nil {
		t.Skipf("impossible de créer le leurre dans /tmp : %v", err)
	}
	defer func() {
		_ = leurre.Close()
		_ = os.Remove(storage.LegacySocketPath)
	}()

	serveurDeTest(t)

	if _, err := os.Stat(storage.LegacySocketPath); err == nil {
		t.Errorf("l'ancien socket %s n'a pas été supprimé au démarrage",
			storage.LegacySocketPath)
	}
}

// TestRequeteValideEstBienFormee documente la requête que l'agent attend.
//
// Sans ce contrôle, TestAppelantNonRootEstRefuse pourrait passer parce que la
// requête est malformée et rejetée pour cette raison — et non parce que
// l'appelant a été refusé.
func TestRequeteValideEstBienFormee(t *testing.T) {
	requete := `{"check":{"user":"victime@dom","password":"essai"}}`

	var message map[string]json.RawMessage
	if err := json.Unmarshal([]byte(requete), &message); err != nil {
		t.Fatalf("la requête de test est invalide : %v", err)
	}
	if _, ok := message["check"]; !ok {
		t.Error("la requête de test ne porte pas de clé « check » : elle serait ignorée pour la mauvaise raison")
	}
}
