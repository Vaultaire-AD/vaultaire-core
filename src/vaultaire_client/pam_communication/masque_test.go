package pamcommunication

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// TO-DO 165 — deux sockets ouverts en même temps laissaient au processus le
// masque de création de l'un des deux, pour toute sa vie.

// masqueCourant lit le masque du processus. Il n'existe pas d'appel pour le
// lire sans l'écrire : on le pose, et on le remet aussitôt.
func masqueCourant() int {
	m := syscall.Umask(0o022)
	syscall.Umask(m)
	return m
}

func TestDeuxOuverturesSimultaneesRendentLeMasque(t *testing.T) {
	avant := masqueCourant()
	dir := t.TempDir()

	// Les deux ouvertures de l'agent, lancées ensemble, beaucoup de fois : avec
	// les sections non verrouillées, l'entrelacement fautif sort en quelques
	// dizaines de tours.
	for tour := 0; tour < 300; tour++ {
		var groupe sync.WaitGroup
		for i, masque := range []int{0o177, 0} {
			groupe.Add(1)
			go func(i, masque int) {
				defer groupe.Done()
				chemin := filepath.Join(dir, "s"+string(rune('a'+i)))
				_ = os.Remove(chemin)
				ln, err := ecouterSousMasque(chemin, masque)
				if err != nil {
					t.Errorf("ecoute : %v", err)
					return
				}
				_ = ln.Close()
			}(i, masque)
		}
		groupe.Wait()

		if apres := masqueCourant(); apres != avant {
			t.Fatalf("tour %d : le masque du processus vaut %04o, il valait %04o — tout ce que "+
				"l'agent creera ensuite en herite, et un repertoire demande en 0700 nait en 0600",
				tour, apres, avant)
		}
	}
}

// Chaque socket naît bien avec SON mode, et pas celui de l'autre.
func TestChaqueSocketNaitAvecSonMode(t *testing.T) {
	dir := t.TempDir()
	cas := []struct {
		masque  int
		attendu os.FileMode
	}{
		{0o177, 0o600},
		{0, 0o777}, // ce que le noyau donne à un socket sans masque ; l'appelant le ramène à 0666
	}
	for _, c := range cas {
		chemin := filepath.Join(dir, "essai")
		_ = os.Remove(chemin)
		ln, err := ecouterSousMasque(chemin, c.masque)
		if err != nil {
			t.Fatalf("%v", err)
		}
		info, err := os.Stat(chemin)
		_ = ln.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}
		if got := info.Mode().Perm(); got != c.attendu {
			t.Errorf("masque %04o : socket en %04o, attendu %04o", c.masque, got, c.attendu)
		}
	}
}

// SENTINELLE — le masque du processus ne se change qu'ICI. Un `syscall.Umask`
// écrit ailleurs dans l'agent, hors du verrou, rouvre le défaut à l'identique :
// c'est ainsi qu'il est né, de deux fichiers qui faisaient chacun la chose
// correctement.
func TestLeMasqueNeSeChangeQuEnUnSeulEndroit(t *testing.T) {
	var fautifs []string
	err := filepath.Walk("..", func(chemin string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(chemin, ".go") || strings.HasSuffix(chemin, "_test.go") {
			return nil
		}
		if filepath.Base(chemin) == "masque.go" {
			return nil
		}
		contenu, err := os.ReadFile(chemin)
		if err != nil {
			return nil
		}
		for _, ligne := range strings.Split(string(contenu), "\n") {
			nette := strings.TrimSpace(ligne)
			if strings.HasPrefix(nette, "//") {
				continue
			}
			if strings.Contains(nette, "syscall.Umask(") || strings.Contains(nette, "unix.Umask(") {
				fautifs = append(fautifs, filepath.ToSlash(chemin))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(fautifs) > 0 {
		t.Errorf("le masque du processus est change hors de masque.go : %v — passer par ecouterSousMasque", fautifs)
	}
}
