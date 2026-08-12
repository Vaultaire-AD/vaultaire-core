package localusermanagement

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// homeDeTest fabrique un répertoire personnel jetable avec un .ssh peuplé.
func homeDeTest(t *testing.T, contenuInitial string) (home, fichier string) {
	t.Helper()
	home = t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.Mkdir(ssh, 0700); err != nil {
		t.Fatalf("préparation du .ssh : %v", err)
	}
	fichier = filepath.Join(ssh, "authorized_keys")
	if contenuInitial != "" {
		if err := os.WriteFile(fichier, []byte(contenuInitial), 0600); err != nil {
			t.Fatalf("préparation d'authorized_keys : %v", err)
		}
	}
	return home, fichier
}

// TestUneCleRevoqueeDisparaitDuFichier — LE test du point 9.
//
// Le compte avait deux clés, le serveur n'en rend plus qu'une. L'ancienne ne
// doit plus figurer dans le fichier. Compléter au lieu de réécrire la laisserait
// en place, et elle continuerait d'ouvrir la session indéfiniment.
func TestUneCleRevoqueeDisparaitDuFichier(t *testing.T) {
	home, fichier := homeDeTest(t,
		"ssh-ed25519 AAAAgardee poste-bureau\nssh-ed25519 AAAAperdue portable-vole\n")

	if err := EcrireClesAutorisees(home, os.Getuid(), os.Getgid(),
		[]string{"ssh-ed25519 AAAAgardee poste-bureau"}); err != nil {
		t.Fatalf("écriture : %v", err)
	}

	contenu := lire(t, fichier)
	if strings.Contains(contenu, "AAAAperdue") {
		t.Error("la clé révoquée est toujours dans authorized_keys : " +
			"le portable volé ouvre encore la session")
	}
	if !strings.Contains(contenu, "AAAAgardee") {
		t.Error("la clé toujours valide a disparu du fichier")
	}
}

// TestUnEnsembleVideEfface — le cas limite qui portait le défaut.
//
// Révoquer TOUTES les clés d'un compte est la révocation la plus radicale, et
// c'était la seule qui ne prenait pas effet : le module PAM sautait purement
// l'écriture quand la liste était vide, et l'ancien fichier survivait intact.
func TestUnEnsembleVideEfface(t *testing.T) {
	home, fichier := homeDeTest(t, "ssh-ed25519 AAAAvieille compte-parti\n")

	if err := EcrireClesAutorisees(home, os.Getuid(), os.Getgid(), nil); err != nil {
		t.Fatalf("écriture : %v", err)
	}

	if contenu := lire(t, fichier); strings.TrimSpace(contenu) != "" {
		t.Errorf("authorized_keys devrait être vide après révocation totale, il contient : %q", contenu)
	}
}

// TestLeFichierEstRemplaceEtNonComplete vérifie qu'aucun appel n'ajoute.
//
// Trois écritures successives de la MÊME clé doivent laisser UNE ligne. Un
// O_APPEND passé inaperçu produirait un fichier qui grossit à chaque connexion.
func TestLeFichierEstRemplaceEtNonComplete(t *testing.T) {
	home, fichier := homeDeTest(t, "")
	cles := []string{"ssh-ed25519 AAAAunique poste"}

	for i := 0; i < 3; i++ {
		if err := EcrireClesAutorisees(home, os.Getuid(), os.Getgid(), cles); err != nil {
			t.Fatalf("écriture %d : %v", i, err)
		}
	}

	if n := len(lignesUtiles(lire(t, fichier))); n != 1 {
		t.Errorf("après trois écritures identiques : %d ligne(s), attendu 1", n)
	}
}

// TestUnLienSymboliqueNEstPasSuivi : authorized_keys pointe vers une cible
// sensible. La fonction tourne en root sur un terrain que l'utilisateur
// contrôle ; suivre le lien ferait écrire root dans la cible.
func TestUnLienSymboliqueNEstPasSuivi(t *testing.T) {
	home, fichier := homeDeTest(t, "")
	cible := filepath.Join(home, "cible-sensible")
	if err := os.WriteFile(cible, []byte("CONTENU D ORIGINE\n"), 0600); err != nil {
		t.Fatalf("préparation de la cible : %v", err)
	}
	if err := os.Symlink(cible, fichier); err != nil {
		t.Fatalf("préparation du piège : %v", err)
	}

	_ = EcrireClesAutorisees(home, os.Getuid(), os.Getgid(),
		[]string{"ssh-ed25519 AAAAlegitime poste"})

	if lire(t, cible) != "CONTENU D ORIGINE\n" {
		t.Error("la cible du lien symbolique a été écrasée")
	}
	info, err := os.Lstat(fichier)
	if err != nil {
		t.Fatalf("authorized_keys absent après écriture : %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("authorized_keys est resté un lien symbolique")
	}
}

// TestUnHomeQuiEstUnLienEstRefuse : le répertoire personnel LUI-MÊME remplacé
// par un lien vers /root ou vers le home d'un autre.
func TestUnHomeQuiEstUnLienEstRefuse(t *testing.T) {
	base := t.TempDir()
	reel := filepath.Join(base, "reel")
	piege := filepath.Join(base, "piege")
	if err := os.Mkdir(reel, 0700); err != nil {
		t.Fatalf("préparation : %v", err)
	}
	if err := os.Symlink(reel, piege); err != nil {
		t.Fatalf("préparation du lien : %v", err)
	}

	err := EcrireClesAutorisees(piege, os.Getuid(), os.Getgid(),
		[]string{"ssh-ed25519 AAAAviaLien x"})
	if err == nil {
		t.Error("un répertoire personnel qui est un lien symbolique a été accepté")
	}
	if _, e := os.Stat(filepath.Join(reel, ".ssh", "authorized_keys")); e == nil {
		t.Error("des clés ont été écrites dans la cible du lien")
	}
}

// TestUneCleAvecSautDeLigneEstEcartee : une clé portant un saut de ligne en
// fabriquerait DEUX dans le fichier, dont la seconde serait choisie par celui
// qui l'a fournie.
func TestUneCleAvecSautDeLigneEstEcartee(t *testing.T) {
	home, fichier := homeDeTest(t, "")

	err := EcrireClesAutorisees(home, os.Getuid(), os.Getgid(), []string{
		"ssh-ed25519 AAAAbonne poste",
		"ssh-ed25519 AAAAx x\nssh-ed25519 AAAAinjectee attaquant",
	})
	if err != nil {
		t.Fatalf("écriture : %v", err)
	}

	if strings.Contains(lire(t, fichier), "injectee") {
		t.Error("une clé injectée par saut de ligne s'est retrouvée dans le fichier")
	}
}

// TestLesDroitsSontRestreints : 0600 dès la création, jamais élargi ensuite.
func TestLesDroitsSontRestreints(t *testing.T) {
	home, fichier := homeDeTest(t, "")
	if err := EcrireClesAutorisees(home, os.Getuid(), os.Getgid(),
		[]string{"ssh-ed25519 AAAAx poste"}); err != nil {
		t.Fatalf("écriture : %v", err)
	}
	info, err := os.Stat(fichier)
	if err != nil {
		t.Fatalf("stat : %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("authorized_keys est en %04o, attendu 0600", perm)
	}
}

// TestAucunTemporaireNeSubsiste : le fichier intermédiaire est publié par
// rename, il ne doit pas rester dans .ssh — sshd n'irait pas le lire, mais il
// porte des clés en clair sous un nom que personne ne surveille.
func TestAucunTemporaireNeSubsiste(t *testing.T) {
	home, _ := homeDeTest(t, "")
	if err := EcrireClesAutorisees(home, os.Getuid(), os.Getgid(),
		[]string{"ssh-ed25519 AAAAx poste"}); err != nil {
		t.Fatalf("écriture : %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", nomTemporaireCles)); err == nil {
		t.Error("le fichier temporaire est resté dans .ssh")
	}
}

func TestDecouperCles(t *testing.T) {
	cas := []struct {
		nom    string
		brut   string
		attend int
	}{
		{"bloc vide", "", 0},
		{"que des blancs", "\n  \n\n", 0},
		{"une clé", "ssh-ed25519 AAAAa poste", 1},
		{"deux clés", "ssh-ed25519 AAAAa a\nssh-ed25519 AAAAb b", 2},
		{"lignes vides intercalées", "ssh-ed25519 AAAAa a\n\nssh-ed25519 AAAAb b\n", 2},
	}
	for _, c := range cas {
		if n := len(DecouperCles(c.brut)); n != c.attend {
			t.Errorf("%s : %d clé(s), attendu %d", c.nom, n, c.attend)
		}
	}
	// Jamais nil : une tranche nil se sérialise en `null` et non en `[]`.
	if DecouperCles("") == nil {
		t.Error("DecouperCles rend nil sur un bloc vide")
	}
}

func lire(t *testing.T, chemin string) string {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("lecture de %s : %v", chemin, err)
	}
	return string(b)
}

func lignesUtiles(contenu string) []string {
	var out []string
	for _, l := range strings.Split(contenu, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
