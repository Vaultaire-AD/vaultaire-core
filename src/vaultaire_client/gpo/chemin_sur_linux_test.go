//go:build linux

package gpo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Le point 97 : un utilisateur qui plante un lien symbolique dans SON dossier
// ne doit pas faire écrire root ailleurs.
//
// # Pourquoi ces tests ne demandent pas root
//
// Ils tournent sous l'utilisateur courant, avec son propre uid comme
// « utilisateur cible ». La propriété vérifiée — refuser de traverser un lien —
// ne dépend pas du privilège : c'est le comportement de `openat(O_NOFOLLOW)`.
// Un test qui exigerait root ne serait jamais lancé, donc ne protégerait rien.

func moiMeme() (int, int) { return os.Getuid(), os.Getgid() }

// fauxHome fabrique un répertoire personnel appartenant à l'utilisateur courant.
func fauxHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	// t.TempDir peut rendre un chemin qui traverse un lien — /tmp est un lien
	// sur certains systèmes, et /var/folders sur d'autres. La racine est donc
	// résolue UNE FOIS, ici : ce qu'on éprouve est le refus des liens plantés
	// SOUS le home, pas la forme du chemin du home lui-même.
	resolu, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatalf("resolution de %s : %v", home, err)
	}
	return resolu
}

// LE test du point, dans sa forme exacte : « rm -rf ~/.config && ln -s /etc ~/.config ».
func TestUnLienVersEtcNeFaitRienEcrireDansEtc(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)

	// L'« ailleurs » que l'attaquant vise. Un répertoire à nous, pour que le
	// test ne dépende pas des droits sur /etc — ce qui est vérifié est que
	// RIEN n'y est écrit, pas qu'on n'a pas le droit d'y écrire.
	ailleurs := fauxHome(t)

	if err := os.Symlink(ailleurs, filepath.Join(home, ".config")); err != nil {
		t.Fatalf("pose du lien : %v", err)
	}

	cible := filepath.Join(home, ".config", "monapp", "app.conf")
	err := ecrireFichierUtilisateur(home, cible, "contenu", 0o644, uid, gid)

	if err == nil {
		t.Fatal("l'ecriture a traverse le lien symbolique — c'est l'elevation du point 97")
	}
	if !errors.Is(err, ErrCheminSuspect) {
		t.Errorf("erreur %v : le refus doit etre reconnaissable comme un chemin "+
			"suspect, sinon le rapport d'application le confond avec un disque plein", err)
	}

	// LA vérification qui compte : rien n'a été créé de l'autre côté.
	if _, err := os.Stat(filepath.Join(ailleurs, "monapp")); !os.IsNotExist(err) {
		t.Errorf("root a cree %s/monapp a travers le lien", ailleurs)
	}
}

// Le lien peut être planté à N'IMPORTE QUEL niveau, y compris le dernier
// répertoire avant le fichier.
func TestUnLienAUnNiveauProfondEstRefuse(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)
	ailleurs := fauxHome(t)

	if err := os.MkdirAll(filepath.Join(home, ".local", "share"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ailleurs, filepath.Join(home, ".local", "share", "app")); err != nil {
		t.Fatal(err)
	}

	cible := filepath.Join(home, ".local", "share", "app", "conf.yaml")
	err := ecrireFichierUtilisateur(home, cible, "x", 0o600, uid, gid)
	if err == nil || !errors.Is(err, ErrCheminSuspect) {
		t.Fatalf("lien profond non refuse : %v", err)
	}
	if _, err := os.Stat(filepath.Join(ailleurs, "conf.yaml")); !os.IsNotExist(err) {
		t.Error("le fichier a ete ecrit de l'autre cote du lien")
	}
}

// Un lien à l'emplacement du FICHIER lui-même est remplacé, pas suivi.
//
// C'est le cas le plus tentant : « ~/.config/app.conf -> /etc/shadow ». Le
// renommage final remplace le lien par un fichier ordinaire, dans le dossier de
// l'utilisateur, et la cible n'est jamais touchée.
func TestUnLienALaPlaceDuFichierEstRemplaceEtNonSuivi(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)
	ailleurs := fauxHome(t)

	victime := filepath.Join(ailleurs, "shadow")
	if err := os.WriteFile(victime, []byte("NE PAS TOUCHER"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victime, filepath.Join(home, "app.conf")); err != nil {
		t.Fatal(err)
	}

	cible := filepath.Join(home, "app.conf")
	if err := ecrireFichierUtilisateur(home, cible, "nouveau contenu", 0o644, uid, gid); err != nil {
		t.Fatalf("ecriture refusee alors qu'elle est legitime : %v", err)
	}

	// La victime est intacte.
	contenu, err := os.ReadFile(victime)
	if err != nil {
		t.Fatalf("lecture de la victime : %v", err)
	}
	if string(contenu) != "NE PAS TOUCHER" {
		t.Errorf("le fichier vise a ete reecrit a travers le lien : %q", contenu)
	}

	// Et le lien a été remplacé par un vrai fichier.
	info, err := os.Lstat(cible)
	if err != nil {
		t.Fatalf("lstat de la cible : %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("la cible est toujours un lien symbolique")
	}
	ecrit, _ := os.ReadFile(cible)
	if string(ecrit) != "nouveau contenu" {
		t.Errorf("contenu ecrit = %q", ecrit)
	}
}

// Le cas ORDINAIRE doit continuer de marcher : c'est ce que le point ne doit
// rien retirer au produit.
func TestUneEcritureOrdinaireFonctionneToujours(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)

	cible := filepath.Join(home, ".config", "monapp", "sous", "app.conf")
	if err := ecrireFichierUtilisateur(home, cible, "bonjour", 0o640, uid, gid); err != nil {
		t.Fatalf("ecriture legitime refusee : %v", err)
	}

	contenu, err := os.ReadFile(cible)
	if err != nil {
		t.Fatalf("relecture : %v", err)
	}
	if string(contenu) != "bonjour" {
		t.Errorf("contenu = %q", contenu)
	}

	info, err := os.Stat(cible)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %04o, attendu 0640", info.Mode().Perm())
	}

	// Les répertoires intermédiaires ont été créés, et en 0700 : ils sont sous
	// le dossier personnel, rien n'exige qu'un autre compte du poste les lise.
	rep, err := os.Stat(filepath.Join(home, ".config", "monapp"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode().Perm() != 0o700 {
		t.Errorf("mode du repertoire intermediaire = %04o, attendu 0700", rep.Mode().Perm())
	}

	// Aucun fichier temporaire ne doit survivre.
	entrees, _ := os.ReadDir(filepath.Dir(cible))
	for _, e := range entrees {
		if strings.HasPrefix(e.Name(), ".vaultaire-") {
			t.Errorf("fichier temporaire laisse derriere : %s", e.Name())
		}
	}
}

// Une seconde écriture remplace la première : le module est réappliqué à chaque
// dérive depuis le point 33, donc ce chemin est le plus fréquent.
func TestUneSecondeEcritureRemplaceLaPremiere(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)
	cible := filepath.Join(home, "a", "b.conf")

	for _, contenu := range []string{"premier", "second"} {
		if err := ecrireFichierUtilisateur(home, cible, contenu, 0o644, uid, gid); err != nil {
			t.Fatalf("ecriture %q : %v", contenu, err)
		}
	}
	relu, _ := os.ReadFile(cible)
	if string(relu) != "second" {
		t.Errorf("contenu = %q, attendu « second »", relu)
	}
}

// Un chemin qui SORT du dossier personnel est refusé, quelle que soit sa forme.
func TestUnCheminHorsDuHomeEstRefuse(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)
	dehors := fauxHome(t)

	cas := map[string]string{
		"remontee par ..":   filepath.Join(home, "..", "evade.conf"),
		"chemin absolu":     filepath.Join(dehors, "evade.conf"),
		"le home lui-meme":  home,
		"remontee profonde": filepath.Join(home, "a", "..", "..", "evade.conf"),
	}
	for nom, chemin := range cas {
		err := ecrireFichierUtilisateur(home, chemin, "x", 0o644, uid, gid)
		if err == nil || !errors.Is(err, ErrCheminSuspect) {
			t.Errorf("%s : %s accepte (%v)", nom, chemin, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dehors, "evade.conf")); !os.IsNotExist(err) {
		t.Error("un fichier a ete ecrit hors du dossier personnel")
	}
}

// Un composant qui existe mais n'est PAS un répertoire est refusé — sinon
// l'écriture se ferait dans un endroit que personne n'a prévu.
func TestUnFichierALaPlaceDUnRepertoireEstRefuse(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)

	if err := os.WriteFile(filepath.Join(home, ".config"), []byte("je suis un fichier"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := ecrireFichierUtilisateur(home, filepath.Join(home, ".config", "app.conf"), "x", 0o644, uid, gid)
	if err == nil || !errors.Is(err, ErrCheminSuspect) {
		t.Fatalf("fichier pris pour un repertoire : %v", err)
	}
}

// Le module `directory_manage` est protégé par la même descente.
func TestLaCreationDeRepertoireNeTraversePasUnLien(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)
	ailleurs := fauxHome(t)

	if err := os.Symlink(ailleurs, filepath.Join(home, ".cache")); err != nil {
		t.Fatal(err)
	}

	err := preparerRepertoireUtilisateur(home, filepath.Join(home, ".cache", "app"), 0o777, uid, gid)
	if err == nil || !errors.Is(err, ErrCheminSuspect) {
		t.Fatalf("creation de repertoire a travers un lien : %v", err)
	}
	if _, err := os.Stat(filepath.Join(ailleurs, "app")); !os.IsNotExist(err) {
		t.Error("un repertoire a ete cree de l'autre cote du lien")
	}

	// Et le cas ordinaire fonctionne, avec son mode.
	ok := filepath.Join(home, "donnees", "app")
	if err := preparerRepertoireUtilisateur(home, ok, 0o750, uid, gid); err != nil {
		t.Fatalf("creation legitime refusee : %v", err)
	}
	info, err := os.Stat(ok)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("mode = %04o, attendu 0750", info.Mode().Perm())
	}
}

// Le `HOME` lui-même ne peut pas être un lien : si la racine ment, rien de ce
// qui suit n'a de sens.
func TestUnHomeQuiEstUnLienEstRefuse(t *testing.T) {
	uid, gid := moiMeme()
	reel := fauxHome(t)
	parent := fauxHome(t)
	faux := filepath.Join(parent, "home-pirate")

	if err := os.Symlink(reel, faux); err != nil {
		t.Fatal(err)
	}

	err := ecrireFichierUtilisateur(faux, filepath.Join(faux, "a.conf"), "x", 0o644, uid, gid)
	if err == nil || !errors.Is(err, ErrCheminSuspect) {
		t.Fatalf("un home qui est un lien a ete accepte : %v", err)
	}
}

// Un répertoire qui n'appartient PAS à l'utilisateur cible est refusé.
//
// C'est ce qui reste quand le lien ne suffit pas : un dossier déposé sous le
// `HOME` par quelqu'un d'autre. Le test compare à un uid voisin plutôt que de
// changer de propriétaire — ce qui demanderait root.
func TestUnRepertoireDUnAutreProprietaireEstRefuse(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)

	if err := os.MkdirAll(filepath.Join(home, "sous"), 0o700); err != nil {
		t.Fatal(err)
	}

	// On demande l'écriture au nom d'un AUTRE uid : les répertoires existants
	// appartiennent à l'utilisateur courant, donc pas à la cible.
	autre := uid + 1
	err := ecrireFichierUtilisateur(home, filepath.Join(home, "sous", "a.conf"), "x", 0o644, autre, gid)
	if err == nil || !errors.Is(err, ErrCheminSuspect) {
		t.Fatalf("repertoire d'un autre proprietaire accepte : %v", err)
	}
	if !strings.Contains(err.Error(), "uid") {
		t.Errorf("le message ne nomme pas le proprietaire : %v", err)
	}
}

// La descente refuse ce qui n'est pas un composant.
func TestComposantsSousRefuseCeQuiSort(t *testing.T) {
	if _, err := composantsSous("/home/alice", "/etc/passwd"); err == nil {
		t.Error("un chemin hors du home est accepte")
	}
	if _, err := composantsSous("/home/alice", "/home/alice/../bob/x"); err == nil {
		t.Error("une remontee est acceptee")
	}
	comp, err := composantsSous("/home/alice", "/home/alice/.config/app/x.conf")
	if err != nil {
		t.Fatalf("chemin legitime refuse : %v", err)
	}
	if strings.Join(comp, "/") != ".config/app/x.conf" {
		t.Errorf("composants = %v", comp)
	}
}

// Le refus de traverser ne laisse AUCUN descripteur ouvert.
//
// La descente en ouvre un par composant. Un échec au milieu qui les laisserait
// derrière épuiserait la table des descripteurs de l'agent — qui tourne en
// permanence — au bout de quelques milliers de tentatives, c'est-à-dire à
// portée d'un utilisateur patient.
func TestUnRefusNeFuitPasDeDescripteur(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)
	ailleurs := fauxHome(t)
	if err := os.Symlink(ailleurs, filepath.Join(home, "piege")); err != nil {
		t.Fatal(err)
	}
	cible := filepath.Join(home, "piege", "a", "b.conf")

	avant := descripteursOuverts(t)
	for i := 0; i < 200; i++ {
		_ = ecrireFichierUtilisateur(home, cible, "x", 0o644, uid, gid)
	}
	apres := descripteursOuverts(t)

	// Une marge : le runtime Go en ouvre et en ferme pour son propre compte.
	if apres > avant+10 {
		t.Errorf("%d descripteurs ouverts avant, %d apres 200 refus — il y a une fuite",
			avant, apres)
	}
}

func descripteursOuverts(t *testing.T) int {
	t.Helper()
	entrees, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("/proc indisponible (%v)", err)
	}
	return len(entrees)
}

// Le pendant positif : la descente pose bien le propriétaire des répertoires
// qu'elle crée. C'était la raison d'être de `chownTree`, qui a disparu ; sans
// cela, l'utilisateur ne pourrait rien écrire dans ses propres dossiers.
func TestLaDescenteAttribueLesRepertoiresCrees(t *testing.T) {
	uid, gid := moiMeme()
	home := fauxHome(t)

	if err := ecrireFichierUtilisateur(home,
		filepath.Join(home, "x", "y", "z.conf"), "c", 0o644, uid, gid); err != nil {
		t.Fatal(err)
	}

	for _, rep := range []string{"x", "x/y"} {
		var st syscall.Stat_t
		if err := syscall.Stat(filepath.Join(home, rep), &st); err != nil {
			t.Fatalf("stat de %s : %v", rep, err)
		}
		if int(st.Uid) != uid {
			t.Errorf("%s appartient a l'uid %d, attendu %d", rep, st.Uid, uid)
		}
	}
}
