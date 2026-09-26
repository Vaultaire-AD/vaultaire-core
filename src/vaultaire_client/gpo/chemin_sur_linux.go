//go:build linux

package gpo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Traversée sûre d'un chemin sous le répertoire personnel — TO-DO 97.
//
// # Le chemin d'attaque que ce fichier ferme
//
// Les appliqueurs de scope utilisateur tournent EN ROOT, lancés par PAM à
// chaque ouverture de session. Ils écrivaient ainsi :
//
//	os.MkdirAll(dir, 0o755)          // suit les liens symboliques
//	chownTree(ctx.HomeDir, dir, …)   // os.Chown : suit les liens
//	writeSystemFile(path, …)         // ouvre par chemin absolu
//	os.Chown(path, uid, gid)         // suit les liens
//
// et `chownTree` vérifiait l'appartenance au `HOME` par `strings.HasPrefix` sur
// la CHAÎNE non résolue — une comparaison de texte, pas de chemin réel.
//
// L'utilisateur n'avait donc qu'à faire, dans son propre dossier et sans aucun
// privilège :
//
//	rm -rf ~/.config && ln -s /etc ~/.config
//
// À sa connexion suivante, une GPO parfaitement ordinaire visant
// `/%h/.config/monapp/app.conf` faisait créer `/etc/monapp` par root, puis
// `chownTree` remontait et chownait `~/.config` — c'est-à-dire **`/etc`**.
// L'utilisateur réécrivait ensuite `/etc/shadow`, `/etc/sudoers` ou
// `/etc/ld.so.preload`. Il était root.
//
// # Pourquoi les protections existantes n'y pouvaient rien
//
// La liste de refus du serveur et `CheckPath` portent sur le chemin DÉCLARÉ
// dans la politique, écrit par un administrateur et parfaitement légitime. Le
// contrôle a lieu côté serveur, sur une chaîne ; la traversée a lieu côté
// agent, sur un système de fichiers que l'attaquant vient de modifier. Aucune
// validation de chaîne ne peut couvrir cela.
//
// # Ce que ce fichier NE retire PAS
//
// Rien. Les chemins autorisés au scope utilisateur ne changent pas, une GPO
// peut toujours écrire la configuration SSH, les fichiers d'un `HOME` ou une
// unité systemd. Ce qui change est la FAÇON de traverser les répertoires.
//
// # openat par composant, et non openat2
//
// `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` ferait la même chose en un
// appel, mais demande un noyau 5.6 et rendrait ENOSYS ailleurs — donc un second
// chemin de code, emprunté seulement sur les machines anciennes, c'est-à-dire
// jamais éprouvé là où il compte. La boucle `openat` ci-dessous fonctionne sur
// tout noyau Linux et offre la même garantie : chaque composant est ouvert
// RELATIVEMENT au précédent, avec `O_NOFOLLOW`, donc un lien planté entre deux
// composants est refusé au lieu d'être suivi.
//
// Et c'est bien la seule garantie qui tienne : entre le moment où l'on vérifie
// un chemin et celui où on l'ouvre, l'utilisateur peut l'avoir remplacé. Un
// descripteur, lui, désigne l'objet lui-même — plus aucune résolution de nom
// n'a lieu ensuite.

// ErrCheminSuspect signale un composant de chemin qui n'est pas ce qu'il devrait
// être : un lien symbolique, un fichier là où un répertoire est attendu, ou un
// répertoire qui n'appartient pas à l'utilisateur cible.
//
// # Pourquoi une erreur DISTINCTE
//
// Ce n'est pas un échec d'écriture ordinaire. C'est le signal qu'un poste a été
// préparé, et il doit se lire comme tel dans le rapport d'application — pas se
// confondre avec un disque plein. Le module est abandonné, et le rapport le dit.
var ErrCheminSuspect = errors.New("chemin suspect sous le repertoire personnel")

// racineOuverte tient le descripteur du répertoire personnel.
type racineOuverte struct {
	fd   int
	home string
}

// ouvrirRacine ouvre le `HOME` et vérifie qu'il est bien ce qu'il prétend être.
//
// Tout part de là : si la racine elle-même est un lien, rien de ce qui suit
// n'a de sens. Elle est ouverte SANS suivre de lien, et son propriétaire est
// vérifié sur le descripteur — pas sur le chemin, qui pourrait déjà avoir
// changé.
func ouvrirRacine(home string, uid int) (*racineOuverte, error) {
	if home == "" {
		return nil, fmt.Errorf("%w : aucun repertoire personnel defini", ErrCheminSuspect)
	}
	fd, err := syscall.Open(home,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w : %s inaccessible (%v)", ErrCheminSuspect, home, err)
	}
	if err := verifierRepertoireDe(fd, home, uid); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &racineOuverte{fd: fd, home: home}, nil
}

func (r *racineOuverte) fermer() {
	if r != nil && r.fd >= 0 {
		_ = syscall.Close(r.fd)
	}
}

// verifierRepertoireDe contrôle un descripteur déjà ouvert.
//
// Sur le DESCRIPTEUR et non sur le chemin : c'est ce qui rend le contrôle
// intransigeant. Vérifier par `os.Stat` puis ouvrir laisserait entre les deux
// une fenêtre pendant laquelle l'utilisateur remplace le répertoire — c'est
// exactement le genre de course que ce point ferme.
func verifierRepertoireDe(fd int, quoi string, uid int) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w : %s illisible (%v)", ErrCheminSuspect, quoi, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("%w : %s n'est pas un repertoire", ErrCheminSuspect, quoi)
	}
	// LE contrôle du point : un répertoire qui n'appartient pas à l'utilisateur
	// cible n'a rien à faire sous son `HOME`. C'est ce qui distingue un dossier
	// qu'il a créé d'un dossier système atteint par un lien qu'il a planté.
	if int(st.Uid) != uid {
		return fmt.Errorf("%w : %s appartient a l'uid %d, attendu %d",
			ErrCheminSuspect, quoi, st.Uid, uid)
	}
	return nil
}

// composantsSous découpe un chemin en composants relatifs à la racine.
//
// Refuse tout ce qui sort du `HOME`. Le chemin est nettoyé AVANT comparaison :
// `filepath.Rel` sur des chemins non nettoyés rendrait un résultat qui commence
// par « .. » dans des cas où il ne le devrait pas, et l'inverse.
func composantsSous(home, chemin string) ([]string, error) {
	rel, err := filepath.Rel(filepath.Clean(home), filepath.Clean(chemin))
	if err != nil {
		return nil, fmt.Errorf("%w : %s hors de %s", ErrCheminSuspect, chemin, home)
	}
	if rel == "." || rel == "" {
		return nil, nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%w : %s sort de %s", ErrCheminSuspect, chemin, home)
	}
	return strings.Split(rel, string(filepath.Separator)), nil
}

// descendre ouvre les répertoires intermédiaires, en les créant au besoin.
//
// Rend le descripteur du DERNIER répertoire. L'appelant le ferme.
//
// Les répertoires créés ici appartiennent à l'utilisateur : c'est ce que faisait
// `chownTree`, et c'est nécessaire — sans cela il ne pourrait rien y écrire
// ensuite. La différence est que le changement de propriétaire se fait sur le
// DESCRIPTEUR du répertoire qu'on vient de créer, et non sur un chemin que
// quelqu'un a pu remplacer entre-temps.
func (r *racineOuverte) descendre(composants []string, uid, gid int) (int, error) {
	courant, err := syscall.Dup(r.fd)
	if err != nil {
		return -1, fmt.Errorf("duplication du descripteur de %s : %v", r.home, err)
	}

	parcouru := r.home
	for _, nom := range composants {
		parcouru = filepath.Join(parcouru, nom)

		suivant, err := ouvrirOuCreerRepertoire(courant, nom, parcouru, uid, gid)
		_ = syscall.Close(courant)
		if err != nil {
			return -1, err
		}
		courant = suivant
	}
	return courant, nil
}

// ouvrirOuCreerRepertoire ouvre un composant sous un répertoire déjà ouvert.
func ouvrirOuCreerRepertoire(parent int, nom, pourMessage string, uid, gid int) (int, error) {
	// « . » et « .. » ne peuvent pas apparaître : composantsSous nettoie le
	// chemin. Les refuser explicitement coûte une ligne et ferme le cas où un
	// appelant futur contournerait composantsSous.
	if nom == "" || nom == "." || nom == ".." {
		return -1, fmt.Errorf("%w : composant invalide %q", ErrCheminSuspect, nom)
	}

	const drapeaux = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

	fd, err := syscall.Openat(parent, nom, drapeaux, 0)
	if err == nil {
		if errV := verifierRepertoireDe(fd, pourMessage, uid); errV != nil {
			_ = syscall.Close(fd)
			return -1, errV
		}
		return fd, nil
	}

	// ELOOP : le composant EST un lien symbolique. C'est le cas du point — on le
	// nomme, plutôt que de le confondre avec une erreur d'accès.
	if errors.Is(err, syscall.ELOOP) {
		return -1, fmt.Errorf("%w : %s est un lien symbolique", ErrCheminSuspect, pourMessage)
	}
	if errors.Is(err, syscall.ENOTDIR) {
		return -1, fmt.Errorf("%w : %s n'est pas un repertoire", ErrCheminSuspect, pourMessage)
	}
	if !errors.Is(err, syscall.ENOENT) {
		return -1, fmt.Errorf("%s inaccessible : %v", pourMessage, err)
	}

	// Absent : on le crée. En 0700 et non 0755 — il est sous le `HOME` d'un
	// utilisateur, et rien n'exige qu'un autre compte du poste puisse le lire.
	// L'ancien code posait 0755 par le défaut de MkdirAll, sans que ce soit une
	// décision.
	if err := syscall.Mkdirat(parent, nom, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return -1, fmt.Errorf("creation de %s impossible : %v", pourMessage, err)
	}

	// Rouvert SANS suivre les liens : entre le mkdirat et cette ouverture,
	// l'utilisateur a pu remplacer ce qu'on vient de créer. C'est improbable et
	// c'est gratuit à fermer.
	fd, err = syscall.Openat(parent, nom, drapeaux, 0)
	if err != nil {
		return -1, fmt.Errorf("%w : %s inaccessible apres creation (%v)",
			ErrCheminSuspect, pourMessage, err)
	}

	// Le propriétaire est posé sur le DESCRIPTEUR. Fchown et non Chown : il n'y
	// a plus de nom à résoudre, donc plus rien à intercepter.
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("proprietaire de %s non applique : %v", pourMessage, err)
	}
	if errV := verifierRepertoireDe(fd, pourMessage, uid); errV != nil {
		_ = syscall.Close(fd)
		return -1, errV
	}
	return fd, nil
}

// ecrireFichierUtilisateur écrit un fichier sous le `HOME`, sans suivre un seul
// lien symbolique.
//
// # L'écriture se fait par DESCRIPTEUR
//
// Le fichier temporaire est créé dans le répertoire déjà ouvert, écrit, changé
// de propriétaire et de mode sur son propre descripteur, puis renommé
// RELATIVEMENT à ce même descripteur. À aucun moment un chemin absolu n'est
// résolu, donc à aucun moment un lien planté entre deux appels ne peut détourner
// l'écriture.
//
// Le renommage final ne suit pas davantage les liens : `rename` remplace le lien
// lui-même. Un utilisateur qui aurait planté `~/.config/app.conf -> /etc/shadow`
// se retrouve avec son lien remplacé par un fichier ordinaire dans son propre
// dossier, et `/etc/shadow` intact.
func ecrireFichierUtilisateur(home, chemin, contenu string, mode os.FileMode, uid, gid int) error {
	racine, err := ouvrirRacine(home, uid)
	if err != nil {
		return err
	}
	defer racine.fermer()

	composants, err := composantsSous(home, chemin)
	if err != nil {
		return err
	}
	if len(composants) == 0 {
		return fmt.Errorf("%w : %s designe le repertoire personnel lui-meme",
			ErrCheminSuspect, chemin)
	}

	base := composants[len(composants)-1]
	fdRep, err := racine.descendre(composants[:len(composants)-1], uid, gid)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fdRep) }()

	return ecrireDansRepertoire(fdRep, base, chemin, contenu, mode, uid, gid)
}

func ecrireDansRepertoire(fdRep int, base, pourMessage, contenu string,
	mode os.FileMode, uid, gid int) error {

	// Le nom temporaire porte le PID : deux cycles simultanés sur la même
	// machine — un « sudo » pendant une session ssh — ne doivent pas écrire dans
	// le même fichier intermédiaire. Le point 33 sérialise déjà le cycle par
	// compte ; cette précaution couvre deux comptes différents visant le même
	// chemin, ce que la sérialisation ne couvre pas.
	tmp := fmt.Sprintf(".vaultaire-%d-%s.tmp", os.Getpid(), base)

	fd, err := syscall.Openat(fdRep, tmp,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		uint32(mode.Perm()))
	if err != nil {
		return fmt.Errorf("fichier temporaire pour %s impossible : %v", pourMessage, err)
	}

	nettoyer := func(format string, args ...any) error {
		_ = syscall.Close(fd)
		_ = syscall.Unlinkat(fdRep, tmp)
		return fmt.Errorf(format, args...)
	}

	if _, err := syscall.Write(fd, []byte(contenu)); err != nil {
		return nettoyer("ecriture de %s impossible : %v", pourMessage, err)
	}
	if err := syscall.Fsync(fd); err != nil {
		return nettoyer("synchronisation de %s impossible : %v", pourMessage, err)
	}
	// Propriétaire et mode sur le DESCRIPTEUR, avant le renommage : le fichier
	// ne doit jamais être visible sous son nom définitif avec les mauvais
	// droits, ni appartenant à root.
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return nettoyer("proprietaire de %s non applique : %v", pourMessage, err)
	}
	// Fchmod après Fchown : changer le propriétaire efface les bits setuid et
	// setgid sur certains systèmes. L'ordre inverse les perdrait en silence.
	if err := syscall.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return nettoyer("permissions de %s non appliquees : %v", pourMessage, err)
	}
	if err := syscall.Close(fd); err != nil {
		_ = syscall.Unlinkat(fdRep, tmp)
		return fmt.Errorf("fermeture de %s impossible : %v", pourMessage, err)
	}

	if err := syscall.Renameat(fdRep, tmp, fdRep, base); err != nil {
		_ = syscall.Unlinkat(fdRep, tmp)
		return fmt.Errorf("remplacement de %s impossible : %v", pourMessage, err)
	}
	return nil
}

// preparerRepertoireUtilisateur crée un répertoire sous le `HOME` et lui pose
// son mode, sans suivre un seul lien symbolique.
//
// C'est le pendant de `ecrireFichierUtilisateur` pour le module
// `directory_manage`. Il avait la même faille par une autre porte : `MkdirAll`
// puis `os.Chmod`, donc un lien `~/.config -> /etc` et un mode permissif
// rendaient `/etc` accessible en écriture à tout le monde.
func preparerRepertoireUtilisateur(home, chemin string, mode os.FileMode, uid, gid int) error {
	racine, err := ouvrirRacine(home, uid)
	if err != nil {
		return err
	}
	defer racine.fermer()

	composants, err := composantsSous(home, chemin)
	if err != nil {
		return err
	}
	if len(composants) == 0 {
		// Le `HOME` lui-même : on ne le crée pas, et on ne change pas son mode.
		// Une politique qui viserait `/%h/` toucherait le dossier personnel
		// entier, ce qu'aucun usage légitime ne demande.
		return fmt.Errorf("%w : %s designe le repertoire personnel lui-meme",
			ErrCheminSuspect, chemin)
	}

	fd, err := racine.descendre(composants, uid, gid)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()

	// Sur le DESCRIPTEUR du répertoire réellement ouvert. `os.Chmod` aurait
	// résolu le chemin une seconde fois — et `fchmodat` ne sait pas ignorer les
	// liens sur Linux, ce qui rendrait la précaution inopérante.
	if err := syscall.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("permissions de %s impossibles : %v", chemin, err)
	}
	return nil
}
