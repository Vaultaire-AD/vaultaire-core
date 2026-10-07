//go:build linux

package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
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

// ErrProprietaireAutre distingue LA cause qu'on ne peut pas corriger seul.
//
// Un composant du chemin qui est un lien symbolique, c'est quelqu'un qui a posé
// un piège : on refuse, on journalise, et il n'y a rien d'autre à faire.
//
// Un répertoire qui EXISTAIT DÉJÀ et appartient à un autre compte, c'est autre
// chose : un `HOME` mal repris, un `chown` oublié, un compte recréé sous le même
// nom avec un uid neuf. Le refus reste le bon réflexe — reprendre un répertoire
// dont on ne sait pas d'où il vient, en root, est précisément ce que le point 97
// a fermé — mais le remède n'est pas le même, et le message ne doit pas accuser
// l'utilisateur d'avoir planté un lien quand il n'a rien fait.
//
// ATTENTION : elle n'enveloppe PAS ErrCheminSuspect — c'est une sentinelle nue.
// Les deux ne cohabitent que parce que le site d'appel les joint par un DOUBLE
// « %w ». Un futur site qui n'emploierait que celle-ci produirait une erreur que
// « errors.Is(err, ErrCheminSuspect) » ne verrait pas, et qui passerait donc à
// travers tout le traitement du cas général, en silence. Ne l'employer que
// conjointement.
var ErrProprietaireAutre = errors.New("repertoire preexistant appartenant a un autre compte")

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
		return fmt.Errorf("%w : %s appartient a l'uid %d, attendu %d — %w",
			ErrCheminSuspect, quoi, st.Uid, uid, ErrProprietaireAutre)
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

	// PAS de branche ELOOP : avec ces drapeaux, elle serait MORTE.
	//
	// Vérifié par programme : openat(O_RDONLY|O_DIRECTORY|O_NOFOLLOW) rend
	// ENOTDIR pour TOUT lien symbolique — vers un répertoire, vers un fichier,
	// vers un tube, cassé, ou bouclant sur lui-même. O_NOFOLLOW fait que le
	// dernier composant résolu EST le lien, et le contrôle de répertoire tranche
	// avant toute considération de lien. ELOOP ne sort que SANS O_DIRECTORY.
	//
	// Une branche ELOOP ici donnerait un diagnostic « propre » qui ne se
	// déclenche jamais, et laisserait croire qu'un chemin de diagnostic existe.
	if errors.Is(err, syscall.ENOTDIR) {
		// TOUT ce qui n'est pas un vrai répertoire arrive ici, lien symbolique
		// COMPRIS — et le lien est le cas le plus courant du point 97. Le message
		// se lisait « n'est pas un repertoire » : exact, et inutile à qui cherche
		// ce qui se passe sur le poste.
		//
		// Les causes sont ÉNUMÉRÉES plutôt que départagées, et c'est un arbitrage :
		//
		//   - les départager demanderait un fstatat(AT_SYMLINK_NOFOLLOW), absent
		//     de la bibliothèque standard. Un openat(O_PATH|O_NOFOLLOW) suivi d'un
		//     Fstat le ferait avec la seule constante O_PATH écrite à la main —
		//     c'est faisable, et c'est le premier candidat si ce message ne suffit
		//     pas à l'usage ;
		//   - retirer O_DIRECTORY rendrait ELOOP fiable, mais ouvrirait en
		//     O_RDONLY ce que l'utilisateur a planté. Un FIFO déposé dans son
		//     propre dossier BLOQUERAIT l'ouverture jusqu'à ce qu'un écrivain se
		//     présente, c'est-à-dire la session PAM elle-même. On échangerait un
		//     message imprécis contre un déni de service.
		//
		// L'énumération cite ce que l'utilisateur PEUT créer chez lui : un lien,
		// un fichier, un tube, une socket. Pas un périphérique, qui demande
		// CAP_MKNOD — le citer enverrait chercher du mauvais côté.
		return -1, fmt.Errorf(
			"%w : %s n'est pas un repertoire reel — lien symbolique, fichier, tube ou socket",
			ErrCheminSuspect, pourMessage)
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
	// machine — deux authentifications du même compte — ne doivent pas écrire dans
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

// --- lire et retirer, par la même porte — TO-DO 135 --------------------------
//
// # Pourquoi ces deux fonctions arrivent avec l'inventaire
//
// Le point 97 a fermé l'ÉCRITURE sous un `HOME`. Deux gestes voisins étaient
// restés sur des chemins :
//
//   - LIRE : pour poser son bloc dans `~/.bashrc` ou `~/.ssh/config`, l'agent
//     relisait le fichier par `os.ReadFile`, qui suit les liens, puis réécrivait
//     ce qu'il avait lu dans un fichier APPARTENANT À L'UTILISATEUR. Avec
//     `ln -sf /etc/shadow ~/.bashrc`, root recopiait donc `/etc/shadow` dans le
//     dossier de la personne, lisible par elle. N'importe quel fichier du poste
//     y passait, clés privées de l'agent comprises ;
//   - RETIRER : `os.Remove(chemin)` résout les répertoires intermédiaires. Avec
//     `ln -s /etc ~/.config`, une politique qui retire `~/.config/app.conf`
//     faisait supprimer `/etc/app.conf` par root.
//
// Tant qu'un module utilisateur n'était rejoué qu'au changement de sa GPO,
// l'attaquant devait attendre que l'administrateur y touche. Le point 135 fait
// rejouer un module dès que son fichier DÉRIVE — c'est-à-dire quand l'utilisateur
// le décide. Livrer l'inventaire sans fermer ces deux portes aurait transformé
// deux défauts dormants en lecture de fichier à la demande.
//
// Les deux passent donc par la descente du point 97 : chaque composant ouvert
// relativement au précédent, sans suivre un seul lien, et l'opération finale
// faite sur le descripteur du répertoire.

// errComposantAbsent : un répertoire du chemin n'existe pas.
//
// Distincte de ErrCheminSuspect, et jamais rendue à l'appelant : pour une
// lecture comme pour un retrait, « le dossier n'existe pas » veut simplement
// dire « le fichier non plus ».
var errComposantAbsent = errors.New("composant absent")

// errObjetAbsent : il n'y a rien au chemin demandé.
//
// designerSousHome le rend enveloppé, sous le même texte qu'avant (« <chemin>
// absent »). Le vérificateur d'ACL doit distinguer « rien ici » — conforme si la
// politique retire l'entrée — d'un chemin suspect (TO-DO 163).
var errObjetAbsent = errors.New("absent")

// tailleMaxLecture borne ce que l'agent accepte de relire sous un `HOME`.
//
// Ce sont des fichiers de démarrage de shell et de configuration : quelques
// kilo-octets. Un mégaoctet laisse une marge sans commune mesure, et empêche
// qu'un fichier géant posé là fasse grossir l'agent — qui tourne en root et ne
// redémarre pas — à chaque ouverture de session.
const tailleMaxLecture = 1 << 20

// descendreSansCreer ouvre les répertoires d'un chemin, sans en créer aucun.
//
// C'est la descente de `descendre`, privée de son `mkdirat` : une lecture ou un
// retrait ne doit laisser aucune trace de son passage.
func (r *racineOuverte) descendreSansCreer(composants []string, uid int) (int, error) {
	courant, err := syscall.Dup(r.fd)
	if err != nil {
		return -1, fmt.Errorf("duplication du descripteur de %s : %v", r.home, err)
	}

	const drapeaux = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

	parcouru := r.home
	for _, nom := range composants {
		parcouru = filepath.Join(parcouru, nom)
		if nom == "" || nom == "." || nom == ".." {
			_ = syscall.Close(courant)
			return -1, fmt.Errorf("%w : composant invalide %q", ErrCheminSuspect, nom)
		}

		suivant, err := syscall.Openat(courant, nom, drapeaux, 0)
		_ = syscall.Close(courant)
		switch {
		case err == nil:
		case errors.Is(err, syscall.ENOENT):
			return -1, errComposantAbsent
		case errors.Is(err, syscall.ENOTDIR):
			// Même énumération que ouvrirOuCreerRepertoire, pour la même raison :
			// un lien symbolique arrive ici, et c'est le cas qui compte.
			return -1, fmt.Errorf(
				"%w : %s n'est pas un repertoire reel — lien symbolique, fichier, tube ou socket",
				ErrCheminSuspect, parcouru)
		default:
			return -1, fmt.Errorf("%s inaccessible : %v", parcouru, err)
		}
		if errV := verifierRepertoireDe(suivant, parcouru, uid); errV != nil {
			_ = syscall.Close(suivant)
			return -1, errV
		}
		courant = suivant
	}
	return courant, nil
}

// ouvrirParent ouvre le répertoire qui contient un chemin, sans rien créer.
//
// Rend le descripteur du répertoire et le nom du dernier composant. Une
// erreur errComposantAbsent veut dire que le fichier ne peut pas exister.
func ouvrirParent(home, chemin string, uid int) (fdRep int, base string, err error) {
	racine, err := ouvrirRacine(home, uid)
	if err != nil {
		return -1, "", err
	}
	defer racine.fermer()

	composants, err := composantsSous(home, chemin)
	if err != nil {
		return -1, "", err
	}
	if len(composants) == 0 {
		return -1, "", fmt.Errorf("%w : %s designe le repertoire personnel lui-meme",
			ErrCheminSuspect, chemin)
	}

	base = composants[len(composants)-1]
	fdRep, err = racine.descendreSansCreer(composants[:len(composants)-1], uid)
	if err != nil {
		return -1, "", err
	}
	return fdRep, base, nil
}

// lireFichierUtilisateur lit un fichier sous le `HOME`, sans suivre un seul lien.
//
// Trois issues, et l'appelant doit les distinguer :
//
//   - (contenu, true, nil)  : un fichier ordinaire de l'utilisateur, lu ;
//   - ("", false, nil)      : il n'existe pas ;
//   - ("", false, erreur)   : il y a quelque chose à cet endroit, et ce n'est pas
//     un fichier ordinaire appartenant au compte. On ne lit pas.
//
// # Ce qui est refusé, et pourquoi
//
// Un LIEN symbolique : c'est la porte que cette fonction ferme. L'appelant
// décide de ce qu'il en fait — passer au fichier suivant, ou échouer.
//
// Un fichier qui n'appartient PAS au compte : un lien physique vers un fichier
// d'un autre propriétaire se présente comme un fichier ordinaire, sous un
// répertoire parfaitement réel. `fs.protected_hardlinks` l'interdit sur les
// distributions courantes ; ce contrôle ne coûte qu'un `fstat` et ne dépend pas
// d'un réglage du noyau.
//
// Un TUBE, une socket, un répertoire : ouvert en `O_NONBLOCK`, donc sans que la
// session PAM reste pendue à un tube sans écrivain, puis refusé sur son type.
func lireFichierUtilisateur(home, chemin string, uid int) (string, bool, error) {
	fdRep, base, err := ouvrirParent(home, chemin, uid)
	if errors.Is(err, errComposantAbsent) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer func() { _ = syscall.Close(fdRep) }()

	fd, err := syscall.Openat(fdRep, base,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	switch {
	case err == nil:
	case errors.Is(err, syscall.ENOENT):
		return "", false, nil
	case errors.Is(err, syscall.ELOOP):
		// Sans O_DIRECTORY, O_NOFOLLOW rend bien ELOOP sur un lien : c'est ici,
		// et seulement ici, que le lien se reconnaît à coup sûr.
		return "", false, fmt.Errorf("%w : %s est un lien symbolique", ErrCheminSuspect, chemin)
	default:
		return "", false, fmt.Errorf("%s illisible : %v", chemin, err)
	}
	defer func() { _ = syscall.Close(fd) }()

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return "", false, fmt.Errorf("%w : %s illisible (%v)", ErrCheminSuspect, chemin, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return "", false, fmt.Errorf("%w : %s n'est pas un fichier ordinaire", ErrCheminSuspect, chemin)
	}
	if int(st.Uid) != uid {
		return "", false, fmt.Errorf("%w : %s appartient a l'uid %d, attendu %d — %w",
			ErrCheminSuspect, chemin, st.Uid, uid, ErrProprietaireAutre)
	}
	if st.Size > tailleMaxLecture {
		return "", false, fmt.Errorf("%s depasse %d octets, il n'est pas relu", chemin, tailleMaxLecture)
	}

	// Lu par le descripteur, borné : la taille annoncée par fstat peut avoir
	// changé depuis, et un fichier qui grossit pendant la lecture ne doit pas
	// la faire durer.
	tampon := make([]byte, 0, st.Size+1)
	bloc := make([]byte, 32*1024)
	for len(tampon) <= tailleMaxLecture {
		n, err := syscall.Read(fd, bloc)
		if n > 0 {
			tampon = append(tampon, bloc[:n]...)
		}
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return "", false, fmt.Errorf("lecture de %s impossible : %v", chemin, err)
		}
		if n == 0 {
			break
		}
	}
	if len(tampon) > tailleMaxLecture {
		return "", false, fmt.Errorf("%s depasse %d octets, il n'est pas relu", chemin, tailleMaxLecture)
	}
	return string(tampon), true, nil
}

// atRemoveDir est AT_REMOVEDIR : `unlinkat` retire alors un répertoire VIDE.
// La bibliothèque standard n'exporte pas la constante.
const atRemoveDir = 0x200

// retirerSousHome retire un fichier — ou un répertoire VIDE — sous le `HOME`,
// sans suivre un seul lien.
//
// Le booléen dit s'il y avait quelque chose à retirer, comme removeSystemFile.
//
// `unlinkat` ne suit jamais le dernier composant : un lien planté à la place du
// fichier est RETIRÉ, et sa cible n'est pas touchée. Ce sont les répertoires
// intermédiaires qui posaient problème, et la descente les traite.
//
// Jamais récursif, pour la raison écrite dans applyDirectory : effacer une
// arborescence depuis une politique transformerait une faute de frappe en perte
// de données sur tout un parc.
func retirerSousHome(home, chemin string, uid int) (bool, error) {
	fdRep, base, err := ouvrirParent(home, chemin, uid)
	if errors.Is(err, errComposantAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = syscall.Close(fdRep) }()

	err = unlinkat(fdRep, base, 0)
	if errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.EPERM) {
		// Linux rend EISDIR pour un répertoire ; POSIX autorise EPERM. Les deux
		// mènent au même essai, qui échouera proprement si ce n'en est pas un.
		err = unlinkat(fdRep, base, atRemoveDir)
	}
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.ENOENT):
		return false, nil
	}
	return false, fmt.Errorf("suppression de %s impossible : %v", chemin, err)
}

// unlinkat appelle unlinkat(2) avec ses drapeaux.
//
// `syscall.Unlinkat` de la bibliothèque standard ne prend pas de drapeaux sur
// Linux : il ne sait donc pas retirer un répertoire.
func unlinkat(dirfd int, nom string, drapeaux int) error {
	p, err := syscall.BytePtrFromString(nom)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT,
		uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(drapeaux))
	if errno != 0 {
		return errno
	}
	return nil
}

// oPath est O_PATH : un descripteur qui DÉSIGNE un objet sans l'ouvrir.
// La bibliothèque standard n'exporte pas la constante.
const oPath = 0x200000

// designerSousHome rend un descripteur qui désigne un objet sous le `HOME`.
//
// # À quoi il sert
//
// À passer une cible à une COMMANDE sans lui passer un chemin. `setfacl` suit
// les liens de l'argument qu'on lui donne : avec `ln -s /etc/shadow ~/partage`,
// une politique « donner au groupe X l'accès à ~/partage » donnait l'accès à
// `/etc/shadow`. Vérifier le chemin avant d'appeler la commande ne ferme rien —
// l'utilisateur le remplace entre les deux.
//
// Un descripteur, lui, désigne l'objet. On le donne à la commande sous la forme
// `/proc/<pid>/fd/<n>`, que le noyau résout vers l'objet lui-même, quel que soit
// ce que le chemin est devenu entre-temps.
//
// Refuse un lien symbolique en dernière position : `O_PATH|O_NOFOLLOW` l'ouvre
// sans le suivre, et le `fstat` le reconnaît.
func designerSousHome(home, chemin string, uid int) (*os.File, error) {
	fdRep, base, err := ouvrirParent(home, chemin, uid)
	if errors.Is(err, errComposantAbsent) {
		return nil, fmt.Errorf("%s %w", chemin, errObjetAbsent)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.Close(fdRep) }()

	fd, err := syscall.Openat(fdRep, base, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, fmt.Errorf("%s %w", chemin, errObjetAbsent)
	}
	if err != nil {
		return nil, fmt.Errorf("%s inaccessible : %v", chemin, err)
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("%w : %s illisible (%v)", ErrCheminSuspect, chemin, err)
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFREG, syscall.S_IFDIR:
	default:
		_ = syscall.Close(fd)
		return nil, fmt.Errorf(
			"%w : %s n'est ni un fichier ni un repertoire — lien symbolique, tube ou socket",
			ErrCheminSuspect, chemin)
	}
	if int(st.Uid) != uid {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("%w : %s appartient a l'uid %d, attendu %d — %w",
			ErrCheminSuspect, chemin, st.Uid, uid, ErrProprietaireAutre)
	}
	return os.NewFile(uintptr(fd), chemin), nil
}

// ---------------------------------------------------------------------------
// Constater sous un `HOME`, sans suivre un seul lien — TO-DO 163
// ---------------------------------------------------------------------------
//
// Le point 135 a fermé la lecture et le retrait ; il restait deux gestes de
// CONSTAT qui passaient un chemin à une primitive qui le résout :
//
//   - le scan des fichiers : `os.Lstat` reconnaît le lien posé À LA PLACE du
//     fichier, mais résout les répertoires qui y mènent. Avec `ln -s /etc
//     ~/.config`, root hachait `/etc/app.conf` pour le comparer à ce que la
//     politique avait déposé dans `~/.config/app.conf` ;
//   - le vérificateur d'ACL, qui donnait le chemin à `getfacl`.
//
// Rien ne sortait de la machine — une empreinte, un bit « conforme ou non » —
// mais c'est root qui lit, sur commande d'un utilisateur, un fichier que
// l'utilisateur ne peut pas lire. Et le verdict était FAUX : le scan comparait
// un autre fichier que celui de la politique.

// tailleMaxHachage borne ce que le scan accepte de hacher sous un `HOME`.
//
// Un contenu déposé par une politique ne dépasse pas 262 144 caractères, soit
// un mébioctet au plus. Un fichier plus gros que cette borne n'est PAS celui
// que la politique a posé : il est dit modifié sans être lu — et un fichier
// creux de cent gigaoctets ne retient pas une ouverture de session.
const tailleMaxHachage = 4 * 1024 * 1024

// etatSousHome est ce qu'on constate d'un chemin sous un dossier personnel.
type etatSousHome struct {
	Existe bool
	// Lien : le dernier composant est un lien symbolique. Il EXISTE, même
	// s'il ne mène nulle part.
	Lien bool
	// Ordinaire : un fichier ordinaire. Faux pour un répertoire, un tube…
	Ordinaire bool
	Uid       int
	Mode      uint32
	// SHA256 n'est renseigné que pour un fichier ordinaire du compte, sous la
	// borne. TropGros dit qu'il la dépasse.
	SHA256   string
	TropGros bool
}

// constaterSousHome dit ce qu'il y a à un chemin sous le `HOME`, et hache un
// fichier ordinaire du compte.
//
// Une erreur ErrCheminSuspect signale un répertoire du chemin qui est un lien,
// ou qui n'appartient pas au compte : on ne sait alors rien du fichier, sinon
// que le chemin qui y menait n'est plus celui que la politique a emprunté.
func constaterSousHome(home, chemin string, uid int) (etatSousHome, error) {
	var e etatSousHome

	fdRep, base, err := ouvrirParent(home, chemin, uid)
	if errors.Is(err, errComposantAbsent) {
		return e, nil
	}
	if err != nil {
		return e, err
	}
	defer func() { _ = syscall.Close(fdRep) }()

	// Le dernier composant LUI-MÊME, sans le suivre.
	st, present, err := designerSansSuivre(fdRep, base)
	if err != nil {
		return e, fmt.Errorf("%s illisible : %v", chemin, err)
	}
	if !present {
		return e, nil
	}
	e.Existe = true
	e.Uid = int(st.Uid)
	e.Mode = uint32(st.Mode & 0o777)
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFLNK:
		e.Lien = true
		return e, nil
	case syscall.S_IFREG:
		e.Ordinaire = true
	default:
		return e, nil
	}
	if e.Uid != uid {
		// Un fichier d'un autre compte — un lien physique, par exemple. On ne
		// le lit pas : l'appelant dira ce qu'il en est.
		return e, nil
	}
	if st.Size > tailleMaxHachage {
		e.TropGros = true
		return e, nil
	}

	// Ouvert RELATIVEMENT au répertoire, sans suivre : si le fichier vient
	// d'être remplacé par un lien, l'ouverture échoue au lieu de le suivre.
	fd, err := syscall.Openat(fdRep, base,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			e.Lien, e.Ordinaire = true, false
			return e, nil
		}
		return e, fmt.Errorf("%s illisible : %v", chemin, err)
	}
	defer func() { _ = syscall.Close(fd) }()

	// Le descripteur fait foi, pas le fstatat qui l'a précédé.
	var ouvert syscall.Stat_t
	if err := syscall.Fstat(fd, &ouvert); err != nil {
		return e, fmt.Errorf("%s illisible : %v", chemin, err)
	}
	if ouvert.Mode&syscall.S_IFMT != syscall.S_IFREG || int(ouvert.Uid) != uid {
		e.Ordinaire = ouvert.Mode&syscall.S_IFMT == syscall.S_IFREG
		e.Uid = int(ouvert.Uid)
		return e, nil
	}
	e.Mode = uint32(ouvert.Mode & 0o777)

	somme := sha256.New()
	bloc := make([]byte, 64*1024)
	lus := 0
	for {
		n, err := syscall.Read(fd, bloc)
		if n > 0 {
			lus += n
			if lus > tailleMaxHachage {
				e.TropGros = true
				return e, nil
			}
			somme.Write(bloc[:n])
		}
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return e, fmt.Errorf("lecture de %s impossible : %v", chemin, err)
		}
		if n == 0 {
			break
		}
	}
	e.SHA256 = hex.EncodeToString(somme.Sum(nil))
	return e, nil
}

// designerSansSuivre rend l'état d'une entrée d'un répertoire déjà ouvert, sans
// la suivre si c'est un lien.
//
// Par `O_PATH|O_NOFOLLOW` puis `fstat`, comme designerSousHome : l'appel
// `fstatat` n'a pas le même nom d'une architecture à l'autre, et la
// bibliothèque standard ne l'exporte pas.
func designerSansSuivre(fdRep int, base string) (st syscall.Stat_t, present bool, err error) {
	fd, err := syscall.Openat(fdRep, base, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Fstat(fd, &st); err != nil {
		return st, false, err
	}
	return st, true, nil
}

// lireLienSousHome rend la cible d'un lien symbolique sous le `HOME`.
//
// Le lien est LU, jamais suivi : ce qu'on veut savoir, c'est ce qu'il dit, pas
// ce qu'il y a au bout. `existe` est faux quand rien n'est à cet endroit ;
// `estLien` l'est quand c'est autre chose qu'un lien.
func lireLienSousHome(home, chemin string, uid int) (cible string, existe, estLien bool, err error) {
	fdRep, base, err := ouvrirParent(home, chemin, uid)
	if errors.Is(err, errComposantAbsent) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	defer func() { _ = syscall.Close(fdRep) }()

	st, present, err := designerSansSuivre(fdRep, base)
	if err != nil {
		return "", false, false, fmt.Errorf("%s illisible : %v", chemin, err)
	}
	if !present {
		return "", false, false, nil
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		return "", true, false, nil
	}

	p, err := syscall.BytePtrFromString(base)
	if err != nil {
		return "", true, true, err
	}
	tampon := make([]byte, 4096)
	n, _, errno := syscall.Syscall6(syscall.SYS_READLINKAT,
		uintptr(fdRep), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&tampon[0])), uintptr(len(tampon)), 0, 0)
	if errno != 0 {
		return "", true, true, fmt.Errorf("lecture du lien %s impossible : %v", chemin, errno)
	}
	return string(tampon[:n]), true, true, nil
}
