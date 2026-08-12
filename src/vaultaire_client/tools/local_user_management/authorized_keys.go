package localusermanagement

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// nomTemporaireCles : le fichier n'est jamais écrit en place.
//
// Une écriture en place laisse, si elle est coupée, un authorized_keys tronqué.
// L'utilisateur ne peut alors plus se connecter et rien ne le signale — le
// fichier existe, il a l'air normal, il lui manque des lignes.
const nomTemporaireCles = ".authorized_keys.vaultaire"

// EcrireClesAutorisees réécrit ~/.ssh/authorized_keys avec l'ensemble donné.
//
// # Réécrire, et non compléter
//
// Le fichier est reconstruit entièrement à chaque appel, à partir de ce que le
// serveur vient de rendre. C'est l'annuaire qui fait foi : une clé retirée côté
// serveur disparaît de la machine à la connexion suivante, sans qu'aucune purge
// n'ait à être déclenchée ni ordonnancée.
//
// La conséquence tient dans un cas limite qu'il faut nommer : `cles` vide écrit
// un fichier VIDE. Ce n'est pas un oubli, c'est l'objet même de la fonction —
// révoquer la dernière clé d'un compte doit lui fermer la porte. L'appelant qui
// n'est pas sûr de sa liste ne doit pas appeler avec une liste vide « au cas
// où » : il doit ne pas appeler du tout.
//
// # Ce qui est écrit ne peut pas atterrir ailleurs
//
// Cette fonction tourne en root, sur un chemin situé dans le répertoire d'un
// utilisateur — donc sur un terrain qu'il contrôle. Trois précautions, les
// mêmes que dans le module PAM (pam_common.c, vaultaire_write_ssh_keys) :
//
//   - tout passe par des descripteurs de répertoire et O_NOFOLLOW. Un chemin
//     reconstruit à chaque étape peut désigner autre chose entre deux appels ;
//     un descripteur, non. Et un lien symbolique fait ÉCHOUER l'ouverture au
//     lieu d'être suivi — sans quoi authorized_keys pointant vers /etc/shadow
//     ferait écrire root dans la cible ;
//
//   - 0600 est donné à la CRÉATION, pas après. Le fichier n'existe jamais avec
//     des droits plus larges, même brièvement ;
//
//   - écriture dans un temporaire, fsync, puis renameat. Le remplacement est
//     atomique : authorized_keys est soit l'ancien, soit le nouveau.
//
// En cas d'échec, l'ancien fichier est CONSERVÉ et l'erreur est rendue. Le
// contraire enfermerait dehors un utilisateur en règle sur un incident disque.
func EcrireClesAutorisees(home string, uid, gid int, cles []string) error {
	if !strings.HasPrefix(home, "/") {
		return fmt.Errorf("répertoire personnel invalide : %q", home)
	}

	homeFD, err := syscall.Open(home,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s inaccessible ou lien symbolique : %v", home, err)
	}
	defer syscall.Close(homeFD)

	if err := syscall.Mkdirat(homeFD, ".ssh", 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("création de .ssh impossible dans %s : %v", home, err)
	}

	sshFD, err := syscall.Openat(homeFD, ".ssh",
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf(".ssh de %s inaccessible ou lien symbolique : %v", home, err)
	}
	defer syscall.Close(sshFD)
	_ = syscall.Fchown(sshFD, uid, gid)

	// O_EXCL : la création échoue si le nom existe déjà, quel qu'il soit —
	// fichier ordinaire ou lien. C'est ce qui empêche d'avoir préparé la place.
	_ = syscall.Unlinkat(sshFD, nomTemporaireCles)
	fd, err := syscall.Openat(sshFD, nomTemporaireCles,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("création du fichier temporaire impossible dans %s/.ssh : %v", home, err)
	}
	f := os.NewFile(uintptr(fd), nomTemporaireCles)

	var contenu strings.Builder
	for _, cle := range cles {
		cle = strings.TrimSpace(cle)
		if cle == "" {
			continue
		}
		// Une clé contenant un saut de ligne en fabriquerait DEUX dans le
		// fichier, dont la seconde serait choisie par celui qui l'a fournie.
		if strings.ContainsAny(cle, "\n\r") {
			continue
		}
		contenu.WriteString(cle)
		contenu.WriteByte('\n')
	}

	_, errEcriture := f.WriteString(contenu.String())
	if errEcriture == nil {
		// fsync avant le rename : sans cela une coupure juste après peut laisser
		// un fichier de taille correcte au contenu vide.
		errEcriture = f.Sync()
	}
	_ = f.Chown(uid, gid)
	if errFermeture := f.Close(); errEcriture == nil {
		errEcriture = errFermeture
	}

	if errEcriture != nil {
		_ = syscall.Unlinkat(sshFD, nomTemporaireCles)
		return fmt.Errorf("écriture des clés échouée pour %s, ancien fichier conservé : %v", home, errEcriture)
	}

	if err := syscall.Renameat(sshFD, nomTemporaireCles, sshFD, "authorized_keys"); err != nil {
		_ = syscall.Unlinkat(sshFD, nomTemporaireCles)
		return fmt.Errorf("publication des clés échouée pour %s : %v", home, err)
	}
	return nil
}

// DecouperCles transforme le bloc de clés reçu du serveur en lignes.
//
// Séparée de l'écriture pour être testable seule, et parce que le format du
// bloc appartient au protocole, pas au système de fichiers.
func DecouperCles(brut string) []string {
	cles := []string{}
	for _, ligne := range strings.Split(brut, "\n") {
		if ligne = strings.TrimSpace(ligne); ligne != "" {
			cles = append(cles, ligne)
		}
	}
	return cles
}
