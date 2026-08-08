package pamcommunication

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
)

// Contrôle de l'appelant sur le socket PAM.
//
// # Pourquoi vérifier, alors que le socket est déjà en 0600
//
// Les permissions du socket et de son répertoire sont la première barrière, et
// la plus solide. Ce contrôle est la seconde : il survit à une erreur de
// déploiement — un répertoire recréé à la main avec le mauvais mode, un umask
// inattendu, une image qui pose /run/vaultaire en 0755.
//
// Une seule barrière suffit tant que rien ne va mal. Ce qui compte ici, c'est ce
// qui se passe quand quelque chose va mal : le mot de passe en clair de chaque
// connexion transite par ce canal.
//
// # Pourquoi root et pas « le même utilisateur »
//
// Les modules PAM sont chargés par sshd, login et sudo, qui tournent tous en
// root au moment de l'authentification. Aucun appelant légitime n'est autre
// chose que root.

// peerIsRoot indique si l'autre extrémité du socket appartient à root.
//
// syscall plutôt que golang.org/x/sys : GetsockoptUcred est dans la
// bibliothèque standard sous Linux, et l'agent n'a aucune dépendance externe en
// dehors de yaml. En ajouter une pour trois lignes obligerait chaque poste de
// compilation à la récupérer.
//
// SO_PEERCRED est renseigné par le NOYAU au moment de connect() : l'appelant ne
// peut pas le falsifier, contrairement à tout ce qu'il enverrait dans la trame.
func peerIsRoot(conn net.Conn) (bool, string, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false, "", fmt.Errorf("connexion non-unix")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false, "", err
	}

	var cred *syscall.Ucred
	var credErr error
	// Control donne accès au descripteur sans que le runtime le referme sous nos
	// pieds : le lire par Fd() le mettrait en mode bloquant et sortirait le
	// socket du poller.
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return false, "", err
	}
	if credErr != nil {
		return false, "", credErr
	}

	desc := fmt.Sprintf("pid=%d uid=%d gid=%d", cred.Pid, cred.Uid, cred.Gid)
	return cred.Uid == 0, desc, nil
}

// ensureSocketDir prépare /run/vaultaire avant l'écoute.
//
// MkdirAll n'ajuste PAS le mode d'un répertoire existant : une machine où le
// répertoire aurait été créé en 0755 par un script de déploiement garderait ce
// mode indéfiniment. Le Chmod explicite est donc nécessaire, pas redondant.
func ensureSocketDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("création de %s : %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("mode de %s : %w", dir, err)
	}
	return nil
}

// connexionsRefusees compte les appelants non privilégiés écartés.
//
// # Pourquoi un compteur, et pas seulement une ligne de journal
//
// Deux raisons, et la seconde est celle qui l'a fait ajouter.
//
// En exploitation : une valeur non nulle veut dire que quelqu'un a tenté
// d'ouvrir le canal d'authentification depuis un compte ordinaire. Ce n'est
// jamais accidentel — aucun appelant légitime n'est autre chose que root.
//
// En test : sans lui, on ne peut pas distinguer « refusé avant traitement » de
// « traité, mais sans réponse parce que le core est injoignable ». Les deux se
// ressemblent vus du client, et un test qui les confond passe au vert alors
// que le contrôle a disparu — ce qui s'est effectivement produit lors de la
// vérification par mutation.
var connexionsRefusees atomic.Int64

// ConnexionsRefusees rend le nombre d'appelants non privilégiés écartés.
func ConnexionsRefusees() int64 { return connexionsRefusees.Load() }
