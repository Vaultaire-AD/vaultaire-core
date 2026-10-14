package localusermanagement

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Restauration du contexte SELinux après création de fichiers.
//
// # Le défaut que cela corrige
//
// Un fichier créé hérite du contexte SELinux de son répertoire parent. Comme
// l'agent crée `/home/<user>`, `.ssh` et `authorized_keys` par des appels
// ordinaires, la chaîne hérite de `/home` — donc `home_root_t` — au lieu de
// recevoir `user_home_dir_t` puis `ssh_home_t`.
//
// Relevé sur une machine réelle :
//
//	denied { open } ... path="/home/admin@vaultaire.fr/.ssh/authorized_keys"
//	tcontext=system_u:object_r:home_root_t
//
// sshd refuse alors de lire les clés, et la connexion échoue par clé publique
// alors que tout le reste a fonctionné.
//
// # Pourquoi corriger ici plutôt que dans la politique
//
// Une règle `allow sshd_t home_root_t:file read` ferait disparaître le refus —
// et autoriserait du même coup sshd à lire n'importe quel fichier déposé
// directement dans `/home`, par n'importe qui. On soignerait le symptôme en
// ouvrant bien plus large que le problème.
//
// Le fichier doit simplement porter le bon type.
//
// # Pourquoi appeler restorecon plutôt que lier libselinux
//
// Lier libselinux imposerait cgo, donc un binaire non statique et une
// dépendance de compilation sur chaque poste. `restorecon` est présent partout
// où SELinux l'est, et son absence est précisément le signe qu'il n'y a rien à
// restaurer.

// lancerRestorecon est une variable pour que les tests voient les appels sans
// SELinux ni restorecon. Rend la sortie combinée et l'erreur ; un binaire
// absent rend errRestoreconAbsent.
var lancerRestorecon = func(args ...string) ([]byte, error) {
	binaire, err := exec.LookPath("restorecon")
	if err != nil {
		return nil, errRestoreconAbsent
	}
	return exec.Command(binaire, args...).CombinedOutput()
}

var errRestoreconAbsent = errors.New("restorecon absent")

// RestaurerContexteSELinux applique le contexte attendu à un chemin, et à
// TOUT ce qu'il contient.
//
// Réservé à la CRÉATION du compte : le répertoire personnel vient d'être rempli
// depuis /etc/skel, et chacun de ces fichiers a hérité de `home_root_t`. Sur un
// compte existant, voir RestaurerContexteSELinuxCompte — parcourir tout le
// dossier à chaque connexion coûtait le temps d'un `find` sur l'ensemble du
// `HOME`, et deux fois (TO-DO 197).
//
// Sans effet et sans erreur sur une machine sans SELinux : `restorecon` y est
// absent, et l'on n'a alors rien à corriger.
func RestaurerContexteSELinux(chemin string) {
	restorecon(chemin, "-RF", chemin)
}

// RestaurerContexteSELinuxCompte remet le contexte de ce que l'agent écrit à
// chaque connexion : le répertoire personnel LUI-MÊME (sans descendre), et
// `.ssh` avec ce qu'il contient.
//
// C'est exactement ce que sshd lit — le dossier pour y entrer, `.ssh` et
// `authorized_keys` pour les clés. Le reste du dossier appartient à
// l'utilisateur : l'agent n'y crée rien à la connexion, et n'a pas à en
// relabelliser des milliers de fichiers.
func RestaurerContexteSELinuxCompte(home string) {
	if !restorecon(home, "-F", home) {
		return
	}
	ssh := filepath.Join(home, ".ssh")
	if _, err := os.Lstat(ssh); err != nil {
		return
	}
	restorecon(ssh, "-RF", ssh)
}

// restorecon lance la commande et dit si elle a tourné. Faux aussi quand
// restorecon est absent : il n'y a alors rien d'autre à essayer.
func restorecon(chemin string, args ...string) bool {
	out, err := lancerRestorecon(args...)
	if errors.Is(err, errRestoreconAbsent) {
		// Ni erreur ni avertissement : sur une machine sans SELinux, c'est le
		// cas NORMAL. Le signaler à chaque connexion remplirait le journal d'un
		// bruit qui n'appelle aucune action.
		return false
	}
	// -F force la réécriture même si le contexte semble déjà correct. Sans lui,
	// un fichier étiqueté par héritage — donc avec un contexte plausible mais
	// faux — serait laissé tel quel.
	if err != nil {
		logs.Write_log("WARNING", "selinux: contexte non restauré sur "+chemin+
			" : "+err.Error()+" "+string(out))
		return false
	}
	logs.Write_log("DEBUG", "selinux: contexte restauré sur "+chemin+" ("+strings.Join(args[:len(args)-1], " ")+")")
	return true
}
