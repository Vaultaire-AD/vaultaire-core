package localusermanagement

import (
	"os/exec"

	"vaultaire_client/logs"
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

// RestaurerContexteSELinux applique le contexte attendu à un chemin.
//
// Récursif : le répertoire personnel, `.ssh` et les fichiers qu'il contient
// portent chacun un type différent, et seul `restorecon -R` les distingue.
//
// Sans effet et sans erreur sur une machine sans SELinux : `restorecon` y est
// absent, et l'on n'a alors rien à corriger.
func RestaurerContexteSELinux(chemin string) {
	binaire, err := exec.LookPath("restorecon")
	if err != nil {
		// Ni erreur ni avertissement : sur une machine sans SELinux, c'est le
		// cas NORMAL. Le signaler à chaque création de compte remplirait le
		// journal d'un bruit qui n'appelle aucune action.
		return
	}

	// -F force la réécriture même si le contexte semble déjà correct. Sans lui,
	// un fichier étiqueté par héritage — donc avec un contexte plausible mais
	// faux — serait laissé tel quel.
	if out, err := exec.Command(binaire, "-RF", chemin).CombinedOutput(); err != nil {
		logs.Write_log("WARNING", "selinux: contexte non restauré sur "+chemin+
			" : "+err.Error()+" "+string(out))
		return
	}
	logs.Write_log("DEBUG", "selinux: contexte restauré sur "+chemin)
}
