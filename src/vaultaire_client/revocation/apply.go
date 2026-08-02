package revocation

import (
	"fmt"
	"os/exec"
	"os/user"
	"strings"

	"vaultaire_client/logs"
)

// Modes acceptés. Doivent rester alignés sur core/revocation côté serveur —
// les deux modules Go sont séparés, il n'y a pas de type partagé possible.
const (
	ModeSoft   = "soft"
	ModeUnlock = "unlock"
	ModeHard   = "hard"
)

// Résultats renvoyés au serveur dans une trame 06_02.
const (
	ResultApplied       = "applied"
	ResultAlreadyAbsent = "already_absent"
	ResultNotApplicable = "not_applicable"
)

// Apply exécute un ordre sur le compte local et retourne le résultat.
//
// Le nom reçu peut être complet (admin@vaultaire.fr) : c'est le nom du compte
// LOCAL tel que le module PAM l'a créé, donc on l'utilise tel quel. Le rogner
// viserait un compte qui n'existe pas et l'ordre serait sans effet — silencieusement.
func Apply(mode, username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("utilisateur cible manquant")
	}

	// Compte absent : rien à faire, et c'est un SUCCÈS. Un ordre part vers
	// toutes les machines partageant un groupe avec l'utilisateur, or il ne
	// s'est pas forcément connecté à chacune. Signaler un échec provoquerait un
	// rejeu sans fin sur des machines qui n'ont rien à nettoyer.
	if _, err := user.Lookup(username); err != nil {
		logs.Write_log("INFO", fmt.Sprintf(
			"revocation: aucun compte local %s sur cette machine, ordre sans objet", username))
		return ResultAlreadyAbsent, nil
	}

	switch mode {
	case ModeSoft:
		return lockAccount(username)
	case ModeUnlock:
		return unlockAccount(username)
	case ModeHard:
		return deleteAccount(username)
	default:
		return "", fmt.Errorf("mode inconnu %q", mode)
	}
}

// lockAccount verrouille un compte local sans rien détruire.
//
// DEUX verrous, et il en faut deux :
//
//   - `usermod -L` préfixe le hash d'un « ! » dans /etc/shadow : plus aucune
//     authentification par mot de passe. Mais cela ne bloque PAS une connexion
//     par clé SSH, ni les sessions déjà ouvertes.
//   - `chage -E 1` fixe la date d'expiration du compte au 2 janvier 1970 :
//     le compte est expiré, ce que la pile PAM (pam_unix, account) refuse
//     quelle que soit la méthode d'authentification, clé SSH comprise.
//
// Le premier seul laisserait entrer par clé. Le second seul suffirait presque,
// mais un administrateur qui lit /etc/shadow doit voir que le compte est
// verrouillé, pas seulement expiré.
func lockAccount(username string) (string, error) {
	if err := run("usermod", "-L", username); err != nil {
		return "", fmt.Errorf("verrouillage du mot de passe : %w", err)
	}
	if err := run("chage", "-E", "1", username); err != nil {
		// Le premier verrou tient déjà : on remonte l'échec pour que le serveur
		// le voie et rejoue, mais l'accès par mot de passe est déjà coupé.
		return "", fmt.Errorf("expiration du compte : %w", err)
	}

	logs.Write_log("WARNING", "revocation: compte local "+username+" verrouillé (mot de passe invalidé, compte expiré)")
	return ResultApplied, nil
}

// unlockAccount lève le verrouillage posé par lockAccount.
//
// `chage -E -1` retire la date d'expiration, `usermod -U` retire le « ! ».
// L'ordre inverse de la pose, sans importance technique ici, mais qui rend la
// symétrie lisible.
func unlockAccount(username string) (string, error) {
	if err := run("chage", "-E", "-1", username); err != nil {
		return "", fmt.Errorf("levée de l'expiration : %w", err)
	}
	if err := run("usermod", "-U", username); err != nil {
		return "", fmt.Errorf("déverrouillage du mot de passe : %w", err)
	}

	logs.Write_log("INFO", "revocation: compte local "+username+" déverrouillé")
	return ResultApplied, nil
}

// deleteAccount supprime le compte et son répertoire personnel.
//
// `userdel -r` détruit le home. C'est le choix retenu pour le mode hard, et il
// est irréversible : sur un compte compromis, cela détruit aussi les traces de
// la compromission.
//
// Les processus de l'utilisateur sont tués d'abord : userdel refuse de
// supprimer un compte dont une session est encore ouverte, et sur une
// révocation d'urgence la personne est précisément en train de travailler.
func deleteAccount(username string) (string, error) {
	// pkill retourne 1 quand aucun processus ne correspond : ce n'est pas une
	// erreur, c'est le cas normal d'un utilisateur non connecté.
	_ = run("pkill", "-KILL", "-u", username)

	if err := run("userdel", "-r", username); err != nil {
		return "", fmt.Errorf("suppression du compte : %w", err)
	}

	logs.Write_log("WARNING", "revocation: compte local "+username+" supprimé, répertoire personnel détruit")
	return ResultApplied, nil
}

// run exécute une commande système et joint sa sortie à l'erreur.
//
// Sans la sortie, un échec de userdel se résume à « exit status 8 » dans le
// rapport remonté au serveur — inexploitable pour comprendre pourquoi une
// machine n'a pas pu couper un compte.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			return err
		}
		return fmt.Errorf("%w : %s", err, detail)
	}
	return nil
}
