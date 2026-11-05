package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Les trois modules utilisateur qui n'avaient pas de vérificateur — TO-DO 163.
//
// Le point 135 a fait entrer la portée utilisateur dans l'inventaire. Trois
// modules n'y laissaient encore rien que le scan sache relire : un compte qui
// ne recevait qu'eux restait « non vérifié », et ce qu'ils posaient pouvait
// être défait sans que personne ne le voie.
//
// Chacun a ici son attente, écrite pour ce qu'il pose VRAIMENT :
//
//	user_git_config        une clé de ~/.gitconfig — pas le fichier, qui est à
//	                       la personne
//	user_password_policy   l'âge maximal et le délai d'avertissement que rend
//	                       `chage -l`
//	user_cron              le lien d'activation du timer, que systemd lit à
//	                       chaque ouverture de session
//
// Tous trois regardent sous un compte : ils reçoivent c.Compte, que le scan pose
// pour une portée utilisateur.

const (
	// CheckGitConfig vérifie la valeur d'une clé de ~/.gitconfig.
	CheckGitConfig = "git_config"
	// CheckPasswordAging vérifie le vieillissement du mot de passe d'un compte.
	CheckPasswordAging = "password_aging"
	// CheckUserTimer vérifie qu'un timer utilisateur est activé.
	CheckUserTimer = "user_timer"
)

// separateurCleGit sépare le chemin du .gitconfig de la clé, dans la cible.
// Même convention que les blocs : `/home/alice/.gitconfig#cle:user.email`.
const separateurCleGit = "#cle:"

func init() {
	registerChecker(CheckGitConfig, verifierCleGit)
	registerChecker(CheckPasswordAging, verifierVieillissement)
	registerChecker(CheckUserTimer, verifierTimerUtilisateur)
}

// compteDuScan rend le dossier et l'uid du compte dont on scanne la portée.
func compteDuScan(c SystemCheck) (home string, uid int, err error) {
	if c.Compte == "" {
		return "", 0, fmt.Errorf("attente %s hors d'une portee utilisateur", c.Kind)
	}
	home, err = resolveHomeDir(c.Compte)
	if err != nil {
		return "", 0, err
	}
	uid, _, err = resolveUserIDs(c.Compte)
	return home, uid, err
}

// --- user_git_config ---------------------------------------------------------

// empreinteDeValeur hache la valeur d'une clé.
//
// Une empreinte et non la valeur : l'attendu d'une attente est un texte
// « a=1,b=2 », et une valeur git peut porter des virgules, des signes égal,
// n'importe quoi.
func empreinteDeValeur(valeur string) string {
	somme := sha256.Sum256([]byte(valeur))
	return hex.EncodeToString(somme[:])
}

// cleGitCanonique met une clé sous la forme où git la rend.
//
// Section et variable sont insensibles à la casse — git les rend en
// minuscules ; la sous-section, entre les deux, garde la sienne. « User.Email »
// et « user.email » sont la même clé, « url.HTTPS://x/.insteadOf » ne perd que
// la casse de ses deux bouts.
func cleGitCanonique(cle string) string {
	premier := strings.Index(cle, ".")
	dernier := strings.LastIndex(cle, ".")
	if premier < 0 {
		return strings.ToLower(cle)
	}
	if premier == dernier {
		return strings.ToLower(cle)
	}
	return strings.ToLower(cle[:premier]) + cle[premier:dernier] + strings.ToLower(cle[dernier:])
}

// lireCleGit rend la valeur d'une clé d'un contenu de .gitconfig.
//
// # Par git, et sur une copie
//
// C'est git qui connaît son format — sections répétées, guillemets,
// continuations de ligne — et le relire à la main finirait par constater autre
// chose que ce que git appliquera. Mais git ne travaille JAMAIS sous le dossier
// de la personne (TO-DO 162) : le contenu, déjà lu par la descente sûre, est
// recopié dans un répertoire que seul root ouvre.
//
// `--list -z` et non `--get` : la sortie sépare clé et valeur sans ambiguïté, et
// la commande ne sort pas en erreur quand la clé manque — une erreur veut alors
// dire que le fichier est illisible pour git, ce qui est une autre nouvelle.
// `--file` n'inclut aucun autre fichier : seul ce contenu est lu.
//
// Une clé répétée rend sa DERNIÈRE valeur, comme git.
func lireCleGit(contenu, cle string) (valeur string, presente bool, err error) {
	if !commandExists("git") {
		return "", false, fmt.Errorf("git absent : cle %s inverifiable", cle)
	}
	atelier, err := os.MkdirTemp("", "vaultaire-git-")
	if err != nil {
		return "", false, fmt.Errorf("repertoire de travail impossible : %v", err)
	}
	defer os.RemoveAll(atelier)
	copie := filepath.Join(atelier, "config")
	if err := os.WriteFile(copie, []byte(contenu), 0o600); err != nil {
		return "", false, fmt.Errorf("copie de travail impossible : %v", err)
	}

	sortie, err := runCommandTimeout(UserCommandTimeout, "git", "config", "--file", copie, "--list", "-z")
	if err != nil {
		return "", false, fmt.Errorf(".gitconfig illisible pour git : %v", err)
	}
	voulue := cleGitCanonique(cle)
	for _, entree := range strings.Split(sortie, "\x00") {
		nom, v, _ := strings.Cut(entree, "\n")
		if nom == voulue {
			valeur, presente = v, true
		}
	}
	return valeur, presente, nil
}

// verifierCleGit constate qu'une clé de ~/.gitconfig a la valeur posée — ou
// n'y est pas, quand la politique la retire.
//
// Le reste du fichier est à la personne : seule CETTE clé est regardée.
func verifierCleGit(c SystemCheck) (bool, string, error) {
	i := strings.Index(c.Target, separateurCleGit)
	if i <= 0 || i+len(separateurCleGit) >= len(c.Target) {
		return false, "", fmt.Errorf("cible de cle git illisible")
	}
	chemin, cle := c.Target[:i], c.Target[i+len(separateurCleGit):]

	home, uid, err := compteDuScan(c)
	if err != nil {
		return false, "", err
	}
	attendu := champsAttendus(c.Expect)
	veutAbsente := attendu["etat"] == "absent"

	contenu, existe, err := lireFichierUtilisateur(home, chemin, uid)
	switch {
	case errors.Is(err, ErrCheminSuspect):
		return false, chemin + " n'est plus un fichier ordinaire du compte", nil
	case err != nil:
		return false, "", err
	case !existe && veutAbsente:
		return true, "", nil
	case !existe:
		return false, "cle git " + cle + " : " + filepath.Base(chemin) + " supprime", nil
	}

	valeur, presente, err := lireCleGit(contenu, cle)
	if err != nil {
		return false, "", err
	}
	switch {
	case veutAbsente && presente:
		return false, "cle git " + cle + " retablie alors que la politique la retire", nil
	case veutAbsente:
		return true, "", nil
	case !presente:
		return false, "cle git " + cle + " retiree", nil
	case empreinteDeValeur(valeur) != attendu["sha256"]:
		return false, "cle git " + cle + " modifiee", nil
	}
	return true, "", nil
}

// --- user_password_policy ----------------------------------------------------

// verifierVieillissement constate l'âge maximal et le délai d'avertissement.
//
// Expect ne porte que ce que le module a fixé : « max=90 », « warn=7 », ou les
// deux.
//
// # Ce qui n'est PAS vérifié : le changement forcé
//
// `force_change` pose la date du dernier changement à zéro. Elle se CONSOMME :
// dès que la personne a changé son mot de passe, la date n'est plus zéro, et
// c'est exactement ce qu'on attendait d'elle. La vérifier signalerait un écart
// sur chaque compte qui a obéi, et le « corriger » redemanderait un mot de
// passe neuf à chaque connexion.
func verifierVieillissement(c SystemCheck) (bool, string, error) {
	attendu := champsAttendus(c.Expect)
	if len(attendu) == 0 {
		return true, "", nil
	}
	if !commandExists("chage") {
		return false, "", fmt.Errorf("chage absent de cette machine")
	}
	sortie, err := runCommand("chage", "-l", c.Target)
	if err != nil {
		return false, "", fmt.Errorf("chage -l %s : %v", c.Target, err)
	}
	valeurs := lireChage(sortie)

	var ecarts []string
	for _, facette := range []struct{ cle, nom string }{
		{"max", "age maximal"},
		{"warn", "delai d'avertissement"},
	} {
		veut, demande := attendu[facette.cle]
		if !demande {
			continue
		}
		if constate, connu := valeurs[facette.cle]; !connu || constate != veut {
			ecarts = append(ecarts, ecartConstate(facette.nom, veut, ouInconnu(constate, connu)))
		}
	}
	if len(ecarts) == 0 {
		return true, "", nil
	}
	return false, c.Target + " : " + strings.Join(ecarts, " ; "), nil
}

// --- user_cron ---------------------------------------------------------------

// LienDActivation rend le chemin du lien qui active un timer utilisateur.
//
// `systemctl --user enable` le crée dans `timers.target.wants`, à côté des
// unités ; c'est lui que systemd relit à chaque ouverture de session pour savoir
// quoi démarrer.
func lienDActivation(repertoireDesUnites, timer string) string {
	return filepath.Join(repertoireDesUnites, "timers.target.wants", timer)
}

// verifierTimerUtilisateur constate qu'un timer utilisateur est ACTIVÉ.
//
// # Ce qui est constaté, et pourquoi pas `is-enabled`
//
// `systemctl --user is-enabled` demande le bus de la personne, qui n'existe pas
// hors de sa session — et le scan tourne justement AVANT qu'elle ne s'ouvre.
// L'activation, elle, est sur le disque : un lien, dans `timers.target.wants`,
// du nom de l'unité. systemd n'y lit que cela.
//
// Deux états sont constatés, et seulement ceux dont on est sûr :
//
//   - le lien a DISPARU : le timer est désactivé ;
//   - il désigne `/dev/null` : systemd ignore une telle entrée — c'est la forme
//     sous laquelle on neutralise une unité.
//
// La CIBLE du lien n'est pas comparée à un chemin : systemd l'écrit en absolu ou
// en relatif selon sa version, et c'est le NOM de l'entrée qu'il lit. Une entrée
// qui n'est pas un lien — quelqu'un y a mis un fichier — n'est ni déclarée
// conforme ni déclarée en écart : on ne sait pas ce que systemd en fera, et on
// le dit. Une vérification approximative est pire qu'aucune.
//
// # Ce qui n'est PAS constaté
//
// Que le timer TOURNE en ce moment. C'est l'état d'un gestionnaire qui n'existe
// qu'en session ; une unité activée y démarre, et c'est ce que la politique
// demande.
func verifierTimerUtilisateur(c SystemCheck) (bool, string, error) {
	home, uid, err := compteDuScan(c)
	if err != nil {
		return false, "", err
	}
	timer := filepath.Base(c.Target)

	cible, existe, estLien, err := lireLienSousHome(home, c.Target, uid)
	switch {
	case errors.Is(err, ErrCheminSuspect):
		return false, "le repertoire des unites de " + c.Compte + " n'est plus un repertoire ordinaire du compte", nil
	case err != nil:
		return false, "", err
	case !existe:
		return false, "timer " + timer + " desactive : son lien d'activation a disparu", nil
	case !estLien:
		return false, "", fmt.Errorf("timer %s : son entree d'activation n'est plus un lien, etat incertain", timer)
	case cible == "/dev/null":
		return false, "timer " + timer + " neutralise : son lien d'activation designe /dev/null", nil
	}
	return true, "", nil
}
