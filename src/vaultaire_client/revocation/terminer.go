package revocation

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Couper ce qu'un compte a d'ouvert sur la machine — TO-DO 133.
//
// # Ce qui est coupé : TOUT ce qui tourne sous ce compte
//
// Pas seulement les sessions interactives. Un `tmux` détaché, une tâche
// planifiée, un tunnel SSH, un `nohup` : tout ce qui appartient au compte
// s'arrête.
//
// C'est une DÉCISION, pas un effet de bord de `pkill -u`. Le kill switch répond
// à « ce compte ne doit plus rien pouvoir faire ici ». Sur un compte compromis,
// ce qui survit à la fermeture du terminal est précisément ce que l'attaquant a
// laissé pour revenir — et c'est invisible depuis le poste. Un verrouillage qui
// épargnerait les processus détachés fermerait la porte en laissant la fenêtre.
//
// La contrepartie est assumée : un verrouillage pour départ (`--reason
// offboarding`) interrompt aussi le calcul long que la personne avait lancé.
// Qui veut l'épargner attend qu'il finisse — ou retire le compte de ses groupes,
// ce qui ferme les accès sans rien tuer.
//
// # Deux moyens, et pourquoi les deux
//
//   - `loginctl terminate-user` quand systemd-logind est là : il ferme les
//     sessions ET le gestionnaire utilisateur, donc tout ce qui vit dans la
//     tranche du compte — y compris un shell passé root par `sudo`, qui garde
//     son appartenance à la session alors que son uid a changé ;
//   - `pkill -KILL` par uid ensuite, dans tous les cas : pour une machine sans
//     logind (un conteneur), et pour ce qui aurait été lancé hors de toute
//     session.
//
// Aucun des deux ne suffit seul, et le second est celui qui se vérifie : on
// compte ce qui reste.
//
// # Ce que Vaultaire ne sait PAS faire, et n'a pas besoin de savoir
//
// Identifier UNE session. La table `user_sessions` du core fusionne trois `ssh`
// simultanés en une ligne ; le module PAM ne relève ni PID ni terminal. Il n'y
// a donc pas d'ordre « ferme la session X » — mais il n'en faut pas : couper un
// compte, c'est couper toutes ses sessions, et le système local les connaît.

// Remplaçables par les tests : sans cela, éprouver la décision demanderait de
// tuer de vrais processus, et d'attendre pour de bon, à chaque `go test`.
var (
	// attenteDeLaFin borne le temps laissé aux processus pour disparaître.
	// SIGKILL ne se refuse pas ; il lui faut seulement le temps d'être servi.
	attenteDeLaFin = 5 * time.Second
	// pasDeScrutation est l'intervalle entre deux comptages.
	pasDeScrutation = 100 * time.Millisecond

	commandePresente = func(nom string) bool {
		_, err := exec.LookPath(nom)
		return err == nil
	}
	logindActif = func() bool {
		// Le répertoire n'existe que si systemd-logind tourne. `loginctl` peut
		// être installé sans lui — c'est le cas d'une image de conteneur — et
		// échouerait alors sur chaque appel, pour rien.
		_, err := os.Stat("/run/systemd/seats")
		return err == nil
	}
	processusDe = compterLesProcessus
)

// terminerLeCompte ferme les sessions d'un compte et tue ses processus.
//
// Rend une erreur s'il en RESTE : c'est ce que le serveur doit apprendre.
func terminerLeCompte(username string) error {
	compte, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("compte %s introuvable : %w", username, err)
	}
	uid := strings.TrimSpace(compte.Uid)

	// DEUX refus, avant toute commande.
	//
	// L'ordre vient du réseau. Il est authentifié, et le core refuse de viser un
	// compte protégé — mais ce qui suit tue des processus par uid, et il n'y a
	// pas de seconde chance après un `pkill -KILL -U 0`. La machine ne s'en
	// relèverait pas, agent compris.
	if uid == "0" {
		return fmt.Errorf("refus de terminer les processus de root")
	}
	if uid == strconv.Itoa(os.Getuid()) {
		return fmt.Errorf("refus de terminer le compte sous lequel tourne l'agent")
	}
	if _, err := strconv.Atoi(uid); err != nil {
		return fmt.Errorf("uid illisible pour %s : %q", username, uid)
	}

	avant := processusDe(uid)

	if commandePresente("loginctl") && logindActif() {
		// L'échec n'est pas remonté : `terminate-user` sort en erreur quand le
		// compte n'a aucune session logind, ce qui est le cas ordinaire d'un
		// compte qui n'est pas connecté. Le comptage qui suit tranche.
		if err := executer("loginctl", "terminate-user", uid); err != nil {
			logs.Write_log("DEBUG", "revocation: loginctl terminate-user "+uid+" : "+err.Error())
		}
	}

	// -U et -u : uid réel, puis uid effectif. Un programme qui a changé
	// d'identité en cours de route n'est vu que par l'un des deux.
	//
	// pkill sort avec 1 quand rien ne correspond : c'est le cas normal d'un
	// compte sans processus, pas une erreur.
	if commandePresente("pkill") {
		_ = executer("pkill", "-KILL", "-U", uid)
		_ = executer("pkill", "-KILL", "-u", uid)
	} else if avant != 0 {
		return fmt.Errorf("pkill absent de cette machine, %s garde ses processus", username)
	}

	// On COMPTE ce qui reste, plutôt que de croire les codes de retour.
	reste := avant
	echeance := time.Now().Add(attenteDeLaFin)
	for {
		reste = processusDe(uid)
		if reste <= 0 || !time.Now().Before(echeance) {
			break
		}
		time.Sleep(pasDeScrutation)
	}

	switch {
	case reste > 0:
		return fmt.Errorf("%d processus de %s encore en vie après %s", reste, username, attenteDeLaFin)
	case reste < 0:
		// Le comptage lui-même a échoué : on ne sait pas. On le dit, sans en
		// faire un échec de l'ordre — les deux coupures sont parties.
		logs.Write_log("WARNING", "revocation: sessions de "+username+
			" coupées, mais ce qui reste n'a pas pu être compté (pgrep absent ?)")
	case avant > 0:
		logs.Write_log("WARNING", fmt.Sprintf(
			"revocation: sessions de %s fermées — %d processus terminé(s)", username, avant))
	default:
		logs.Write_log("INFO", "revocation: "+username+" n'avait rien d'ouvert sur cette machine")
	}
	return nil
}

// compterLesProcessus rend le nombre de processus d'un uid, ou -1 s'il n'a pas
// pu être établi.
//
// Par /proc et non par `pgrep` : la machine qu'on est en train de couper est
// peut-être celle où un attaquant a remplacé les outils, et lire /proc ne
// dépend d'aucun binaire. Le uid RÉEL et le uid EFFECTIF comptent tous deux.
func compterLesProcessus(uid string) int {
	entrees, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	total := 0
	for _, e := range entrees {
		if !e.IsDir() || !estUnNombre(e.Name()) {
			continue
		}
		statut, err := os.ReadFile("/proc/" + e.Name() + "/status")
		if err != nil {
			// Le processus a disparu entre le listage et la lecture : c'est ce
			// qu'on attend d'un compte qu'on vient de couper.
			continue
		}
		if appartientA(string(statut), uid) {
			total++
		}
	}
	return total
}

// appartientA dit si un /proc/<pid>/status décrit un processus VIVANT du compte.
//
//	State:  S (sleeping)
//	Uid:    1001    1001    1001    1001      réel, effectif, sauvegardé, fs
//
// Un zombie ne compte pas : il est mort, il n'exécute plus rien, et il ne reste
// dans la table que le temps que son parent le relève. Le compter ferait
// déclarer en échec une coupure réussie chaque fois qu'un parent tarde.
func appartientA(statut, uid string) bool {
	for _, ligne := range strings.Split(statut, "\n") {
		if strings.HasPrefix(ligne, "State:") && strings.Contains(ligne, "Z") {
			return false
		}
		if !strings.HasPrefix(ligne, "Uid:") {
			continue
		}
		champs := strings.Fields(strings.TrimPrefix(ligne, "Uid:"))
		for i, champ := range champs {
			if i > 1 {
				break
			}
			if champ == uid {
				return true
			}
		}
		return false
	}
	return false
}

func estUnNombre(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
