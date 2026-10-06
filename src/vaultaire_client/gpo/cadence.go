package gpo

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Cadence du rafraîchissement machine, et déclenchements hors tour.
//
// # Pourquoi la cadence vient du core
//
// La boucle tourne ici, mais la décision appartient au core : c'est lui qui
// sait si le parc doit se rafraîchir toutes les dix minutes pendant un
// déploiement, ou toutes les six heures sur un réseau contraint. Une constante
// dans l'agent aurait obligé à redéployer tout le parc pour changer un nombre.
//
// La valeur voyage dans les réponses machine (05_02 et 05_03), derrière le
// préfixe PrefixeCadence. Même recette que `group_sync_minutes` et la trame
// 03_09 : une ligne en queue, reconnue à son préfixe, ignorée par un agent qui
// ne la connaît pas.
//
// # Pourquoi elle n'est pas persistée
//
// Un agent qui redémarre repart de MachineRefreshInterval — mais son premier
// cycle est immédiat, et la réponse à ce cycle porte la cadence. La fenêtre
// pendant laquelle l'agent utilise le défaut dure donc le temps d'un aller-
// retour. Écrire la valeur sur le disque aurait ajouté un fichier à tenir à
// jour, à migrer et à protéger, pour couvrir quelques secondes.

// PrefixeCadence ouvre la ligne de cadence dans 05_02 et 05_03.
const PrefixeCadence = "refresh:"

// Bornes de la cadence acceptée, identiques à celles du réglage
// `gpo_refresh_minutes` côté core.
//
// Un core ne devrait jamais annoncer hors de ces bornes — le réglage les
// applique déjà. Elles sont là parce qu'une valeur reçue du réseau qui pilote
// une boucle infinie mérite une borne locale : une cadence à zéro transformerait
// l'agent en boucle d'attente active, et une cadence d'un mois le ferait
// disparaître du parc sans que rien ne le signale.
const (
	CadenceMinimum = 5 * time.Minute
	CadenceMaximum = 24 * time.Hour
)

// PrefixeVerifUtilisateur ouvre la ligne qui annonce la cadence de vérification
// du scope UTILISATEUR — TO-DO 142.
//
// # Pourquoi une seconde cadence
//
// La vérification d'un `HOME` était bornée par la cadence MACHINE : au plus un
// scan par compte et par `gpo_refresh_minutes`. Sur un parc réglé à une heure,
// quelqu'un qui défaisait sa politique, se déconnectait et revenait dix minutes
// plus tard retrouvait son dossier tel qu'il l'avait laissé — le scan avait eu
// lieu « récemment », et sans scan le cycle reçoit « politique inchangée ».
//
// Les deux durées ne répondent pas à la même question. La cadence machine dit
// à quel rythme un parc redemande une politique qui n'a le plus souvent pas
// changé : c'est du trafic, on le veut rare. Celle-ci dit combien de temps une
// personne peut rester avec un dossier défait en se reconnectant : c'est le
// délai de réparation, on le veut court. Les lier obligeait à choisir entre un
// parc bavard et des `HOME` réparés une fois par heure.
//
// Elle part dans les QUATRE réponses de politique — 05_02 et 05_03 pour que
// l'agent la connaisse dès son premier cycle machine, avant la première
// connexion ; 05_06 et 05_07 pour qu'un réglage modifié atteigne le poste à la
// connexion suivante, sans attendre le tour de la machine.
const PrefixeVerifUtilisateur = "usercheck:"

// Bornes et défaut de la vérification utilisateur, identiques à celles du
// réglage `gpo_user_check_minutes` côté core.
//
// Cinq minutes par défaut : c'est aussi ce qu'applique un agent face à un core
// qui n'annonce rien — plus ancien que ce réglage.
//
// Une minute au moins. La borne ne protège pas d'une boucle, comme celle de la
// cadence machine : aucune boucle ne tourne ici, c'est PAM qui déclenche. Elle
// protège du scan répété — un déverrouillage d'écran est une authentification
// PAM comme une autre, et quelqu'un qui verrouille et déverrouille son poste
// ne doit pas faire hacher son inventaire à chaque fois.
const (
	VerifUtilisateurParDefaut = 5 * time.Minute
	VerifUtilisateurMinimum   = 1 * time.Minute
	VerifUtilisateurMaximum   = 24 * time.Hour
)

var (
	cadenceMu sync.Mutex
	cadence   = MachineRefreshInterval

	cadenceUtilisateur = VerifUtilisateurParDefaut

	// Canaux de réveil de la boucle de rafraîchissement.
	//
	// Capacité 1 et écriture non bloquante : un signal déjà en attente rend le
	// suivant inutile — la boucle ne fera de toute façon qu'un seul cycle. Sans
	// cette précaution, une rafale de 05_18 bloquerait le lecteur de trames.
	reveilCadence = make(chan struct{}, 1)
	reveilCycle   = make(chan struct{}, 1)
)

// CadenceActuelle rend l'intervalle de rafraîchissement en vigueur.
func CadenceActuelle() time.Duration {
	cadenceMu.Lock()
	defer cadenceMu.Unlock()
	return cadence
}

// CadenceUtilisateur rend l'intervalle minimal entre deux vérifications du
// scope utilisateur d'un même compte.
func CadenceUtilisateur() time.Duration {
	cadenceMu.Lock()
	defer cadenceMu.Unlock()
	return cadenceUtilisateur
}

// appliquerCadenceUtilisateur cherche la ligne `usercheck:` dans une réponse de
// politique et l'applique.
//
// Cherchée par son PRÉFIXE, comme l'autre. Aucune boucle à réveiller : la
// valeur est lue au prochain passage de PAM.
func appliquerCadenceUtilisateur(lignes []string) {
	for _, ligne := range lignes {
		valeur := strings.TrimSpace(ligne)
		if !strings.HasPrefix(valeur, PrefixeVerifUtilisateur) {
			continue
		}
		minutes, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(valeur, PrefixeVerifUtilisateur)))
		if err != nil {
			logs.Write_log("WARNING", "GPO: cadence de verification utilisateur illisible : "+valeur)
			return
		}
		definirCadenceUtilisateur(time.Duration(minutes) * time.Minute)
		return
	}
}

// definirCadenceUtilisateur pose la cadence, bornée.
func definirCadenceUtilisateur(nouvelle time.Duration) {
	switch {
	case nouvelle < VerifUtilisateurMinimum:
		nouvelle = VerifUtilisateurMinimum
	case nouvelle > VerifUtilisateurMaximum:
		nouvelle = VerifUtilisateurMaximum
	}

	cadenceMu.Lock()
	change := nouvelle != cadenceUtilisateur
	cadenceUtilisateur = nouvelle
	cadenceMu.Unlock()

	if change {
		logs.Write_log("INFO", fmt.Sprintf(
			"GPO: verification du scope utilisateur au plus toutes les %s, sur decision du serveur", nouvelle))
	}
}

// appliquerCadence cherche la ligne de cadence dans une réponse machine et
// l'applique si elle a changé.
//
// La ligne est cherchée par son PRÉFIXE dans toutes les lignes, jamais à un
// rang fixe : les réponses 05_02 et 05_03 n'ont pas le même nombre de champs,
// et un champ ajouté plus tard ne doit pas déplacer celui-ci.
func appliquerCadence(lignes []string) {
	for _, ligne := range lignes {
		valeur := strings.TrimSpace(ligne)
		if !strings.HasPrefix(valeur, PrefixeCadence) {
			continue
		}
		minutes, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(valeur, PrefixeCadence)))
		if err != nil {
			logs.Write_log("WARNING", "GPO: cadence illisible dans la reponse du serveur : "+valeur)
			return
		}
		definirCadence(time.Duration(minutes) * time.Minute)
		return
	}
}

// definirCadence pose la cadence, bornée, et réveille la boucle si elle change.
func definirCadence(nouvelle time.Duration) {
	switch {
	case nouvelle < CadenceMinimum:
		nouvelle = CadenceMinimum
	case nouvelle > CadenceMaximum:
		nouvelle = CadenceMaximum
	}

	cadenceMu.Lock()
	change := nouvelle != cadence
	cadence = nouvelle
	cadenceMu.Unlock()

	if !change {
		return
	}
	logs.Write_log("INFO", fmt.Sprintf(
		"GPO: cadence de rafraichissement machine portee a %s par le serveur", nouvelle))
	// Le réveil sert le cas qui compte : passer d'une heure à dix minutes
	// pendant un déploiement. Sans lui, la nouvelle cadence n'entrerait en
	// vigueur qu'au terme de l'ancienne attente — soit jusqu'à une heure de
	// retard sur un changement fait pour aller plus vite.
	signaler(reveilCadence)
}

// DemanderCycleImmediat déclenche un cycle machine hors du tour périodique.
//
// Trois appelants, un seul chemin : la trame 05_18 poussée par le core, le
// rétablissement du tunnel, et un déclenchement local. Passer par la boucle
// plutôt que lancer un cycle sur place préserve le verrou de cycle unique et
// laisse la boucle reprendre son attente ensuite.
func DemanderCycleImmediat(motif string) {
	logs.Write_log("INFO", "GPO: cycle machine demande hors tour ("+motif+")")
	signaler(reveilCycle)
}

// signaler dépose un réveil sans jamais bloquer.
func signaler(canal chan struct{}) {
	select {
	case canal <- struct{}{}:
	default:
	}
}
