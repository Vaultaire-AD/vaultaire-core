package sshauth

import (
	"fmt"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
)

// La boucle de synchronisation des groupes du domaine.
//
// # Pourquoi pas un time.Ticker
//
// Un ticker lit sa période UNE FOIS, à la construction. La cadence, elle, arrive
// du core dans chaque 03_09 et peut changer d'un passage à l'autre : avec un
// ticker, la nouvelle valeur serait visible dans l'interface d'administration et
// sans effet jusqu'au redémarrage du service.
//
// Un réglage qui s'affiche sans agir est plus trompeur que pas de réglage du
// tout — c'est la raison d'être de `reglages.Boucle` côté core, et la même ici.
// Le `time.After` est donc reconstruit à chaque tour, sur la période courante.

// BootstrapGroupes arme la synchronisation et rend la main immédiatement.
//
// Appelé au démarrage du service, AVANT que le tunnel ne soit monté : la boucle
// attend elle-même une session utilisable.
func BootstrapGroupes() {
	go boucleGroupes()
	logs.Write_log("INFO", fmt.Sprintf(
		"groupes du domaine : synchronisation armée (cadence initiale %s)", Cadence()))
}

func boucleGroupes() {
	defer logs.Recover("synchronisation des groupes")

	// Premier passage immédiat : la machine doit connaître ses groupes dès le
	// démarrage, pas au bout d'une heure. Sans cela, un poste redémarré
	// n'appliquerait aucune appartenance de toute la première période.
	envoyerDemandeGroupes()

	for {
		select {
		case <-time.After(Cadence()):
		case <-declencher:
			// Réveil provoqué par une session qui a trouvé un groupe manquant.
		}
		envoyerDemandeGroupes()
	}
}

// envoyerDemandeGroupes émet une 03_08.
func envoyerDemandeGroupes() {
	// WaitForVaultaireSession plutôt qu'un simple Get : au moment de l'envoi, le
	// tunnel peut être en cours de rétablissement après une coupure, et
	// abandonner ferait perdre un cycle entier.
	session, err := stosession.SessionsUser.WaitForVaultaireSession()
	if err != nil || session == nil || session.DuckySession == nil {
		logs.Write_log("WARNING",
			"groupes du domaine : aucune session vaultaire valide, demande non envoyée")
		return
	}

	trame := strings.Join([]string{
		"03_08",
		"serveur_central",
		string(session.DuckySession.SessionKey),
		"vaultaire",
		storage.Computeur_ID,
	}, "\n")

	sendmessage.SendMessage(trame, session.DuckySession)
}
