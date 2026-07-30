package gpo

import (
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
	"vaultaire_client/storage/stosession"
	sto_session "vaultaire_client/storage/stosession"
)

// Amorçage du transport GPO côté agent.
//
// Isolé dans son propre fichier parce qu'il est le seul endroit du paquet à
// connaître la couche session et la couche d'envoi. Le reste du paquet ne
// dépend que de l'émetteur injecté par Configure, ce qui le garde testable sans
// tunnel réseau.

// Bootstrap configure le transport puis démarre le cycle machine et son
// rafraîchissement périodique.
//
// Appelé une fois au démarrage du service, après le lancement de la session
// mère. Le premier cycle attend qu'une session vaultaire soit disponible : au
// démarrage, le tunnel n'est pas encore établi et une demande partirait dans le
// vide.
func Bootstrap() {
	Configure(func(trame string) {
		session, _ := sto_session.SessionsUser.WaitForVaultaireSession()
		if session == nil || session.DuckySession == nil {
			logs.Write_log("WARNING", "GPO: aucune session vaultaire valide, trame non envoyee")
			return
		}
		sendmessage.SendMessage(trame, session.DuckySession)
	}, storage.Computeur_ID)

	StartMachineRefresh(CurrentSessionKey)
	logs.Write_log("INFO", "GPO: transport initialise, cycle machine programme")
}

// CurrentSessionKey retourne la clé de la session mère vaultaire, ou "" si
// aucune session n'est établie.
//
// Réévaluée à chaque usage : la clé change à chaque reconnexion du tunnel, la
// mémoriser produirait des trames rejetées après la première rupture.
func CurrentSessionKey() string {
	session := stosession.SessionsUser.GetValidVaultaireSession()
	if session == nil || session.DuckySession == nil {
		return ""
	}
	return string(session.DuckySession.SessionKey)
}
