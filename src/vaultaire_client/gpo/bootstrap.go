package gpo

import (
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/logs"
	"vaultaire_client/revocation"
	"vaultaire_client/storage"
	"vaultaire_client/storage/stosession"
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
// Appelé au démarrage du service, AVANT que le tunnel ne soit monté : la
// connexion s'établit ensuite, et la session mère ne devient authentifiée que
// quelques secondes plus tard. C'est StartMachineRefresh qui attend cette
// session (voir InitialSessionWait) ; Bootstrap se contente d'armer le tout et
// rend la main immédiatement.
func Bootstrap() {
	Configure(func(trame string) {
		// WaitForVaultaireSession plutôt qu'un simple Get : au moment de l'envoi
		// le tunnel peut être en cours de rétablissement après une coupure, et
		// abandonner la trame ferait perdre un cycle entier.
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			logs.Write_log("WARNING", "GPO: aucune session vaultaire valide, trame non envoyee")
			return
		}
		sendmessage.SendMessage(trame, session.DuckySession)
	}, storage.Computeur_ID)

	StartMachineRefresh(CurrentSessionKey)
	logs.Write_log("INFO", "GPO: transport initialise, cycle machine programme")

	bootstrapRevocation()
}

// bootstrapRevocation arme le transport du kill switch.
//
// Amorcé ici plutôt que dans son propre point d'entrée : les deux mécanismes
// partagent exactement la même couche d'envoi et le même moment de démarrage.
// Les séparer imposerait de dupliquer l'attente de session, avec le risque que
// l'un des deux dérive de l'autre.
//
// La demande d'ordres en attente part dans une goroutine : elle attend la
// session, et Bootstrap doit rendre la main tout de suite pour que le tunnel
// puisse justement s'établir.
func bootstrapRevocation() {
	revocation.Configure(func(trame string) {
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			logs.Write_log("WARNING", "revocation: aucune session vaultaire valide, trame non envoyee")
			return
		}
		sendmessage.SendMessage(trame, session.DuckySession)
	})

	go func() {
		defer logs.Recover("bootstrap GPO")
		// WaitForVaultaireSession bloque jusqu'à ce que le tunnel soit monté et
		// authentifié : c'est exactement le moment où le serveur acceptera une
		// demande 06_04.
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			logs.Write_log("WARNING", "revocation: session indisponible, ordres en attente non reclames")
			return
		}
		revocation.AskPending(string(session.DuckySession.SessionKey))
	}()

	logs.Write_log("INFO", "revocation: transport initialise, ordres en attente reclames")
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
