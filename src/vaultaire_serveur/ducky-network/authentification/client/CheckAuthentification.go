package client

import (
	"bytes"
	"strconv"
	"strings"
	"time"
	"vaultaire/core/auth/passwordpolicy"
	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/database"
	dbsessions "vaultaire/core/database/db_sessions"
	dbusers "vaultaire/core/database/db_users"
	logs "vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/reglages"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/sessionmgr"
	"vaultaire/ducky-network/trame"
)

// SendAuthRequest processes the authentication request from the client.
// It checks if the username is "vaultaire" and generates a challenge token for it.
// If the username is not "vaultaire", it retrieves the user ID, password hash, and salt from the database.
// It then compares the provided password with the stored hash using the salt.
// If the password matches, it generates a challenge token and stores the authentication data in storage.
// It returns a response string that includes the session integrity key, authID, and challenge token.
// If the username does not exist or the password is incorrect, it returns an error message.
func SendAuthRequest(trames_content storage.Trames_struct_client) string {
	// À ce stade, trames_content.SessionIntegritykey == duckysession.SessionID
	// (Rekey a déjà eu lieu pendant la poignée de main 01_01) : on peut
	// l'utiliser directement comme clé de corrélation dans les logs.
	meta := logs.WithMeta(trames_content.SessionIntegritykey, trames_content.Username)

	if trames_content.Username == "vaultaire" {
		token, alphaCheck := Generate_Challenge(trames_content.ClientSoftwareID)
		nouvelleAuth := storage.Authentification{
			RandomAuth:       token,
			AuthID:           alphaCheck,
			Username:         trames_content.Username,
			ClientSoftwareID: trames_content.ClientSoftwareID,
		}
		storeAuth(nouvelleAuth)
		logs.Write_LogCodeMeta("INFO", logs.CodeNone,
			trames_content.ClientSoftwareID+" try to login by auth server Has User = vaultaire", meta)
		return ("02_02\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + alphaCheck + "\n" + string(token))
	}
	// LIMITATION DES TENTATIVES — avant tout le reste.
	//
	// La SOURCE est le ClientSoftwareID, PAS une adresse IP. Sur ce canal
	// l'adresse est celle du poste — partagée par tous ses utilisateurs — ou
	// celle du proxy, auquel cas tout le parc n'aurait qu'une seule source et le
	// premier balayage venu freinerait tout le monde. L'identifiant de logiciel
	// client désigne le poste lui-même, quel que soit le chemin réseau.
	//
	// Et il n'est pas falsifiable ici : Split_Action refuse toute trame dont le
	// ClientSoftwareID diffère de celui figé à la poignée de main 01_01
	// (clientMatchesSession). Le champ lu est donc déjà le BoundClientSoftwareID
	// de la session. Sans ce contrôle en amont, un attaquant en changerait à
	// chaque essai et repartirait d'un compteur neuf à chaque coup.
	//
	// REFUS IMMÉDIAT, sans attente. Cette trame arrive sur la session MACHINE,
	// partagée, et Split_Action la traite dans la boucle de lecture : y dormir
	// bloquerait le canal entier — GPO, révocation et les autres utilisateurs du
	// poste compris.
	//
	// Le message est le même que celui d'un mot de passe faux : le distinguer
	// dirait à l'attaquant qu'il a touché un compte réel.
	source := trames_content.ClientSoftwareID
	if autorisé, reste := ratelimit.Autorise(trames_content.Username, source); !autorisé {
		logs.Write_LogCodeMeta("SECURITY", logs.CodeAuthLoginDenied,
			trames_content.Username+" : trop de tentatives depuis "+source+
				", encore "+reste.Round(time.Second).String(), meta)
		return Refus(trames_content.SessionIntegritykey, trames_content.Username, MotifIdentifiants)
	}

	// KILL SWITCH — refus avant toute évaluation du mot de passe.
	//
	// Le message renvoyé est le même que pour un mot de passe faux : un compte
	// révoqué ne doit pas se distinguer d'un compte inexistant vu du réseau,
	// sinon le kill switch devient un oracle qui confirme qu'un compte existe
	// et qu'il vient d'être coupé.
	if permission.IsRevoked(trames_content.Username) {
		logs.Write_LogCodeMeta("SECURITY", logs.CodeNone,
			trames_content.Username+" : tentative d'authentification sur un compte révoqué", meta)
		ratelimit.Echec(trames_content.Username, source)
		return Refus(trames_content.SessionIntegritykey, trames_content.Username, MotifIdentifiants)
	}

	user_ID, err := dbusers.Get_User_ID_By_Username(database.GetDatabase(), trames_content.Username)
	if err != nil {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone, trames_content.Username+" try to login but user does not exist", meta)
		ratelimit.Echec(trames_content.Username, source)
		return Refus(trames_content.SessionIntegritykey, trames_content.Username, MotifIdentifiants)
	}
	valide, err := dbusers.VerifierMotDePasse(database.GetDatabase(), user_ID, trames_content.Content)
	if err != nil {
		// Panne de lecture, pas un mauvais mot de passe : ne pas compter d'échec.
		// Le faire ferait dégénérer une indisponibilité de la base en freinage
		// général de tous les comptes qui tentent de se connecter.
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone, trames_content.Username+" try to login but error for get password", meta)
		return Refus(trames_content.SessionIntegritykey, trames_content.Username, MotifIdentifiants)
	}
	if !valide {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone, trames_content.Username+" try to login but password is not correct", meta)
		ratelimit.Echec(trames_content.Username, source)
		return Refus(trames_content.SessionIntegritykey, trames_content.Username, MotifIdentifiants)
	}

	// Mot de passe prouvé : les compteurs repartent de zéro.
	ratelimit.Reussite(trames_content.Username, source)

	// ⏳ EXPIRATION DU MOT DE PASSE — après vérification réussie du mot de passe.
	//
	// Ici le message EST explicite, contrairement au bind LDAP. La raison tient
	// à qui le lit : ce chemin porte PAM, donc un humain devant une invite de
	// connexion. Lui répondre « Wrong login Data » alors qu'il vient de taper le
	// bon mot de passe l'enverrait le retaper, puis appeler le support.
	//
	// Aucun oracle n'est créé pour autant. Le contrôle est placé APRÈS la
	// comparaison du mot de passe : qui voit ce message connaît déjà un mot de
	// passe valide pour ce compte. L'information « il est expiré » ne lui apporte
	// rien qu'il n'ait déjà. C'est exactement l'inverse du kill switch, dont le
	// refus est muet parce qu'il précède, lui, toute vérification.
	//
	// Aucune trame nouvelle : 02_07 est déjà le refus d'authentification porteur
	// d'un message libre.
	if status, err := passwordpolicy.Check(database.GetDatabase(), trames_content.Username); err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
			trames_content.Username+" : état d'expiration illisible ("+err.Error()+") — connexion autorisée", meta)
	} else if status.IsExpired() {
		logs.Write_LogCodeMeta("SECURITY", logs.CodeNone,
			trames_content.Username+" : refus, mot de passe expiré depuis "+
				strconv.Itoa(-status.DaysUntilExpiry)+" jour(s)", meta)
		return Refus(trames_content.SessionIntegritykey, trames_content.Username, MotifMotDePasseExpire)
	}

	token, alphaCheck := Generate_Challenge(trames_content.ClientSoftwareID)
	if alphaCheck == "no" {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, trames_content.Username+" try to login but error for generate challenge", meta)
		return Refus(trames_content.SessionIntegritykey, trames_content.Username, MotifDefiImpossible)
	}
	nouvelleAuth := storage.Authentification{
		RandomAuth:       token,
		AuthID:           alphaCheck,
		Username:         trames_content.Username,
		ClientSoftwareID: trames_content.ClientSoftwareID,
	}
	storeAuth(nouvelleAuth)
	logs.Write_LogCodeMeta("INFO", logs.CodeNone, nouvelleAuth.Username+" try to login", meta)
	return ("02_02\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + alphaCheck + "\n" + string(token))
}

// CheckAuth verifies the authentication challenge sent by the client.
// It reconstructs the message content from the received data, retrieves the random authentication data and username using the authID,
// and deletes the authentication entry from storage.
// If the username is "vaultaire", it adds the server to the online list and returns a success message.
// If the username is not "vaultaire", it compares the provided challenge with the stored random authentication data.
// If they match, it generates a session key, checks if the user can log in, and adds a login entry to the database.
// If the user can log in, it sends the GPO to the client and returns a success message with the session key.
// If the challenge does not match, it logs a warning and returns an error message indicating that the authentication failed.
func CheckAuth(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	meta := logs.WithMeta(duckysession.SessionID, trames_content.Username)

	message_reconstruction := strings.Split(trames_content.Content, "\n")
	message_content := storage.Authentification_Challenge_server{
		AuthID:    message_reconstruction[0],
		Challenge: strings.Join(message_reconstruction[1:], "\n"),
	}
	randomAuth, username := GetRandomAuthByAuthID(message_content.AuthID)

	// Garde-fou sur le cas vide.
	//
	// Un AuthID inconnu fait renvoyer (nil, "") par le store. Plus bas, la
	// comparaison est bytes.Equal(randomAuth, returnchack) : en Go,
	// bytes.Equal(nil, []byte("")) vaut true. Une trame 02_03 dont le contenu
	// est vide franchissait donc la comparaison du challenge avec un username
	// vide. Elle était arrêtée juste après par DidUserCanLogin — aucun
	// utilisateur ne porte le nom vide — mais elle l'était par accident, pas
	// par décision. On refuse explicitement.
	if message_content.AuthID == "" || len(randomAuth) == 0 || username == "" {
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone,
			"Challenge d'authentification inconnu ou vide, trame 02_03 rejetée", meta)
		// Le compte du défi est inconnu, par définition : on rend celui que la
		// trame annonce.
		return Refus(trames_content.SessionIntegritykey, trames_content.Username, MotifNonAuthentifie)
	}

	if username == "vaultaire" {
		sessionmgr.Sessions.SetIdentity(duckysession.SessionID, username, trames_content.ClientSoftwareID)
		sessionmgr.Sessions.SetStatus(duckysession.SessionID, sessionmgr.SessionAuthenticated)
		addOnlineServerToTable(duckysession.SessionID, username, trames_content.ClientSoftwareID)
		db := database.GetDatabase()
		userID, _ := dbusers.Get_User_ID_By_Username(db, username)
		dbsessions.AddLoginEntry(db, userID, []byte(trames_content.SessionIntegritykey), trames_content.ClientSoftwareID)
		logs.Write_LogCodeMeta("INFO", logs.CodeNone, trames_content.ClientSoftwareID+" is online and enter in the system", meta)
		// La cadence de vérification en ligne part dès ce premier 02_11 : un
		// agent qui vient de se connecter règle son délai de fermeture avant
		// d'avoir attendu un seul battement (TO-DO 110).
		// Les capacités du core aussi : c'est à CETTE trame, la première de la
		// connexion, qu'un proxy apprend s'il peut émettre sa 04_18 (TO-DO 141).
		return ("02_11\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + username + "\nclient_giveinformation\n" +
			reglages.LigneCadenceEnLigne() + "\n" + trame.LigneCapacites())

	}

	returnchack := []byte(message_content.Challenge)
	if bytes.Equal(randomAuth, returnchack) {
		db := database.GetDatabase()
		userID, _ := dbusers.Get_User_ID_By_Username(db, username)

		can, err := dbusers.DidUserCanLogin(database.GetDatabase(), username, trames_content.ClientSoftwareID)
		if err != nil {
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone, username+" try to login but error for get user can login", meta)
			// Cette trame était composée SANS sa ligne de destination : tous ses
			// champs arrivaient décalés d'un rang (TO-DO 159).
			return Refus(trames_content.SessionIntegritykey, username, MotifErreurInterne)
		}
		if can {
			// L'acceptation est COMPOSÉE avant d'être actée (TO-DO 138).
			//
			// La 02_04 porte toutes les clés SSH du compte. Un compte garni
			// avant les bornes de la 2.2 peut dépasser ce qu'une trame Ducky
			// transporte : elle n'était alors pas émise, le poste attendait
			// une réponse qui ne venait pas, et le core n'écrivait qu'une
			// taille — sans nom de compte, donc sans rien à corriger. Pendant
			// ce temps la session était déjà inscrite comme authentifiée.
			//
			// On regarde donc la taille AVANT d'inscrire quoi que ce soit, et un
			// compte qui ne tient pas reçoit un refus qui dit pourquoi.
			admin, _ := dbusers.IsUserAdmin(database.GetDatabase(), username, trames_content.ClientSoftwareID)
			userpukey, errCles := dbusers.GetUserKeys(userID)
			if errCles != nil {
				logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
					"Erreur lors de la récupération de la clé publique de l'utilisateur "+username+" : "+errCles.Error(), meta)
			}
			acceptation, tient := ComposerAcceptation(trames_content.SessionIntegritykey, username, admin, userpukey, errCles)
			if !tient {
				logs.Write_LogCodeMeta("ERROR", logs.CodeNone, MessageClesTropLourdes(username, len(userpukey), len(acceptation)), meta)
				// Un REFUS, pas une liste tronquée : retirer des clés pour faire
				// tenir la trame serait retirer un accès sans que personne
				// l'ait décidé — et lequel ?
				return RefusPourPoids(trames_content.SessionIntegritykey, username)
			}

			dbsessions.AddLoginEntry(db, userID, []byte(trames_content.SessionIntegritykey), trames_content.ClientSoftwareID)
			sessionmgr.Sessions.SetIdentity(duckysession.SessionID, username, trames_content.ClientSoftwareID)
			sessionmgr.Sessions.SetStatus(duckysession.SessionID, sessionmgr.SessionAuthenticated)
			logs.Write_LogCodeMeta("INFO", logs.CodeNone, username+" login with succes with clientsoftware "+trames_content.ClientSoftwareID, meta)
			if admin {
				logs.Write_LogCodeMeta("INFO", logs.CodeNone, username+" is admin for the client : "+trames_content.ClientSoftwareID, meta)
			}
			return acceptation

		} else {
			return Refus(trames_content.SessionIntegritykey, username, MotifMachineInterdite)
		}

	} else {
		// Challenge faux : la seconde étape de l'authentification échoue. Comptée
		// comme le premier échec venu — sans cela, un attaquant qui obtient une
		// 02_02 pourrait pilonner la vérification du challenge sans jamais
		// repasser par le mot de passe, donc sans jamais être freiné.
		logs.Write_LogCodeMeta("WARNING", logs.CodeNone, username+" Does not have the permission for login to "+trames_content.ClientSoftwareID, meta)
		ratelimit.Echec(username, trames_content.ClientSoftwareID)
		return Refus(trames_content.SessionIntegritykey, username, MotifNonAuthentifie)

	}
}
