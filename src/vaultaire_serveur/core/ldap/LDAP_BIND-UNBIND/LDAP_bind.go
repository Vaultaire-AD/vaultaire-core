package ldapbindunbind

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
	"vaultaire/core/auth/passwordpolicy"
	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	dbusers "vaultaire/core/database/db_users"
	gc "vaultaire/core/global/security"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapresponse "vaultaire/core/ldap/LDAP_RESPONSE"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// respond envoie une BindResponse.
//
// L'encodage passe par ldapresponse, qui utilise ber.Encode. La version
// antérieure construisait les octets à la main avec des longueurs sur un seul
// octet : au-delà de 127 caractères de diagnostic, le paquet devenait malformé,
// et le symptôme apparaissait côté client, loin de la cause.
func respond(conn net.Conn, messageID, resultCode int, diagnostic string) {
	if err := ldapresponse.SendResult(conn, messageID, ldapstorage.AppBindResponse,
		resultCode, "", diagnostic); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap bind: "+err.Error())
	}
}

func respondBindSuccess(messageID int, conn net.Conn) {
	respond(conn, messageID, ldapstorage.ResultSuccess, "Bind successful")
}

// respondInvalidCredentials est la réponse d'échec par défaut.
//
// Volontairement identique pour un compte inconnu, un mauvais mot de passe, un
// mot de passe expiré et un refus de droits : distinguer ces cas ferait du bind
// un moyen d'énumérer l'annuaire. Le journal serveur, lui, porte la vraie
// raison.
func respondInvalidCredentials(messageID int, conn net.Conn) {
	respond(conn, messageID, ldapstorage.ResultInvalidCredentials, "Invalid credentials")
}

func respondProtocolError(messageID int, conn net.Conn, diagnostic string) {
	respond(conn, messageID, ldapstorage.ResultProtocolError, diagnostic)
}

// respondAuthMethodNotSupported refuse un mécanisme d'authentification inconnu.
//
// Distinct d'invalidCredentials à dessein : ici l'identité n'est pas en cause,
// c'est la MÉTHODE qui n'est pas gérée. Un client qui reçoit « invalid
// credentials » sur un bind SASL vérifie le mot de passe pendant des heures.
func respondAuthMethodNotSupported(messageID int, conn net.Conn, diagnostic string) {
	respond(conn, messageID, ldapstorage.ResultAuthMethodNotSupported, diagnostic)
}

// respondUnwillingToPerform refuse une opération que le serveur ne veut pas
// exécuter, sans que ce soit une erreur du client.
func respondUnwillingToPerform(messageID int, conn net.Conn, diagnostic string) {
	respond(conn, messageID, ldapstorage.ResultUnwillingToPerform, diagnostic)
}

// refuser répond, réinitialise la session et COMPTE l'échec.
//
// Une seule porte de sortie pour tous les refus : chaque chemin oubliait
// jusqu'ici l'une ou l'autre de ces trois choses, et un refus qui ne compte pas
// ne freine personne.
func refuser(conn net.Conn, messageID int, source, compte string) {
	EnregistrerÉchec(source, compte)
	ldapsessionmanager.ResetBindInfo(conn)
	respondInvalidCredentials(messageID, conn)
}

func HandleBindRequest(op ldapstorage.BindRequest, messageID int, conn net.Conn) {
	user, domain, ou := ldaptools.ExtractUsernameAndDomain(op.Name)
	source := sourceAddr(conn)

	// Limitation AVANT toute lecture de l'annuaire.
	//
	// La placer plus loin laisserait un balayage interroger la base à chaque
	// tentative : le coût pour le serveur resterait le même, seule la réponse
	// changerait.
	if autorisé, reste := BindAutorisé(source, user); !autorisé {
		logs.Write_LogCode("SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"ldap bind: trop de tentatives depuis %s pour %s, encore %s",
			source, user, reste.Round(time.Second)))
		ldapsessionmanager.ResetBindInfo(conn)
		// unwillingToPerform et non invalidCredentials : le refus ne porte pas
		// sur l'identité, et le dire ne renseigne pas sur l'existence du compte.
		respondUnwillingToPerform(messageID, conn, "too many attempts, try again later")
		return
	}
	// Bind avec mot de passe hors TLS.
	//
	// Le port 389 est en clair : un mot de passe y transite en clair. Le réglage
	// est désactivé par défaut pour ne pas couper un parc existant à la mise à
	// jour ; l'activer impose LDAPS sur 636.
	if ldapstorage.RequireTLSForBind && len(op.Authentication) > 0 && !isTLS(conn) {
		logs.Write_LogCode("SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"ldap bind: refusé hors TLS depuis %s", conn.RemoteAddr()))
		ldapsessionmanager.ResetBindInfo(conn)
		respond(conn, messageID, ldapstorage.ResultStrongerAuthRequired,
			"TLS is required for password authentication")
		return
	}
	// Seul LDAPv3 est géré.
	//
	// La version était lue puis ignorée : un bind LDAPv2 était traité comme du v3.
	// Les deux versions n'ont ni le même encodage des DN ni la même sémantique de
	// référence ; accepter silencieusement, c'est promettre un comportement qu'on
	// ne tient pas.
	if op.Version != 3 {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"ldap bind: version %d refusée depuis %s (seul LDAPv3 est géré)",
			op.Version, conn.RemoteAddr()))
		respondProtocolError(messageID, conn, "only LDAPv3 is supported")
		return
	}

	// Le mécanisme d'authentification doit être « simple ».
	//
	// AuthenticationChoice vaut [0] simple ou [3] sasl. Le parseur lisait le
	// contenu brut sans regarder l'étiquette : un bind SASL voyait son DER
	// interprété comme un mot de passe et recevait « invalid credentials », un
	// message qui envoie chercher du côté du mot de passe alors que c'est la
	// méthode qui n'est pas gérée.
	if !op.SimpleAuth {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"ldap bind: mécanisme non simple refusé depuis %s", conn.RemoteAddr()))
		respondAuthMethodNotSupported(messageID, conn, "only simple authentication is supported")
		return
	}

	// Bind « non authentifié » : DN vide AVEC un mot de passe.
	//
	// RFC 4513 §5.1.2 : à refuser par défaut. Le cas vient presque toujours d'une
	// configuration cliente incomplète — un DN oublié — et l'accepter en anonyme
	// laisse l'application croire qu'elle est authentifiée alors qu'elle n'a que
	// les droits d'un inconnu. L'incident se manifeste bien plus tard, sur une
	// lecture vide.
	if op.Name == "" && len(op.Authentication) > 0 {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"ldap bind: bind non authentifié refusé depuis %s (DN vide, mot de passe fourni)",
			conn.RemoteAddr()))
		ldapsessionmanager.ResetBindInfo(conn)
		respondUnwillingToPerform(messageID, conn, "unauthenticated bind is not allowed")
		return
	}

	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: bind request messageID=%d dn=%s user=%s ou=%s domain=%s", messageID, op.Name, user, ou, domain))

	// 🔒 Interdiction d'utiliser le compte système Vaultaire
	if user == "vaultaire" {
		logs.Write_LogCode("WARNING", logs.CodeAuthFailed, fmt.Sprintf("ldap bind: system user rejected from %s", conn.RemoteAddr().String()))
		// ResetBindInfo et non ClearSession : la connexion vit encore.
		//
		// Supprimer la session sous une connexion ouverte laissait le
		// gestionnaire de recherche RootDSE déréférencer un pointeur nil, ce
		// qui arrêtait le serveur entier — sans authentification préalable.
		refuser(conn, messageID, source, user)
		return
	}

	// Selon la RFC 4511, un bind avec un DN vide est une demande d'anonymat.
	if op.Name == "" || op.Anonymous {
		logs.Write_Log("INFO", fmt.Sprintf("ldap: anonymous bind request from %s", conn.RemoteAddr().String()))

		// On marque la session comme "Bound" mais sans utilisateur (Anonymous)
		ldapsessionmanager.SetAnonymousBindInfo(conn)

		// Succès LDAP (code 0)
		respondBindSuccess(messageID, conn)
		return
	}

	// KILL SWITCH — avant toute évaluation du mot de passe.
	//
	// Le refus était jusqu'ici indirect : un compte révoqué n'a plus aucun groupe,
	// donc l'étape permission échouait. Le résultat était le bon, mais APRÈS avoir
	// comparé le mot de passe — le temps de réponse différait donc selon qu'il
	// était correct ou non, ce qui dit à un attaquant qu'il a trouvé le bon mot de
	// passe d'un compte révoqué.
	//
	// Le chemin Ducky coupe avant, et pour cette raison précise. Les deux sont
	// désormais alignés.
	if permission.IsRevoked(user) {
		logs.Write_LogCode("SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"ldap bind: tentative sur le compte révoqué %s depuis %s", user, conn.RemoteAddr()))
		refuser(conn, messageID, source, user)
		return
	}

	// 🔍 Vérification que l'utilisateur existe
	userID, err := dbusers.Get_User_ID_By_Username(database.GetDatabase(), user)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeAuthFailed, fmt.Sprintf("ldap bind: unknown user=%s from %s", user, conn.RemoteAddr().String()))
		refuser(conn, messageID, source, user)
		return
	}

	// 🔐 Vérification du mot de passe
	Hpassword, salt, err := dbusers.Get_User_Password_By_ID(database.GetDatabase(), userID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf("ldap bind: password lookup failed for user=%s: %v", user, err))
		respondProtocolError(messageID, conn, "password lookup failed")
		return
	}

	if !gc.ComparePasswords(string(op.Authentication), salt, Hpassword) {
		logs.Write_LogCode("WARNING", logs.CodeAuthFailed, fmt.Sprintf("ldap bind: invalid password user=%s from %s", user, conn.RemoteAddr().String()))
		refuser(conn, messageID, source, user)
		return
	}

	// ⏳ EXPIRATION DU MOT DE PASSE — après vérification réussie du mot de passe.
	//
	// La réponse reste un invalidCredentials générique, contrairement au chemin
	// Ducky qui, lui, annonce explicitement l'expiration. L'asymétrie n'est pas
	// une inattention :
	//
	//   - LDAP n'a pas de moyen standard de signaler une expiration. Le contrôle
	//     de politique de mot de passe est resté à l'état de brouillon IETF et
	//     n'est pas implémenté de façon homogène par les bibliothèques clientes.
	//     Un code de résultat exotique serait interprété au mieux comme un échec,
	//     au pire comme une erreur de protocole ;
	//   - de l'autre côté d'un bind, il y a une application, pas un humain. Elle
	//     ne peut rien faire de l'information — le changement de mot de passe
	//     passe par l'interface web, qui reste ouverte.
	//
	// Le log serveur, lui, distingue les deux cas : sans cela, un administrateur
	// verrait une vague de « invalid password » le jour où la politique prend
	// effet et chercherait une attaque là où il n'y a qu'une expiration.
	if status, err := passwordpolicy.Check(database.GetDatabase(), user); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf(
			"ldap bind: état d'expiration illisible pour user=%s (%v) — connexion autorisée", user, err))
	} else if status.IsExpired() {
		logs.Write_LogCode("SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"ldap bind: refusé, mot de passe expiré depuis %d jour(s) user=%s from %s",
			-status.DaysUntilExpiry, user, conn.RemoteAddr().String()))
		refuser(conn, messageID, source, user)
		return
	}

	// SECOND FACTEUR — après la vérification du mot de passe.
	//
	// LDAP n'a aucun mécanisme standard de second facteur : on ne peut pas le
	// demander, seulement refuser. Le contrôle vient APRÈS le mot de passe pour la
	// même raison que l'expiration : qui voit ce refus connaît déjà un mot de
	// passe valide, l'information ne lui apprend rien.
	//
	// Désactivé par défaut — voir ldapstorage.RefuseBindWhenMFARequired.
	if ldapstorage.RefuseBindWhenMFARequired {
		if requis, err := dbauthpolicy.IsMFARequired(database.GetDatabase(), user); err != nil {
			// Illisible : on laisse passer plutôt que de bloquer tout le monde sur
			// une panne de base. L'incident est journalisé.
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf(
				"ldap bind: état MFA illisible pour %s (%v) — connexion autorisée", user, err))
		} else if requis {
			logs.Write_LogCode("SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
				"ldap bind: refusé, le second facteur est imposé à %s et LDAP ne sait pas le porter", user))
			refuser(conn, messageID, source, user)
			return
		}
	}

	// ✅ Authentification réussie — maintenant vérification de la permission
	groupIDs, normalizedAction, err := permission.PrePermissionCheck(user, "auth")
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeAuthPermission, fmt.Sprintf("ldap bind: pre-permission failed user=%s: %v", user, err))
		refuser(conn, messageID, source, user)
		return
	}

	ok, msg := permission.CheckPermissionsMultipleDomains(groupIDs, normalizedAction, []string{domain})
	if !ok {
		logs.Write_LogCode("WARNING", logs.CodeAuthPermission, fmt.Sprintf("ldap bind: permission denied user=%s domain=%s reason=%s", user, domain, msg))
		refuser(conn, messageID, source, user)
		return
	}

	EnregistrerSuccès(source, user)
	ldapsessionmanager.SetBindInfo(conn, user, op.Name)
	logs.Write_LogCodeMeta("INFO", logs.CodeNone, fmt.Sprintf("ldap bind: success user=%s domain=%s from %s", user, domain, conn.RemoteAddr().String()), logs.UserMeta(userID))

	// ✅ Réponse LDAP
	respondBindSuccess(messageID, conn)
}

// isTLS dit si la connexion est chiffrée.
//
// Le même gestionnaire sert les deux écoutes : LDAP en clair sur 389 et LDAPS
// sur 636. Seul le type concret de la connexion les distingue.
func isTLS(conn net.Conn) bool {
	_, ok := conn.(*tls.Conn)
	return ok
}

// sourceAddr rend l'adresse du client, sans le port.
//
// Sans ce découpage, chaque connexion aurait une clé différente — le port source
// change à chaque fois — et la limitation par adresse ne compterait jamais
// au-delà de un.
func sourceAddr(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
