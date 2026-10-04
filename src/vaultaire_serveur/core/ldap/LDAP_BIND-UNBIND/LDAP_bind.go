package ldapbindunbind

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
	"vaultaire/core/auth/passwordpolicy"
	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/database"
	dbusers "vaultaire/core/database/db_users"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
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
		ldapjournal.Ecrire(conn, "ERROR", logs.CodeLDAPListen, "bind: "+err.Error())
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
	ratelimit.Echec(compte, source)
	ldapsessionmanager.ResetBindInfo(conn)
	respondInvalidCredentials(messageID, conn)
}

// Les quatre formes d'un bind simple, selon ce qui est fourni.
type formeDeBind int

const (
	// bindAnonyme : DN vide ET mot de passe vide — RFC 4513 §5.1.1.
	bindAnonyme formeDeBind = iota
	// bindNonAuthentifie : DN fourni, mot de passe VIDE — RFC 4513 §5.1.2,
	// « unauthenticated bind ». À refuser par défaut.
	bindNonAuthentifie
	// bindSansNom : DN vide, mot de passe fourni. Hors RFC ; refusé.
	bindSansNom
	// bindNomEtMotDePasse : les deux fournis — RFC 4513 §5.1.3. Le seul qui
	// identifie quelqu'un.
	bindNomEtMotDePasse
)

// natureDuBind classe un bind simple par ce qu'il fournit, et par rien d'autre.
//
// Une fonction à part pour que la table des quatre cas soit écrite UNE fois et
// éprouvée telle quelle : le défaut du TO-DO 128 était un commentaire qui
// nommait un cas et un code qui en traitait un autre.
func natureDuBind(op ldapstorage.BindRequest) formeDeBind {
	nom := op.Name != ""
	motDePasse := len(op.Authentication) > 0
	switch {
	case nom && motDePasse:
		return bindNomEtMotDePasse
	case nom:
		return bindNonAuthentifie
	case motDePasse:
		return bindSansNom
	default:
		return bindAnonyme
	}
}

func HandleBindRequest(op ldapstorage.BindRequest, messageID int, conn net.Conn) {
	user, domain, ou := ldaptools.ExtractUsernameAndDomain(op.Name)
	source := ratelimit.SourceConn(conn)

	// Limitation AVANT toute lecture de l'annuaire.
	//
	// La placer plus loin laisserait un balayage interroger la base à chaque
	// tentative : le coût pour le serveur resterait le même, seule la réponse
	// changerait.
	//
	// Les compteurs sont ceux de core/auth/ratelimit, PARTAGÉS avec le portail
	// web et le canal Ducky. Le compte de cette limitation vivait auparavant ici
	// seul : un attaquant freiné sur le bind repartait de zéro sur le portail.
	if autorisé, reste := ratelimit.Autorise(user, source); !autorisé {
		ldapjournal.Ecrire(conn, "SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"bind: trop de tentatives depuis %s pour %s, encore %s",
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
		ldapjournal.Ecrire(conn, "SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"bind: refusé hors TLS depuis %s", conn.RemoteAddr()))
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
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
			"bind: version %d refusée depuis %s (seul LDAPv3 est géré)",
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
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
			"bind: mécanisme non simple refusé depuis %s", conn.RemoteAddr()))
		respondAuthMethodNotSupported(messageID, conn, "only simple authentication is supported")
		return
	}

	// Les deux formes de bind SANS identité prouvée — RFC 4513 §5.1.
	//
	// Le classement est fait par natureDuBind, et refusé ICI : avant toute
	// lecture de la base, et sans compter d'échec. Ce n'est pas une tentative
	// d'identification ratée, c'est une requête que le serveur ne veut pas
	// servir ; un client mal configuré qui la rejoue en boucle doit recevoir un
	// refus de protocole immédiat, pas épuiser le compteur d'échecs du compte
	// qu'il nomme — compteur partagé avec le portail.
	switch natureDuBind(op) {
	case bindNonAuthentifie:
		// §5.1.2 : DN fourni, mot de passe de longueur nulle.
		//
		// Ce cas descendait jusqu'à la vérification du mot de passe avec une
		// chaîne vide. Il n'était pas exploitable — aucune empreinte ne correspond
		// à une chaîne vide — mais le commentaire qui se trouvait ici citait ce
		// paragraphe pour le cas d'à côté, et laissait croire celui-ci couvert
		// (TO-DO 128).
		//
		// Pourquoi la RFC demande de le refuser : des applications s'authentifient
		// en tentant un bind avec ce que l'utilisateur a saisi. Si un mot de passe
		// VIDE réussit — fût-ce en anonyme —, l'application conclut que
		// l'utilisateur est authentifié sous le DN qu'elle a envoyé.
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
			"bind: bind non authentifié refusé depuis %s (DN fourni, mot de passe vide)",
			conn.RemoteAddr()))
		ldapsessionmanager.ResetBindInfo(conn)
		respondUnwillingToPerform(messageID, conn, "unauthenticated bind is not allowed")
		return
	case bindSansNom:
		// DN vide AVEC un mot de passe : aucune des formes de la RFC. Ni
		// l'anonymat de §5.1.1, qui veut les deux vides, ni un bind nom / mot de
		// passe, qui veut les deux fournis. Le cas vient d'une configuration
		// cliente incomplète — un DN oublié — et l'accepter en anonyme laisserait
		// l'application croire qu'elle est authentifiée alors qu'elle n'a que les
		// droits d'un inconnu. L'incident se manifesterait bien plus tard, sur une
		// lecture vide.
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
			"bind: bind sans nom refusé depuis %s (DN vide, mot de passe fourni)",
			conn.RemoteAddr()))
		ldapsessionmanager.ResetBindInfo(conn)
		respondUnwillingToPerform(messageID, conn, "a password was sent without a bind DN")
		return
	}

	// Le découpage du DN, en déroulé : la demande elle-même est sur la ligne de
	// l'opération. Jamais le mot de passe — voir ldapjournal.Decrire.
	ldapjournal.Trace(conn, "bind : dn=%q découpé en compte=%q ou=%q domaine=%q", op.Name, user, ou, domain)

	// 🔒 Interdiction d'utiliser le compte système Vaultaire
	if user == "vaultaire" {
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeAuthFailed, fmt.Sprintf("bind: system user rejected from %s", conn.RemoteAddr().String()))
		// ResetBindInfo et non ClearSession : la connexion vit encore.
		//
		// Supprimer la session sous une connexion ouverte laissait le
		// gestionnaire de recherche RootDSE déréférencer un pointeur nil, ce
		// qui arrêtait le serveur entier — sans authentification préalable.
		refuser(conn, messageID, source, user)
		return
	}

	// L'anonymat — RFC 4513 §5.1.1 : DN vide ET mot de passe vide, les deux.
	//
	// La condition était « DN vide, ou drapeau d'anonymat » : exacte seulement
	// parce que le DN vide avec mot de passe venait d'être refusé au-dessus. Elle
	// dit maintenant ce qu'elle veut dire, sans dépendre de l'ordre des blocs.
	if natureDuBind(op) == bindAnonyme {
		ldapjournal.Ecrire(conn, "INFO", logs.CodeNone, fmt.Sprintf("bind: anonymous bind request from %s", conn.RemoteAddr().String()))

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
		ldapjournal.Ecrire(conn, "SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"bind: tentative sur le compte révoqué %s depuis %s", user, conn.RemoteAddr()))
		refuser(conn, messageID, source, user)
		return
	}

	// 🔍 Vérification que l'utilisateur existe
	userID, err := dbusers.Get_User_ID_By_Username(database.GetDatabase(), user)
	if err != nil {
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeAuthFailed, fmt.Sprintf("bind: unknown user=%s from %s", user, conn.RemoteAddr().String()))
		refuser(conn, messageID, source, user)
		return
	}

	// UN COMPTE SANS AUCUN GROUPE NE SE LIE PAS — point 122.
	//
	// C'était déjà le cas, mais par accident : sans groupe il n'y a aucune
	// permission à consulter, donc la vérification de droits, tout en bas,
	// échouait. Le refus était juste et son motif illisible — le journal disait
	// « permission denied » et envoyait chercher une permission manquante là où
	// c'est l'appartenance qui manque.
	//
	// # Pourquoi ici, et pas plus haut ni plus bas
	//
	// APRÈS la vérification d'existence du compte, et c'est essentiel. Placé
	// avant, ce contrôle attrapait aussi les comptes INEXISTANTS — une recherche
	// de groupes sur un nom inconnu rend une liste vide, pas une erreur. Ils
	// sortaient alors par ce chemin, qui ne compte pas d'échec : la limitation de
	// débit ne montait plus sur un balayage de noms inventés, et un attaquant
	// pouvait distinguer un compte réel d'un compte imaginaire en observant quel
	// nom finit par être freiné. Un refus qui ne compte pas doit rester réservé à
	// un compte qui existe.
	//
	// AVANT la comparaison du mot de passe, pour la raison exacte du KILL SWITCH
	// plus haut : un refus prononcé après elle fait dépendre le temps de réponse
	// de la justesse du mot de passe, ce qui dit à un attaquant qu'il a trouvé
	// celui d'un compte qui ne sert à rien. Un compte détaché de son dernier
	// groupe n'est pas marqué révoqué : il ne passe pas par le kill switch.
	//
	// # Pourquoi sans compter d'échec
	//
	// `refuser` alimente des compteurs PARTAGÉS avec le portail web. Un client
	// dont la configuration pointe un compte sans groupe rejoue sa liaison en
	// boucle : le compter bannirait ce compte du portail, c'est-à-dire du seul
	// endroit où on peut le rattacher à un groupe. Ce n'est pas un échec
	// d'identification mais un état de configuration — et la limitation posée en
	// tête de fonction, elle, s'applique toujours.
	//
	// Le compte reste visible et corrigeable depuis le portail et `vlt`. Ce qui
	// disparaît est sa présence dans l'annuaire, pas le compte.
	groupIDsDuCompte, err := permission.GetGroupIDsForUser(user)
	if err != nil {
		ldapjournal.Ecrire(conn, "ERROR", logs.CodeDBQuery, fmt.Sprintf(
			"bind: groupes de %s illisibles (%v) — refusé", user, err))
		refuser(conn, messageID, source, user)
		return
	}
	if len(groupIDsDuCompte) == 0 {
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeAuthPermission, fmt.Sprintf(
			"bind: refusé, le compte %s n'appartient à aucun groupe — il n'a aucun "+
				"droit sur le parc (rattachez-le depuis le portail ou « vlt »)", user))
		ldapsessionmanager.ResetBindInfo(conn)
		respondInvalidCredentials(messageID, conn)
		return
	}

	// 🔑 SECOND FACTEUR — ce que le bind doit exiger, AVANT le mot de passe.
	//
	// Un compte soumis au second facteur fournit `motdepasse` suivi du code à
	// six chiffres : il faut donc savoir où couper avant de vérifier quoi que
	// ce soit. Voir ldapstorage.MFABypass.
	//
	// Un état illisible REFUSE : laisser passer « dans le doute » rouvrirait le
	// contournement que ce contrôle ferme, sur une simple panne de lecture.
	motDePasse := string(op.Authentication)
	code := ""
	mfa, err := lireEtatMFA(user)
	if err != nil {
		ldapjournal.Ecrire(conn, "ERROR", logs.CodeDBQuery, fmt.Sprintf(
			"bind: état du second facteur illisible pour %s (%v) — refusé", user, err))
		refuser(conn, messageID, source, user)
		return
	}
	if mfa.Lie && !ldapstorage.MFABypass {
		if mfa.Secret == "" {
			// Imposé par un groupe, jamais enrôlé : aucun code ne peut être
			// valide. Le compte doit enrôler sur le portail.
			ldapjournal.Ecrire(conn, "SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
				"bind: refusé, second facteur imposé à %s mais non enrôlé", user))
			refuser(conn, messageID, source, user)
			return
		}
		mdp, c, ok := separerCode(motDePasse)
		if !ok {
			ldapjournal.Ecrire(conn, "WARNING", logs.CodeAuthFailed, fmt.Sprintf(
				"bind: refusé, %s est soumis au second facteur et le mot de passe ne se termine pas par un code à 6 chiffres", user))
			refuser(conn, messageID, source, user)
			return
		}
		motDePasse, code = mdp, c
	}

	// 🔐 Vérification du mot de passe
	//
	// VerifierMotDePasse réencode au passage l'empreinte des comptes restés en
	// SHA-256. Le bind LDAP compte parmi les portes qui doivent le faire : sur
	// une installation où l'annuaire ne sert qu'à des applications, c'est peut-être
	// la SEULE par laquelle un compte donné se connecte jamais.
	valide, err := dbusers.VerifierMotDePasse(database.GetDatabase(), userID, motDePasse)
	if err != nil {
		ldapjournal.Ecrire(conn, "ERROR", logs.CodeDBQuery, fmt.Sprintf("bind: password lookup failed for user=%s: %v", user, err))
		respondProtocolError(messageID, conn, "password lookup failed")
		return
	}

	if !valide {
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeAuthFailed, fmt.Sprintf("bind: invalid password user=%s from %s", user, conn.RemoteAddr().String()))
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
		ldapjournal.Ecrire(conn, "ERROR", logs.CodeDBQuery, fmt.Sprintf(
			"bind: état d'expiration illisible pour user=%s (%v) — connexion autorisée", user, err))
	} else if status.IsExpired() {
		ldapjournal.Ecrire(conn, "SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
			"bind: refusé, mot de passe expiré depuis %d jour(s) user=%s from %s",
			-status.DaysUntilExpiry, user, conn.RemoteAddr().String()))
		refuser(conn, messageID, source, user)
		return
	}

	// SECOND FACTEUR — le code, APRÈS le mot de passe : qui voit ce refus
	// connaît déjà un mot de passe valide, l'information ne lui apprend rien.
	if code != "" {
		if raison := verifierCode(user, mfa.Secret, code); raison != "" {
			ldapjournal.Ecrire(conn, "SECURITY", logs.CodeAuthFailed, fmt.Sprintf(
				"bind: refusé pour %s depuis %s : %s", user, conn.RemoteAddr().String(), raison))
			refuser(conn, messageID, source, user)
			return
		}
	} else if mfa.Lie {
		// ldap.mfa_bypass : le bind passe sans code. Journalisé pour que le
		// contournement reste visible à l'audit.
		ldapjournal.Ecrire(conn, "SECURITY", logs.CodeNone, fmt.Sprintf(
			"bind: second facteur de %s contourné (ldap.mfa_bypass activé)", user))
	}

	// ✅ Authentification réussie — maintenant vérification de la permission
	//
	// Les groupes ont déjà été lus plus haut, pour le contrôle du point 122 :
	// PrePermissionCheck les relirait à l'identique. Seule la validation du nom
	// d'action reste à faire.
	normalizedAction, actionValide := permission.IsValidAction("auth")
	if !actionValide {
		ldapjournal.Ecrire(conn, "ERROR", logs.CodeAuthPermission,
			"bind: l'action « auth » n'est pas reconnue du registre")
		refuser(conn, messageID, source, user)
		return
	}

	ok, msg := permission.CheckPermissionsMultipleDomains(groupIDsDuCompte, normalizedAction, []string{domain})
	if !ok {
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeAuthPermission, fmt.Sprintf("bind: permission denied user=%s domain=%s reason=%s", user, domain, msg))
		refuser(conn, messageID, source, user)
		return
	}

	ratelimit.Reussite(user, source)
	ldapsessionmanager.SetBindInfo(conn, user, op.Name)
	// Le protocole figure sur la ligne : « qui s'est lié, et par quel canal »
	// est la question qu'on pose à cette ligne-là, et LDAP en clair ne se lisait
	// pas différemment de LDAPS.
	ldapjournal.EcrireMeta(conn, "INFO", logs.CodeNone, fmt.Sprintf(
		"bind: success user=%s domain=%s from %s (%s)",
		user, domain, conn.RemoteAddr().String(), canal(conn)), logs.UserMeta(userID))

	// ✅ Réponse LDAP
	respondBindSuccess(messageID, conn)
}

// canal rend « LDAPS » ou « LDAP » pour le journal.
func canal(conn net.Conn) string {
	if isTLS(conn) {
		return "LDAPS"
	}
	return "LDAP"
}

// isTLS dit si la connexion est chiffrée.
//
// Le même gestionnaire sert les deux écoutes : LDAP en clair sur 389 et LDAPS
// sur 636. Seul le type concret de la connexion les distingue.
func isTLS(conn net.Conn) bool {
	_, ok := conn.(*tls.Conn)
	return ok
}
