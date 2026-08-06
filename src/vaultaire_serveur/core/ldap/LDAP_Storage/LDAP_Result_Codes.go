package ldapstorage

// Codes de résultat LDAP — RFC 4511 §4.1.9 et annexe A.
//
// # Pourquoi les nommer plutôt que les écrire en clair
//
// Le paquet employait des littéraux — `0x31`, `0x32`, `1`, `0x40` — dispersés
// dans trois fichiers. Deux conséquences :
//
//   - `0x40` était envoyé comme code de refus d'une ExtendedRequest. 0x40 vaut
//     64, qui n'est pas un code de résultat LDAP. Un client ne peut rien en
//     faire ;
//   - toute recherche en échec renvoyait `operationsError`, que la cause soit un
//     défaut d'authentification, un refus de droits ou une panne interne. Le
//     client ne pouvait pas distinguer « ré-authentifie-toi » de « tu n'as pas
//     le droit », donc ne pouvait pas réagir correctement.
//
// La liste ne contient que ce que le serveur émet réellement.
const (
	ResultSuccess                      = 0
	ResultOperationsError              = 1
	ResultProtocolError                = 2
	ResultTimeLimitExceeded            = 3
	ResultSizeLimitExceeded            = 4
	ResultAuthMethodNotSupported       = 7
	ResultStrongerAuthRequired         = 8
	ResultUnavailableCriticalExtension = 12
	ResultInvalidCredentials           = 49
	ResultInsufficientAccessRights     = 50
	ResultUnwillingToPerform           = 53
)

// Étiquettes d'application des réponses LDAP — RFC 4511 §4.
//
// Le type de réponse doit correspondre à l'opération demandée : un client qui
// reçoit un SearchResultDone pour un ModifyRequest ne fait pas le lien avec sa
// requête et attend jusqu'à expiration.
const (
	AppBindResponse     = 1
	AppSearchResultDone = 5
	AppModifyResponse   = 7
	AppAddResponse      = 9
	AppDelResponse      = 11
	AppModifyDNResponse = 13
	AppCompareResponse  = 15
	AppExtendedResponse = 24
)

// Étiquettes d'application des REQUÊTES, telles qu'elles arrivent sur le fil.
const (
	AppBindRequest     = 0
	AppUnbindRequest   = 2
	AppSearchRequest   = 3
	AppModifyRequest   = 6
	AppAddRequest      = 8
	AppDelRequest      = 10
	AppModifyDNRequest = 12
	AppCompareRequest  = 14
	AppAbandonRequest  = 16
	AppExtendedRequest = 23
)

// ResponseTagFor rend l'étiquette de réponse attendue pour une requête.
//
// Retourne false pour AbandonRequest : la RFC 4511 §4.11 précise qu'elle
// n'appelle AUCUNE réponse. Se taire est ici le comportement correct — c'est le
// seul cas où il l'est.
func ResponseTagFor(requestTag int) (int, bool) {
	switch requestTag {
	case AppBindRequest:
		return AppBindResponse, true
	case AppSearchRequest:
		return AppSearchResultDone, true
	case AppModifyRequest:
		return AppModifyResponse, true
	case AppAddRequest:
		return AppAddResponse, true
	case AppDelRequest:
		return AppDelResponse, true
	case AppModifyDNRequest:
		return AppModifyDNResponse, true
	case AppCompareRequest:
		return AppCompareResponse, true
	case AppExtendedRequest:
		return AppExtendedResponse, true
	case AppAbandonRequest:
		return 0, false
	default:
		// Étiquette inconnue : on répond tout de même, avec le type le plus
		// neutre. Ne rien envoyer laisserait le client attendre.
		return AppExtendedResponse, true
	}
}
