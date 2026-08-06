package ldapstorage

import "testing"

// TestResponseTagFor couvre le point 2.1.
//
// Une opération non supportée doit recevoir une réponse DU BON TYPE : un client
// qui reçoit un SearchResultDone pour son ModifyRequest ne fait pas le lien avec
// sa requête et attend jusqu'à expiration.
func TestResponseTagFor(t *testing.T) {
	attendu := map[int]int{
		AppBindRequest:     AppBindResponse,
		AppSearchRequest:   AppSearchResultDone,
		AppModifyRequest:   AppModifyResponse,
		AppAddRequest:      AppAddResponse,
		AppDelRequest:      AppDelResponse,
		AppModifyDNRequest: AppModifyDNResponse,
		AppCompareRequest:  AppCompareResponse,
		AppExtendedRequest: AppExtendedResponse,
	}
	for requete, reponse := range attendu {
		got, wants := ResponseTagFor(requete)
		if !wants {
			t.Errorf("ResponseTagFor(%d) : aucune réponse attendue, or il en faut une", requete)
			continue
		}
		if got != reponse {
			t.Errorf("ResponseTagFor(%d) = %d, attendu %d", requete, got, reponse)
		}
	}

	// AbandonRequest est la SEULE opération sans réponse (RFC 4511 §4.11).
	// Se taire est ici le comportement correct, et nulle part ailleurs.
	if _, wants := ResponseTagFor(AppAbandonRequest); wants {
		t.Error("AbandonRequest ne doit appeler aucune réponse")
	}

	// Une étiquette inconnue reçoit tout de même une réponse : ne rien envoyer
	// laisserait le client attendre.
	if _, wants := ResponseTagFor(99); !wants {
		t.Error("une opération inconnue doit tout de même recevoir une réponse")
	}
}

// TestCodesDistincts couvre le point 2.5.
//
// Toutes les recherches en échec renvoyaient operationsError. Un client doit
// pouvoir distinguer « ré-authentifie-toi » de « tu n'as pas le droit » de « le
// serveur est en panne » : les trois appellent des réactions différentes.
func TestCodesDistincts(t *testing.T) {
	codes := map[string]int{
		"operationsError":              ResultOperationsError,
		"protocolError":                ResultProtocolError,
		"authMethodNotSupported":       ResultAuthMethodNotSupported,
		"strongerAuthRequired":         ResultStrongerAuthRequired,
		"unavailableCriticalExtension": ResultUnavailableCriticalExtension,
		"invalidCredentials":           ResultInvalidCredentials,
		"insufficientAccessRights":     ResultInsufficientAccessRights,
		"unwillingToPerform":           ResultUnwillingToPerform,
	}
	vus := map[int]string{}
	for nom, code := range codes {
		if autre, existe := vus[code]; existe {
			t.Errorf("%s et %s partagent le code %d", nom, autre, code)
		}
		vus[code] = nom
	}
	// Valeurs de la RFC 4511 annexe A : elles ne sont pas arbitraires.
	if ResultInvalidCredentials != 49 || ResultInsufficientAccessRights != 50 ||
		ResultUnwillingToPerform != 53 || ResultUnavailableCriticalExtension != 12 {
		t.Error("les codes doivent correspondre à ceux de la RFC 4511")
	}
}
