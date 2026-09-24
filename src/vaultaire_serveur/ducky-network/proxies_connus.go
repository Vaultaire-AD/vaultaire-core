package duckynetwork

import (
	"vaultaire/core/proxiesconnus"
)

// Plafond de connexions Ducky pour les PROXIES du cluster.
//
// Le plafond par adresse (20) protège le core d'une source qui ouvrirait des
// milliers de connexions. Mais depuis le relais (TO-DO 38), tous les agents
// qu'un proxy sert arrivent de l'adresse DU PROXY : sans exception, un proxy
// serait coupé au vingt-et-unième agent, en silence.
//
// L'exception ne vaut que pour les adresses d'un proxy ENREGISTRÉ et en ligne.
// La liste est tenue par core/proxiesconnus, commune avec l'écoute LDAP depuis
// le TO-DO 72. Le plafond global (2000) reste, lui, commun à tous.

// PlafondParProxy est le nombre de connexions simultanées admises depuis
// l'adresse d'un proxy.
const PlafondParProxy = 1000

// plafondPourSource est branché sur le limiteur Ducky.
func plafondPourSource(source string) int {
	if proxiesconnus.EstUnProxy(source) {
		return PlafondParProxy
	}
	return 0
}

// demarrerSuiviProxies branche l'exception et lance la relecture commune.
func demarrerSuiviProxies() {
	duckyLimiter.DefinirPlafondPour(plafondPourSource)
	proxiesconnus.Demarrer()
}
