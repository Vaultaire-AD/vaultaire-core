// Package userauth traite la catégorie 02 : authentification auprès du core.
//
// # Le flux, commun à tous les programmes
//
//	02_01  →  je demande à m'authentifier (identifiant, mot de passe)
//	02_02  ←  défi
//	02_03  →  défi renvoyé
//	02_04  ←  utilisateur authentifié
//	 ou
//	02_11  ←  machine ou service authentifié, décline ton inventaire
//	02_12  →  inventaire
//	02_07  ←  refus
//
// # Deux issues, parce qu'il y a deux natures de session
//
// Un agent qui authentifie une PERSONNE reçoit 02_04, porteur des droits et des
// clés publiques de cette personne. Un programme qui s'authentifie LUI-MÊME —
// agent au démarrage, proxy, interface web — se présente sous le compte
// « vaultaire » et reçoit 02_11.
//
// Le core ne vérifie pas de mot de passe pour « vaultaire », et il n'a pas à le
// faire : l'identité de la machine a déjà été prouvée en 01_02, que seul le
// détenteur de la clé privée pouvait lire. Redemander un secret ici n'ajouterait
// rien qu'un secret de plus à déployer.
package userauth

// Codes de la catégorie.
const (
	AskAuth       = "02_01"
	Challenge     = "02_02"
	CheckAuth     = "02_03"
	AuthSuccess   = "02_04"
	CloseSession  = "02_05"
	AuthFailed    = "02_07"
	AskInfo       = "02_11"
	ServeurInfo   = "02_12"
	ClientInfo    = "02_13"
	AskProxyList  = "02_17"
	ProxyListResp = "02_18"
)

// ServiceAccount est le compte sous lequel un programme s'authentifie lui-même.
//
// Ce n'est pas un compte de secours : c'est le compte que le core reconnaît
// comme « ce n'est pas une personne, c'est un logiciel ». Un service qui
// s'annoncerait sous un autre nom se ferait traiter comme un utilisateur et se
// verrait demander un vrai mot de passe.
const ServiceAccount = "vaultaire"
