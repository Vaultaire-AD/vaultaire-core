package ldapstorage

// Bornes et réglages du service LDAP.
//
// Ce sont des variables et non des constantes : elles sont destinées à être
// relues depuis la configuration au démarrage. Les valeurs par défaut sont
// choisies pour ne RIEN casser à la mise à jour — voir chaque commentaire.
var (
	// MaxSearchEntries borne le nombre d'entrées qu'une recherche peut rendre,
	// quoi que le client demande.
	//
	// # Pourquoi une borne SERVEUR en plus du sizeLimit du client
	//
	// sizeLimit est une demande du client, et vaut « sans limite » quand il
	// envoie 0 — ce que fait tout client hostile. Une borne serveur est la seule
	// qui tienne face à quelqu'un qui ne coopère pas.
	//
	// 10 000 est large pour un usage normal : les clients qui listent un
	// annuaire paginent, et ceux qui cherchent un compte en veulent un.
	MaxSearchEntries = 10000

	// MaxSearchDuration borne le temps passé à construire une réponse.
	//
	// Le timeLimit du client est honoré s'il est plus court. Zéro désactive.
	MaxSearchDurationSeconds = 30

	// RequireTLSForBind refuse un bind avec mot de passe hors TLS.
	//
	// DÉSACTIVÉ par défaut, délibérément : l'activer d'office couperait tout
	// client configuré sur le port 389 dès le redémarrage du core — JumpServer,
	// FortiGate, Keycloak compris. À activer une fois vérifié que le parc sait
	// faire du LDAPS sur 636.
	RequireTLSForBind = false

	// RefuseBindWhenMFARequired refuse le bind LDAP aux comptes dont un groupe
	// impose le second facteur.
	//
	// DÉSACTIVÉ par défaut, pour la même raison : un compte MFA qui utilise LDAP
	// aujourd'hui perdrait l'accès sans préavis.
	//
	// # Ce que le réglage ferme
	//
	// LDAP n'a aucun mécanisme standard de second facteur. Sans ce contrôle, la
	// contrainte posée dans l'interface web est contournable en se connectant
	// par un autre protocole — la politique s'applique alors sur un chemin et
	// pas sur l'autre.
	RefuseBindWhenMFARequired = false
)
