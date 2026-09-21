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

	// MFABypass laisse un compte soumis au second facteur se lier par LDAP avec
	// son SEUL mot de passe (`ldap.mfa_bypass` dans serveur_conf.yaml).
	//
	// DÉSACTIVÉ par défaut : un compte dont le second facteur est posé (ou
	// imposé par un groupe) doit fournir, au bind, son mot de passe SUIVI du
	// code à 6 chiffres — `motdepasse123456`. C'est la convention des annuaires
	// qui portent un second facteur (FreeIPA, par exemple) : LDAP n'a pas de
	// champ pour le code, on l'accole donc au mot de passe.
	//
	// Avant, c'était l'inverse : LDAP contournait le second facteur par défaut,
	// et le seul réglage possible — `RefuseBindWhenMFARequired`, jamais branché
	// sur la configuration — refusait le bind sans offrir de moyen de le passer.
	// La contrainte posée dans l'interface web se contournait donc en passant
	// par LDAP.
	//
	// À activer seulement pour un parc d'applications qui ne savent pas
	// transmettre le code ; préférer, quand c'est possible, des comptes de
	// service hors des groupes soumis au second facteur.
	MFABypass = false
)
