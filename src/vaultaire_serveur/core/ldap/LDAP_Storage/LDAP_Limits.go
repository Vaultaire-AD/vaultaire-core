package ldapstorage

// Bornes et réglages du service LDAP.
//
// Ce sont des variables et non des constantes : elles sont relues depuis
// `serveur_conf.yaml` au démarrage. Les valeurs par défaut sont choisies pour
// ne RIEN casser à la mise à jour — voir chaque commentaire.
//
// Les sept bornes numériques se règlent dans la section `ldap.limites`, sous le
// nom de la variable en minuscules soulignées (`MaxPageSize` →
// `max_page_size`) ; leurs intervalles admis sont dans LDAP_Limits_Reglage.go
// (TO-DO 152). Les trois booléens ont chacun leur clé sous `ldap:`.
//
// Dans le CODE, zéro désactive une borne — les tests s'en servent. Depuis le
// FICHIER, zéro est refusé : aucune protection ne se retire par une saisie.
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

	// MaxPageSize borne la taille d'une page (point 130).
	//
	// Le client propose une taille, le serveur peut en rendre moins : la RFC
	// 2696 le permet, et tous les clients le gèrent — Active Directory plafonne
	// à 1000 depuis toujours. Sans plafond, « une page de dix millions » serait
	// une façon de demander l'annuaire entier en une réponse.
	MaxPageSize = 1000

	// MaxPagedSearchEntries borne ce qu'UNE recherche paginée peut rendre, toutes
	// pages confondues.
	//
	// C'est la borne qui remplace MaxSearchEntries quand le client pagine : la
	// pagination existe précisément pour lire au-delà de dix mille entrées. Elle
	// n'est pas infinie pour autant — le jeu de résultats est tenu en mémoire
	// entre deux pages.
	MaxPagedSearchEntries = 200000

	// MaxPagedEntriesHeld borne le nombre d'entrées tenues en mémoire par TOUTES
	// les recherches paginées en cours.
	//
	// Entre deux pages, le serveur garde ce qui reste à servir. Un client qui
	// ouvre des recherches et ne lit jamais la suite ferait croître cette
	// mémoire sans limite : au-delà de ce plafond, une nouvelle recherche
	// paginée reçoit `busy` et doit être rejouée.
	MaxPagedEntriesHeld = 500000

	// MaxPagedCursorsPerConnection borne les recherches paginées ouvertes en même
	// temps sur une connexion. Au-delà, la plus ancienne est abandonnée.
	MaxPagedCursorsPerConnection = 4

	// PagedCursorTTLSeconds est le temps laissé au client pour demander la page
	// suivante. Passé ce délai, le cookie est refusé et la recherche est à
	// refaire.
	PagedCursorTTLSeconds = 300

	// MaxSearchDuration borne le temps passé à construire une réponse.
	//
	// Le timeLimit du client est honoré s'il est plus court. Zéro désactive.
	MaxSearchDurationSeconds = 30

	// RequireTLSForBind refuse un bind avec mot de passe hors TLS.
	//
	// DÉSACTIVÉ par défaut, délibérément : l'activer d'office couperait tout
	// client configuré sur le port 389 dès le redémarrage du core — JumpServer,
	// FortiGate, Keycloak compris. À activer une fois vérifié que le parc sait
	// faire du LDAPS sur 636 : `ldap.require_tls_for_bind: true` dans
	// serveur_conf.yaml (TO-DO 152 — la variable existait, aucun réglage ne
	// permettait de la poser).
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

	// OneLevelSubtree élargit TOUTE recherche `one` à l'arborescence,
	// sous-domaines compris (`ldap.onelevel_subtree`).
	//
	// « Toute », et non plus « celles dont le conteneur s'appelle users » : le nom
	// du conteneur ne décide plus de rien. Un réglage dont l'effet dépendrait du
	// texte du baseObject reproduirait, en plus explicite, le défaut qu'il corrige.
	//
	// # Ce que le serveur faisait, sans le dire
	//
	// Une recherche de portée `one` sur un conteneur d'utilisateurs était
	// silencieusement promue en `sub`. C'était écrit pour JumpServer, qui cherche
	// en `one` et attend malgré tout les comptes des sous-domaines.
	//
	// L'effet dépassait ce client : un administrateur qui configurait une
	// application en `scope=one` pour restreindre son périmètre obtenait
	// l'arborescence entière. Ce qu'il lisait dans sa configuration ne décrivait
	// plus ce qui lui était servi — et la RFC 4511 §4.5.1 dit exactement le
	// contraire de ce que le serveur faisait.
	//
	// # Faux par défaut, contrairement aux deux réglages ci-dessus
	//
	// MFABypass et RequireTLSForBind sont livrés de façon à ne rien casser à la
	// mise à jour, parce que le défaut « correct » couperait des clients. Ici le
	// choix inverse a été fait : `one` rend enfin ce qu'il dit.
	//
	// Un client qui dépendait de la promotion voit donc moins d'entrées, SANS
	// erreur — le mode de panne le plus désagréable à diagnostiquer. C'est pour
	// cela que chaque recherche élargie par ce réglage est journalisée, et que la
	// documentation nomme JumpServer.
	//
	// Deux façons de le servir : mettre ce réglage à true, ou — mieux —
	// reconfigurer le client en `scope=sub`, qui est la manière juste de demander
	// une arborescence.
	OneLevelSubtree = false
)
