package action

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	sshclient "vaultaire/ducky-network/authentification/ssh"
)

// L'exigence de second facteur sur le chemin Ducky — TO-DO 95.
//
// # Pourquoi ce réglage n'est pas une clé RBAC de domaine
//
// Il décide de ce que TOUT LE PARC exige à l'ouverture de session. Un délégué
// qui administre un domaine n'a aucune raison de pouvoir l'activer — ni de
// pouvoir le retirer, ce qui est le vrai risque : couper le second facteur de
// tout le monde depuis une délégation de périmètre.
//
// D'où les mêmes clés que la signature des GPO (point 52), et pour le même
// raisonnement : `write:server` pour écrire, `read:log` pour lire, portée
// globale.

// EtatMFADucky décrit le réglage et ce qu'il implique.
type EtatMFADucky struct {
	Exigee bool

	// ComptesEnroles compte les comptes qui ont réellement un second facteur.
	// Affiché AVANT activation : c'est le chiffre qui dit si l'on s'apprête à
	// verrouiller un annuaire qui n'est pas prêt.
	ComptesEnroles int

	// Indisponible porte la raison quand ce compte n'a pas pu être fait.
	Indisponible string
}

// EnregistrerActionsMFADucky ajoute la paire lecture/écriture.
func EnregistrerActionsMFADucky(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "mfa.get_ducky_policy",
		CleRBAC:  "read:log",
		Portee:   PorteeGlobale,
		Resume:   "dit si un agent doit obligatoirement envoyer un code de second facteur",
		Executer: lireExigenceMFADucky,
	})
	r.MustEnregistrer(Definition{
		Nom:      "mfa.set_ducky_policy",
		CleRBAC:  "write:server",
		Portee:   PorteeGlobale,
		Resume:   "exige, ou non, un code de second facteur à l'ouverture de session",
		Executer: definirExigenceMFADucky,
	})
}

func lireExigenceMFADucky(_ Appelant, _ Params) (Resultat, error) {
	db := database.GetDatabase()
	etat := EtatMFADucky{Exigee: sshclient.MFADuckyExigee(db)}

	n, err := dbauthpolicy.CompterComptesAvecMFA(db)
	if err != nil {
		etat.Indisponible = err.Error()
	} else {
		etat.ComptesEnroles = n
	}

	message := "Les agents peuvent ouvrir une session sans envoyer de code " +
		"(migration en cours)."
	if etat.Exigee {
		message = "Tout agent doit envoyer un code de second facteur — « " +
			sshclient.CodeSansSecondFacteur + " » pour un compte qui n'en a pas."
	}
	return Resultat{Message: message, Donnees: etat}, nil
}

func definirExigenceMFADucky(a Appelant, p Params) (Resultat, error) {
	brut := strings.ToLower(strings.TrimSpace(p.Get("required")))
	var exigee bool
	switch brut {
	case "on", "oui", "true", "1", "exiger":
		exigee = true
	case "off", "non", "false", "0", "laisser":
		exigee = false
	default:
		return Resultat{}, fmt.Errorf(
			"valeur attendue : on (exiger) ou off (laisser passer les agents anciens)")
	}

	db := database.GetDatabase()

	// LE GARDE-FOU, avant l'écriture.
	//
	// Activer l'exigence sur un parc dont les agents n'envoient pas encore de
	// code coupe l'accès à TOUTES les machines, d'un coup, y compris celle depuis
	// laquelle on administre. Le message d'erreur arriverait alors sur les
	// postes, pas devant celui qui tape — c'est-à-dire trop tard.
	//
	// On ne peut pas savoir d'ici quelle version d'agent tourne sur chaque
	// poste. Ce qu'on peut faire, et qui suffit à écarter la faute la plus
	// probable, est de le DIRE, et de refuser le geste le plus manifestement
	// prématuré : activer alors que personne n'a enrôlé de second facteur.
	if exigee {
		n, err := dbauthpolicy.CompterComptesAvecMFA(db)
		if err != nil {
			return Resultat{}, fmt.Errorf(
				"impossible de compter les comptes enrôlés (%w) — "+
					"l'exigence n'est pas activée sur une base qu'on ne sait pas lire", err)
		}
		if n == 0 {
			return Resultat{}, fmt.Errorf(
				"aucun compte n'a enrôlé de second facteur.\n"+
					"  L'activer maintenant n'apporterait rien — tout le monde taperait « %s » —\n"+
					"  et couperait l'accès de toute machine dont l'agent est trop ancien pour\n"+
					"  envoyer une ligne « %s ».\n"+
					"  Faites enrôler au moins un compte sur /profil/mfa, puis réessayez",
				sshclient.CodeSansSecondFacteur, sshclient.PrefixeOTP)
		}
	}

	if err := sshclient.DefinirMFADuckyExigee(db, exigee, a.Username); err != nil {
		return Resultat{}, fmt.Errorf("enregistrement du réglage : %w", err)
	}

	if !exigee {
		return Resultat{Message: "Exigence retirée : un agent qui n'envoie pas de code " +
			"est de nouveau accepté. Les comptes qui ONT un second facteur restent " +
			"tenus de le fournir."}, nil
	}
	return Resultat{Message: "Exigence activée. Tout agent doit désormais envoyer un code " +
		"à l'ouverture de session — « " + sshclient.CodeSansSecondFacteur +
		" » pour un compte qui n'en a pas. Une machine dont l'agent est trop ancien " +
		"ne pourra plus ouvrir de session : « vlt mfa ducky off » retire l'exigence."}, nil
}
