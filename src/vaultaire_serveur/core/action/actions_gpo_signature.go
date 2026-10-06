package action

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	gpomanager "vaultaire/ducky-network/gpo_manager"
	keymanagement "vaultaire/ducky-network/key_management"
)

// Exigence de signature des politiques (TO-DO 52).
//
// # Pourquoi write:server et non write:update:gpo
//
// Ce réglage ne modifie aucune GPO : il change ce que TOUT le parc accepte de
// recevoir. L'accorder à qui écrit une GPO donnerait à un délégué de domaine le
// pouvoir de couper l'application des politiques sur des machines qui ne sont
// pas les siennes — ou, dans l'autre sens, de désarmer une vérification que
// l'exploitation vient d'activer.
//
// C'est un réglage de SERVEUR, au même titre que les durées : `write:server`
// pour l'écrire, `read:log` pour le lire, comme `settings`.
//
// # Portée globale, et pas de « par machine »
//
// L'exigence part dans le manifeste de chaque livraison. La rendre variable par
// machine aurait donné un parc où l'on ne peut plus répondre à « les politiques
// sont-elles vérifiées ici », sinon machine par machine — c'est-à-dire la
// question à laquelle ce réglage existe pour répondre d'un coup.

// EnregistrerActionsSignatureGPO ajoute la lecture et l'écriture de l'exigence.
func EnregistrerActionsSignatureGPO(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "gpo.get_signature_policy",
		CleRBAC:  "read:log",
		Portee:   PorteeGlobale,
		Resume:   "dit si les agents doivent refuser une politique non signée",
		Executer: lireExigenceSignature,
	})
	r.MustEnregistrer(Definition{
		Nom:      "gpo.set_signature_policy",
		CleRBAC:  "write:server",
		Portee:   PorteeGlobale,
		Resume:   "exige, ou non, que les politiques soient signées",
		Executer: definirExigenceSignature,
	})
}

// EtatSignatureGPO décrit la situation, pour la ligne de commande comme pour la
// page web.
type EtatSignatureGPO struct {
	Exigee bool
	// Empreinte de la clé de signature du cluster, ou le motif de son absence.
	//
	// Les deux voyagent ensemble parce que la question se pose ensemble :
	// activer l'exigence sans clé de signature couperait le parc, et c'est
	// précisément ce qu'il faut voir avant d'activer.
	Empreinte    string
	Indisponible string
}

func lireExigenceSignature(_ Appelant, _ Params) (Resultat, error) {
	etat := EtatSignatureGPO{Exigee: gpomanager.SignatureExigee(database.GetDatabase())}

	if emp, err := keymanagement.EmpreinteCleSignature(); err != nil {
		etat.Indisponible = err.Error()
	} else {
		etat.Empreinte = emp
	}

	message := "Les politiques non signées sont ACCEPTÉES par les agents."
	if etat.Exigee {
		message = "Les politiques non signées sont REFUSÉES par les agents."
	}
	return Resultat{Message: message, Donnees: etat}, nil
}

func definirExigenceSignature(a Appelant, p Params) (Resultat, error) {
	valeur := strings.ToLower(strings.TrimSpace(p.Get("exigee")))

	var exigee bool
	switch valeur {
	case "on", "oui", "true", "1", "exiger":
		exigee = true
	case "off", "non", "false", "0", "accepter":
		exigee = false
	default:
		return Resultat{}, fmt.Errorf("valeur attendue : on ou off")
	}

	// La clé est vérifiée AVANT d'exiger, jamais après.
	//
	// Activer l'exigence sans clé de signature ferait refuser toutes les
	// politiques du parc, et le message d'erreur arriverait sur les machines —
	// pas ici. Mieux vaut refuser la commande en disant pourquoi.
	if exigee {
		if _, err := keymanagement.EmpreinteCleSignature(); err != nil {
			return Resultat{}, fmt.Errorf(
				"ce core n'a pas de clé de signature des politiques (%v) : "+
					"exiger une signature couperait l'application des GPO sur tout le parc", err)
		}
	}

	if err := gpomanager.DefinirSignatureExigee(database.GetDatabase(), exigee, a.Username); err != nil {
		return Resultat{}, err
	}

	if exigee {
		return Resultat{
			Message: "Les politiques non signées seront désormais REFUSÉES.\n" +
				"Les machines sans clé de signature ne vérifient rien et continuent " +
				"d'appliquer : déposez la clé du cluster pour que le refus ait lieu.",
			Donnees: true,
		}, nil
	}
	return Resultat{
		Message: "Les politiques non signées sont de nouveau acceptées. " +
			"Une signature PRÉSENTE reste vérifiée.",
		Donnees: false,
	}, nil
}
