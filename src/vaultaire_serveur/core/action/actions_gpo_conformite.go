package action

import (
	"fmt"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
)

// Lecture de la CONFORMITÉ des GPO — `gpo status` et `gpo drift`.
//
// # Le défaut corrigé
//
// La commande exigeait `read:get:gpo` sur « * », donc le droit GLOBAL. Le
// commentaire d'origine le justifiait ainsi : « l'état de conformité couvre
// tout le parc, et un rapport filtré par domaine donnerait une vue partielle
// présentée comme complète — pire qu'un refus ».
//
// Le raisonnement tenait tant qu'aucun filtre ne pouvait le dire. Il ne tient
// plus : le registre annonce désormais le nombre d'entrées masquées dans le
// message. Une vue partielle qui S'ANNONCE partielle vaut mieux qu'un refus
// pur et simple — le délégué voyait auparavant zéro machine, la sienne
// comprise.
//
// # Sur quoi porte le filtre, et pourquoi ce n'est pas la GPO
//
// Une ligne de conformité décrit une MACHINE : son identifiant, la portée
// appliquée, le nombre de modules en échec, la date du dernier rapport. Elle ne
// nomme aucune GPO — le rapport agrège ce que la machine a reçu.
//
// Le filtre porte donc sur les domaines de la MACHINE, avec la clé
// `read:get:gpo`. Ce qui revient à : « je vois la conformité GPO des machines
// de mes domaines ». C'est l'intention — ne lire que ce que ma délégation
// couvre — appliquée à ce que la donnée permet réellement de distinguer.
//
// Si un jour la table portait la GPO d'origine, le filtre pourrait basculer sur
// EntiteGPO sans rien changer d'autre.

// EnregistrerActionsConformiteGPO ajoute les lectures d'état de conformité.
func EnregistrerActionsConformiteGPO(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:             "gpo.list_compliance",
		CleRBAC:         "read:get:gpo",
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
		Filtre:          filtrerConformite,
		Resume:          "état d'application des GPO sur le parc",
		Executer:        listerConformite,
	})

	r.MustEnregistrer(Definition{
		Nom:     "gpo.get_compliance",
		CleRBAC: "read:get:gpo",
		// Portée de la MACHINE visée : la conformité d'un poste se lit avec le
		// droit sur ses domaines, pas sur « * ».
		Portee:          PorteeClient,
		UnDomaineSuffit: true,
		Resume:          "détail de conformité d'une machine",
		Executer:        lireConformiteMachine,
	})
}

func filtrerConformite(donnees any, perim Perimetre) (any, int) {
	rows, ok := donnees.([]dbgpo.ComplianceRow)
	if !ok {
		return donnees, 0
	}
	garde := make([]dbgpo.ComplianceRow, 0, len(rows))
	for _, r := range rows {
		if perim.AutoriseUnDes(perim.DomainesDe(EntiteClient, r.ComputeurID)) {
			garde = append(garde, r)
		}
	}
	return garde, len(rows) - len(garde)
}

// ConformiteMachine rassemble ce qu'il faut pour la fiche d'une machine.
//
// Trois requêtes distinctes en une seule réponse : l'état par portée, les
// modules en échec, les écarts constatés. Les rendre séparément obligerait
// l'appelant à trois contrôles de droits pour une seule question.
type ConformiteMachine struct {
	ComputeurID string
	Etats       []dbgpo.ComplianceRow
	Echecs      []dbgpo.ModuleReportRow
	Ecarts      []dbgpo.DriftRow

	// ModulesIllisibles et EcartsIllisibles disent qu'une des trois lectures a
	// échoué, sans faire échouer l'ensemble.
	//
	// L'état par portée suffit à répondre à « cette machine est-elle
	// conforme ». Refuser toute la fiche parce que le détail des modules
	// manque priverait de la réponse principale.
	ModulesIllisibles string
	EcartsIllisibles  string
}

func listerConformite(_ Appelant, _ Params) (Resultat, error) {
	rows, err := dbgpo.ListCompliance(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture de la conformité : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d scope(s) suivi(s).", len(rows)),
		Donnees: rows,
	}, nil
}

func lireConformiteMachine(_ Appelant, p Params) (Resultat, error) {
	id := p.Get("computeur_id")
	if id == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}
	db := database.GetDatabase()

	etats, err := dbgpo.GetComplianceForClient(db, id)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture de la conformité de %q : %w", id, err)
	}

	out := ConformiteMachine{ComputeurID: id, Etats: etats}

	if modules, err := dbgpo.GetModuleReports(db, id); err != nil {
		out.ModulesIllisibles = err.Error()
	} else {
		for _, m := range modules {
			if m.Result == "failed" {
				out.Echecs = append(out.Echecs, m)
			}
		}
	}

	if ecarts, err := dbgpo.GetDriftForClient(db, id); err != nil {
		out.EcartsIllisibles = err.Error()
	} else {
		out.Ecarts = ecarts
	}

	return Resultat{
		Message: fmt.Sprintf("Machine %s : %d scope(s) suivi(s).", id, len(etats)),
		Donnees: out,
	}, nil
}
