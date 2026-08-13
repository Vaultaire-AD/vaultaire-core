package webserveur

import (
	"net/http"
	"strings"
	"time"

	act "vaultaire/core/action"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Page de conformité des GPO.
//
// # Ce que cette page N'A PAS à faire
//
// Ni trier, ni décider d'un état, ni composer un libellé. Tout cela vit dans
// `db_gpo` — `TrierConformite`, `Fraicheur`, `EtatConformite`, `ModulesAppliques`,
// `ResumerParc` — et la ligne de commande emprunte exactement les mêmes
// fonctions.
//
// C'était la condition posée à cette page : deux vues qui recalculeraient
// séparément « en retard » ou « non vérifié » finiraient par ne plus dire la
// même chose, et personne ne remarquerait l'écart tant qu'il serait petit. Quand
// il grandit, on ne sait plus laquelle des deux avait raison — et c'est la vue
// qu'on consulte quand quelque chose ne va pas.
//
// Le tri arrive DÉJÀ fait : `ListCompliance` appelle `TrierConformite`. La page
// ne le refait pas, et surtout ne le défait pas en réordonnant.
//
// # Accès
//
// `read:get:gpo`, la même clé que la ligne de commande, portée par les actions.
// La liste est réduite au périmètre de l'appelant par le filtre du registre, et
// le nombre d'entrées masquées est annoncé dans le message de l'action.

type conformiteVue struct {
	dbgpo.ComplianceRow

	// Les libellés sont calculés ICI, une fois, plutôt que dans le gabarit.
	// `html/template` ne sait pas appeler une méthode avec argument, et
	// `Fraicheur` en prend un — l'instant. Le faire passer par le gabarit
	// demanderait d'y injecter l'heure, donc d'y faire entrer une décision.
	Etat       string
	Modules    string
	Conformite string
	VuIlYA     string
}

// AdminGPOComplianceHandler affiche la conformité du parc, ou le détail d'une
// machine quand `?machine=` est fourni.
func AdminGPOComplianceHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:gpo") {
		return
	}

	appelant := act.Appelant{Username: username, GroupIDs: groupIDs}
	maintenant := time.Now()

	if machine := strings.TrimSpace(r.URL.Query().Get("machine")); machine != "" {
		detailConformite(w, appelant, username, machine, maintenant)
		return
	}

	// « ?ecarts=1 » reproduit `vlt gpo drift`.
	ecartsSeuls := r.URL.Query().Get("ecarts") == "1"

	res, err := act.Executer("gpo.list_compliance", appelant, act.Params{})
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: gpo compliance failed: "+err.Error())
		http.Error(w, MessageDActionPourAffichage(res, err), http.StatusForbidden)
		return
	}
	rows, _ := res.Donnees.([]dbgpo.ComplianceRow)

	data := struct {
		Username    string
		DnsEnable   bool
		Section     string
		Message     string
		Resume      string
		Lignes      []conformiteVue
		Total       int
		EcartsSeuls bool
		Vide        bool
	}{
		Username: username, DnsEnable: storage.Dns_Enable, Section: "conformite",
		Message: res.Message, EcartsSeuls: ecartsSeuls, Total: len(rows),
	}

	for _, ligne := range rows {
		// Le filtre « écarts » vient du paquet : une machine MUETTE y figure
		// alors qu'elle a zéro écart constaté — non parce qu'elle est saine,
		// mais parce que plus personne ne regarde.
		if ecartsSeuls && !ligne.ARetenirDansLaVueDesEcarts(maintenant) {
			continue
		}
		data.Lignes = append(data.Lignes, vueDeLigne(ligne, maintenant))
	}

	if len(rows) > 0 {
		data.Resume = dbgpo.ResumerParc(rows, maintenant).Lisible()
	}
	// Zéro ligne à l'inventaire et zéro ligne après filtrage sont deux états
	// différents, et le gabarit doit pouvoir les distinguer : le premier appelle
	// « créez une machine », le second « rien à signaler ».
	data.Vide = len(rows) == 0

	if err := executeAdminPage(w, "admin_gpo_compliance.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

func vueDeLigne(r dbgpo.ComplianceRow, maintenant time.Time) conformiteVue {
	return conformiteVue{
		ComplianceRow: r,
		Etat:          string(r.Fraicheur(maintenant)),
		Modules:       r.ModulesAppliques(),
		Conformite:    r.EtatConformite(),
		VuIlYA:        dbgpo.AgeRelatif(r.ReportedAt, maintenant),
	}
}

// detailConformite affiche la fiche d'une machine.
func detailConformite(w http.ResponseWriter, appelant act.Appelant, username, machine string, maintenant time.Time) {
	res, err := act.Executer("gpo.get_compliance", appelant,
		act.Params{"computeur_id": machine})
	if err != nil {
		http.Error(w, MessageDActionPourAffichage(res, err), http.StatusForbidden)
		return
	}
	d, ok := res.Donnees.(act.ConformiteMachine)
	if !ok {
		http.Error(w, "Réponse inattendue", http.StatusInternalServerError)
		return
	}

	type etatVue struct {
		dbgpo.ComplianceRow
		Conformite   string
		VuIlYA       string
		ScanIlYA     string
		JamaisScanne bool
	}

	data := struct {
		Username  string
		DnsEnable bool
		Section   string
		Machine   string
		Etats     []etatVue
		Echecs    []dbgpo.ModuleReportRow
		Ecarts    []dbgpo.DriftRow
		// Les deux lectures secondaires peuvent échouer sans faire échouer la
		// fiche : l'état par portée suffit à répondre à « cette machine est-elle
		// conforme ». Refuser toute la page parce que le détail des modules
		// manque priverait de la réponse principale.
		ModulesIllisibles string
		EcartsIllisibles  string
	}{
		Username: username, DnsEnable: storage.Dns_Enable, Section: "conformite",
		Machine: d.ComputeurID, Echecs: d.Echecs, Ecarts: d.Ecarts,
		ModulesIllisibles: d.ModulesIllisibles, EcartsIllisibles: d.EcartsIllisibles,
	}

	for _, e := range d.Etats {
		v := etatVue{
			ComplianceRow: e,
			Conformite:    e.EtatConformite(),
			VuIlYA:        dbgpo.AgeRelatif(e.ReportedAt, maintenant),
			JamaisScanne:  !e.DriftAt.Valid,
		}
		if e.DriftAt.Valid {
			v.ScanIlYA = dbgpo.AgeRelatif(e.DriftAt.Time, maintenant)
		}
		data.Etats = append(data.Etats, v)
	}

	if err := executeAdminPage(w, "admin_gpo_compliance_detail.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}
