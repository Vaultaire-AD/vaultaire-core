package webserveur

import (
	"net/http"
	"strings"
	"time"

	act "vaultaire/core/action"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
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
// Le tri arrive DÉJÀ fait : `RegrouperParMachine` rend les machines dans
// l'ordre. La page ne le refait pas, et surtout ne le défait pas en réordonnant.
//
// # Accès
//
// `read:get:gpo`, la même clé que la ligne de commande, portée par les actions.
// La liste est réduite au périmètre de l'appelant par le filtre du registre, et
// le nombre d'entrées masquées est annoncé dans le message de l'action.

// conformiteVue est une ligne de la liste : une MACHINE (TO-DO 143).
//
// Les libellés sont calculés ICI, une fois, plutôt que dans le gabarit.
// `html/template` ne sait pas appeler une méthode avec argument, et
// `Fraicheur` en prend un — l'instant. Le faire passer par le gabarit
// demanderait d'y injecter l'heure, donc d'y faire entrer une décision.
type conformiteVue struct {
	ComputeurID string
	Etat        string
	Application string
	Modules     string
	Conformite  string
	Comptes     string
	VuIlYA      string

	// NonVerifiee fait ressortir la cellule : « non vérifié » en texte nu se
	// lisait comme une valeur parmi d'autres, entre deux « ok » (TO-DO 135).
	NonVerifiee bool

	// ARemonter : les comptes qui ont quelque chose à montrer, affichés sous
	// la machine. Les autres ne sont que dans la fiche.
	ARemonter []compteVue
}

// compteVue est la portée d'un compte remontée sous sa machine.
type compteVue struct {
	Utilisateur string
	Application string
	Modules     string
	Conformite  string
	VuIlYA      string
	NonVerifiee bool
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
		// La fiche d'une machine porte UNE écriture : demander un cycle
		// (TO-DO 169). Elle passe par le registre, comme la ligne de commande —
		// `gpo.refresh`, write:update:client sur les domaines de la machine. La
		// cible vient de l'adresse, pas du formulaire : un champ forgé ne fait
		// pas rafraîchir une autre machine que celle qu'on regarde.
		message, erreur := "", ""
		if r.Method == http.MethodPost {
			res, traite, errAction := ExecuterActionFormulaireAvec(r, username, groupIDs,
				act.Params{"computeur_id": machine})
			if traite {
				if errAction != nil {
					erreur = MessageDActionPourAffichage(res, errAction)
				} else {
					message = res.Message
				}
			}
		}
		detailConformite(w, appelant, username, machine, maintenant, ficheMachineActions{
			Message: message, Erreur: erreur,
			// Le bouton n'est montré qu'à qui détient le droit QUELQUE PART ; le
			// contrôle qui compte, sur cette machine-ci, est celui de l'action.
			PeutDemanderUnCycle: permission.HasActionAnywhere(groupIDs, "write:update:client"),
		})
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

	// Une ligne par machine. Le regroupement — quelle portée date la machine,
	// quels comptes remontent, quel état l'emporte — vient du paquet, comme le
	// tri : la ligne de commande passe par la même fonction.
	machines := dbgpo.RegrouperParMachine(rows, maintenant)

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
		Message: res.Message, EcartsSeuls: ecartsSeuls, Total: len(machines),
	}

	for _, machine := range machines {
		// Le filtre « écarts » vient du paquet : une machine MUETTE y figure
		// alors qu'elle a zéro écart constaté — non parce qu'elle est saine,
		// mais parce que plus personne ne regarde.
		if ecartsSeuls && !machine.ARetenirDansLaVueDesEcarts(maintenant) {
			continue
		}
		data.Lignes = append(data.Lignes, vueDeMachine(machine, maintenant))
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

// vueDeMachine met une machine en forme pour la liste.
func vueDeMachine(m dbgpo.LigneMachine, maintenant time.Time) conformiteVue {
	v := conformiteVue{
		ComputeurID: m.ComputeurID,
		Etat:        string(m.Fraicheur(maintenant)),
		Application: "—",
		Modules:     "—",
		Conformite:  "—",
		Comptes:     m.EtatDesComptes(),
		VuIlYA:      dbgpo.AgeRelatif(m.VuLe(), maintenant),
	}
	if m.AMachine {
		v.Modules = m.Machine.ModulesAppliques()
		v.Conformite = m.Machine.EtatConformite()
		v.NonVerifiee = m.Machine.NonVerifiee()
		if m.Machine.Status != "" {
			v.Application = m.Machine.Status
		}
	}
	for _, c := range m.ARemonter() {
		application := c.Status
		if application == "" {
			application = "—"
		}
		v.ARemonter = append(v.ARemonter, compteVue{
			Utilisateur: c.TargetUser,
			Application: application,
			Modules:     c.ModulesAppliques(),
			Conformite:  c.EtatConformite(),
			VuIlYA:      dbgpo.AgeRelatif(c.ReportedAt, maintenant),
			NonVerifiee: c.NonVerifiee(),
		})
	}
	return v
}

// ficheMachineActions porte ce que la fiche d'une machine affiche de ses
// actions : le résultat de celle qui vient d'être faite, et le droit de la
// proposer.
type ficheMachineActions struct {
	Message, Erreur     string
	PeutDemanderUnCycle bool
}

// detailConformite affiche la fiche d'une machine.
func detailConformite(w http.ResponseWriter, appelant act.Appelant, username, machine string, maintenant time.Time, actions ficheMachineActions) {
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

	// NonVerifiee vient du paquet, comme dans la liste. La fiche le décidait
	// elle-même (« pas de date de scan ») et affichait donc « jamais vérifiée »
	// pour une portée qui n'applique AUCUN module — celle que la liste, une
	// page plus haut, dit « rien à vérifier ». Deux pages, deux réponses pour la
	// même ligne : c'est exactement ce que cette page ne doit pas faire.
	type etatVue struct {
		dbgpo.ComplianceRow
		Conformite  string
		VuIlYA      string
		ScanIlYA    string
		NonVerifiee bool
		// EmpreinteCourte : les douze premiers caractères. Les soixante-quatre
		// de l'empreinte entière poussaient la colonne « Conformité » — celle
		// qu'on vient lire — hors de l'écran. L'empreinte entière reste au
		// survol, et dans `vlt gpo status <machine>`.
		EmpreinteCourte string
	}

	// L'historique porte une date déjà mise en forme : un gabarit HTML ne sait
	// pas dire « il y a trois jours », et lui faire calculer une durée
	// donnerait deux façons de l'écrire selon qu'on lit la page ou la CLI.
	type transitionVue struct {
		dbgpo.ApplyHistoryRow
		QuandIlYA string
		Reussis   int
	}

	data := struct {
		Username   string
		DnsEnable  bool
		Section    string
		Machine    string
		Etats      []etatVue
		Echecs     []dbgpo.ModuleReportRow
		Ecarts     []dbgpo.DriftRow
		Historique []transitionVue
		// Les lectures secondaires peuvent échouer sans faire échouer la
		// fiche : l'état par portée suffit à répondre à « cette machine est-elle
		// conforme ». Refuser toute la page parce que le détail des modules
		// manque priverait de la réponse principale.
		ModulesIllisibles   string
		EcartsIllisibles    string
		HistoriqueIllisible string
		// Demander un cycle (TO-DO 169).
		Message             string
		Error               string
		PeutDemanderUnCycle bool
	}{
		Username: username, DnsEnable: storage.Dns_Enable, Section: "conformite",
		Message: actions.Message, Error: actions.Erreur, PeutDemanderUnCycle: actions.PeutDemanderUnCycle,
		Machine: d.ComputeurID, Echecs: d.Echecs, Ecarts: d.Ecarts,
		ModulesIllisibles: d.ModulesIllisibles, EcartsIllisibles: d.EcartsIllisibles,
		HistoriqueIllisible: d.HistoriqueIllisible,
	}

	for _, h := range d.Historique {
		data.Historique = append(data.Historique, transitionVue{
			ApplyHistoryRow: h,
			QuandIlYA:       dbgpo.AgeRelatif(h.ReportedAt, maintenant),
			Reussis:         h.ModulesTotal - h.ModulesFailed - h.ModulesSkipped,
		})
	}

	for _, e := range d.Etats {
		v := etatVue{
			ComplianceRow: e,
			Conformite:    e.EtatConformite(),
			VuIlYA:        dbgpo.AgeRelatif(e.ReportedAt, maintenant),
			NonVerifiee:   e.NonVerifiee(),
		}
		v.EmpreinteCourte = e.Fingerprint
		if len(v.EmpreinteCourte) > 12 {
			v.EmpreinteCourte = v.EmpreinteCourte[:12] + "…"
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
