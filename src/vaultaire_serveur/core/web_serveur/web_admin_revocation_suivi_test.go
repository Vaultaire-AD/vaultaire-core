package webserveur

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/revocation"
)

// La fiche d'un compte montre le suivi avec les MÊMES mots que la ligne de
// commande — TO-DO 164.
func TestLaFicheReprendLesLibellesDuSuivi(t *testing.T) {
	cibles := []dbrevocation.TargetRecord{
		{ComputeurID: "PC-07", Status: revocation.StatusFailed, Attempts: 4, Detail: "command_failed : 2 processus",
			DepuisLeDernier: sql.NullInt64{Int64: 12, Valid: true}},
		{ComputeurID: "PC-03", Status: revocation.StatusPending},
		{ComputeurID: "PC-04", Status: revocation.StatusLifted, Attempts: 2},
		{ComputeurID: "PC-01", Status: revocation.StatusAcked, Attempts: 1, Detail: "applied"},
	}
	vues := vueDuSuivi(dbrevocation.Suivi{Ordres: []dbrevocation.OrdreSuivi{
		{Record: dbrevocation.Record{ID: 12, Mode: revocation.ModeSoft, Reason: revocation.ReasonCompromised,
			IssuedBy: "admin", IssuedAt: time.Date(2026, 10, 7, 16, 2, 3, 0, time.UTC)}, Cibles: cibles, Masquees: 1},
		{Record: dbrevocation.Record{ID: 9, Mode: revocation.ModeUnlock, LiftedBy: ""}, Cibles: cibles[3:]},
		{Record: dbrevocation.Record{ID: 7, Mode: revocation.ModeSoft, LiftedBy: "admin"}, Cibles: cibles[:1]},
	}})
	if len(vues) != 3 {
		t.Fatalf("%d ordre(s) mis en forme, attendu 3", len(vues))
	}

	v := vues[0]
	if v.Decompte != dbrevocation.Compter(cibles).Lisible() || v.Reste != 2 || v.Masquees != 1 {
		t.Errorf("ordre 12 : décompte %q, reste %d, masquées %d", v.Decompte, v.Reste, v.Masquees)
	}
	if v.Action != revocation.ModeSoft.Label() || v.Motif != revocation.ReasonCompromised.Label() || v.Le != "2026-10-07 16:02:03" {
		t.Errorf("ordre 12 : %q, %q, %q", v.Action, v.Motif, v.Le)
	}
	for i, c := range cibles {
		got := v.Cibles[i]
		if got.Machine != c.ComputeurID || got.Etat != c.Status.Libelle() || got.Detail != c.Commentaire() ||
			got.Echange != c.Echange() || got.Remises != c.Attempts {
			t.Errorf("cible %d : %+v — la page ne reprend pas ce que rend db_revocation", i, got)
		}
		if got.AReprendre != c.Status.ARejouer() {
			t.Errorf("%s (%s) : mise en avant = %v", c.ComputeurID, c.Status, got.AReprendre)
		}
	}

	// Dépliés : le plus récent, et tout ordre qui n'est pas réglé. Un ordre
	// ancien et réglé reste replié.
	if !vues[0].Ouvert || vues[1].Ouvert || !vues[2].Ouvert {
		t.Errorf("ordres dépliés : %v, %v, %v — attendu le plus récent, pas l'ancien réglé, et l'ancien en échec",
			vues[0].Ouvert, vues[1].Ouvert, vues[2].Ouvert)
	}
}

// Sentinelle : la page ne recompose ni un libellé d'état, ni un décompte, ni
// un tri. Elle appelle les fonctions partagées, et passe par l'action.
func TestLaFicheNeDecideRienDuSuivi(t *testing.T) {
	brut, err := os.ReadFile("web_admin_revocation_suivi.go")
	if err != nil {
		t.Fatal(err)
	}
	var code strings.Builder
	for _, ligne := range strings.Split(string(brut), "\n") {
		if i := strings.Index(ligne, "//"); i >= 0 {
			ligne = ligne[:i]
		}
		code.WriteString(ligne + "\n")
	}
	source := code.String()

	for _, attendu := range []string{
		`"revocation.get_status"`, "dbrevocation.Compter(", ".Lisible()", ".Libelle()", ".Commentaire()", ".Echange()", ".ARejouer()",
	} {
		if !strings.Contains(source, attendu) {
			t.Errorf("la fiche n'appelle plus %s : elle décide à la place du paquet partagé", attendu)
		}
	}
	for _, interdit := range []string{
		"sort.", "StatusPending", "StatusFailed", "StatusAcked", "StatusLifted",
		`"en attente"`, `"en échec"`, `"appliqué"`, "dbrevocation.SuiviPour(", "dbrevocation.TargetsOf(",
	} {
		if strings.Contains(source, interdit) {
			t.Errorf("la fiche contient %s : un tri, un état ou une lecture directe qui contourne l'action", interdit)
		}
	}
}

// codeSans rend le code d'un fichier Go sans ses commentaires de fin de ligne.
func codeSans(t *testing.T, fichier string) string {
	t.Helper()
	brut, err := os.ReadFile(fichier)
	if err != nil {
		t.Fatal(err)
	}
	var code strings.Builder
	for _, ligne := range strings.Split(string(brut), "\n") {
		if i := strings.Index(ligne, "//"); i >= 0 {
			ligne = ligne[:i]
		}
		code.WriteString(ligne + "\n")
	}
	return code.String()
}

// TO-DO 169 — « Demander un cycle » depuis le portail.
//
// Deux boutons, une seule action : celui d'une machine est routé vers
// `gpo.refresh` ; celui d'une GPO fait la boucle PARTAGÉE avec la ligne de
// commande, et ne la refait pas.
func TestLesBoutonsDeCyclePassentParLActionPartagee(t *testing.T) {
	if nom, ok := ActionDuRegistrePour("refresh_gpo"); !ok || nom != "gpo.refresh" {
		t.Errorf("le bouton d'une machine est routé vers %q (%v), attendu gpo.refresh", nom, ok)
	}
	// Le bouton d'une GPO n'est PAS une action du registre : s'il y était
	// routé, il ne viserait qu'une machine.
	if _, ok := ActionDuRegistrePour(actionCycleDesMachines); ok {
		t.Errorf("%s est routée vers une action unique : la boucle par machine a disparu", actionCycleDesMachines)
	}

	gpoPage := codeSans(t, "web_admin_gpo.go")
	if !strings.Contains(gpoPage, "act.RafraichirMachinesDeLaGPO(") {
		t.Error("la fiche d'une GPO ne passe plus par action.RafraichirMachinesDeLaGPO : " +
			"le portail et « vlt gpo refresh --gpo » ne compteraient plus pareil")
	}
	for _, interdit := range []string{"gpomanager.", "DemanderRafraichissement(", `"gpo.refresh"`} {
		if strings.Contains(gpoPage, interdit) {
			t.Errorf("la fiche d'une GPO contient %s : elle pousse ou boucle elle-même au lieu d'emprunter la fonction partagée", interdit)
		}
	}

	conformite := codeSans(t, "web_admin_conformite.go")
	if !strings.Contains(conformite, `act.Params{"computeur_id": machine}`) {
		t.Error("la fiche d'une machine ne tire plus sa cible de l'adresse : un champ de formulaire forgé " +
			"ferait rafraîchir une autre machine que celle qu'on regarde")
	}
	if strings.Contains(conformite, "gpomanager.") {
		t.Error("la fiche d'une machine pousse elle-même la demande, sans passer par l'action et son contrôle de droits")
	}
}

// Les gabarits : le bouton d'une GPO n'est proposé que pour une portée machine,
// et la page dit ce qu'il en est d'une GPO de compte.
func TestLesGabaritsProposentLeCycleAuBonEndroit(t *testing.T) {
	lire := func(nom string) string {
		brut, err := os.ReadFile(cheminGabarits + "/" + nom)
		if err != nil {
			t.Fatal(err)
		}
		return string(brut)
	}

	gpoPage := lire("admin_gpo_detail.html")
	garde, bouton := strings.Index(gpoPage, "{{ if .PorteeMachine }}"), strings.Index(gpoPage, `value="refresh_gpo_machines"`)
	sinon := strings.Index(gpoPage, "Une GPO de compte s'applique à la prochaine ouverture de session")
	if garde < 0 || bouton < 0 || sinon < 0 || !(garde < bouton && bouton < sinon) {
		t.Errorf("fiche d'une GPO : le bouton doit être sous « si portée machine », et la phrase sur les GPO de compte "+
			"dans le « sinon » (positions %d, %d, %d)", garde, bouton, sinon)
	}
	if !strings.Contains(gpoPage, "{{ if .PeutDemanderUnCycle }}") {
		t.Error("fiche d'une GPO : le bouton est proposé à qui n'a le droit d'agir sur aucune machine")
	}

	machine := lire("admin_gpo_compliance_detail.html")
	for _, attendu := range []string{
		`name="action" value="refresh_gpo"`, "{{ if .PeutDemanderUnCycle }}",
		"Les GPO de compte ne sont pas concernées", "{{ if .Message }}", "{{ if .Error }}",
	} {
		if !strings.Contains(machine, attendu) {
			t.Errorf("fiche d'une machine : %q absent du gabarit", attendu)
		}
	}
	// La cible n'est pas un champ du formulaire : elle vient de l'adresse.
	if strings.Contains(machine, `name="computeur_id"`) {
		t.Error("fiche d'une machine : le formulaire porte la cible — elle doit venir de l'adresse")
	}
}
