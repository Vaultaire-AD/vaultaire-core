package action

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"vaultaire/core/parcversion"
	"vaultaire/core/reglages"
)

// La cadence de vérification en ligne et le parc — TO-DO 161.
//
// # Ce que ces tests gardent
//
// Le défaut est silencieux par nature : poser 10 minutes réussit, le compte
// rendu est propre, et ce sont des postes anciens, ailleurs, qui se mettent à
// se reconnecter en boucle. D'où trois propriétés :
//
//   - sans confirmation, une cadence que le parc ne suit pas n'écrit RIEN ;
//   - un parc illisible n'est pas un parc à jour ;
//   - le seuil est celui que conseille le texte du réglage, pas un autre.

type parcSimule struct {
	ecrits []string
}

func simulerParc(t *testing.T, machines []parcversion.Machine, erreur error) *parcSimule {
	t.Helper()
	ps := &parcSimule{}
	anciensRecenser, anciensEcrire, anciensEtat := recenserParc, ecrireReglage, etatCourant
	recenserParc = func() (parcversion.Bilan, error) {
		if erreur != nil {
			return parcversion.Bilan{}, erreur
		}
		return parcversion.Recenser(machines, reglages.VersionQuiSuitLaCadence), nil
	}
	ecrireReglage = func(cle string, valeur int, par string) error {
		ps.ecrits = append(ps.ecrits, fmt.Sprintf("%s=%d par %s", cle, valeur, par))
		return nil
	}
	t.Cleanup(func() { recenserParc, ecrireReglage, etatCourant = anciensRecenser, anciensEcrire, anciensEtat })
	return ps
}

func parcMixte() []parcversion.Machine {
	return []parcversion.Machine{
		{ComputeurID: "a", Hostname: "pc-a", Declaree: "2.3.0+g1 (2026-10-07)"},
		{ComputeurID: "b", Hostname: "pc-b", Declaree: "2.1.4+g2 (2026-08-01)"},
		{ComputeurID: "c", Hostname: "pc-c", Declaree: ""},
		{ComputeurID: "d", Hostname: "pc-d", Declaree: "2.2.0"},
	}
}

func parcAJour() []parcversion.Machine {
	return []parcversion.Machine{
		{Hostname: "pc-a", Declaree: "2.3.0+g1"},
		{Hostname: "pc-d", Declaree: "2.2.0 (build local)"},
	}
}

var cadence = reglages.CleVerificationEnLigne

func TestUneCadenceQueLeParcNeSuitPasDemandeConfirmation(t *testing.T) {
	ps := simulerParc(t, parcMixte(), nil)

	_, err := reglerDuree(quelquun, Params{"setting": cadence, "value": "10"})
	var attente *ErrConfirmationRequise
	if !errors.As(err, &attente) {
		t.Fatalf("attendu une demande de confirmation, reçu : %v", err)
	}
	if len(ps.ecrits) != 0 {
		t.Fatalf("le réglage a été écrit SANS confirmation : %v", ps.ecrits)
	}
	// Le motif nomme les machines, avec leur version, et dit quoi taper.
	for _, attendu := range []string{
		"RIEN n'a été changé", "2 machine(s)", "pc-b (2.1.4)", "pc-c (jamais déclarée)",
		"settings set check_online_minutes 10 --confirm",
	} {
		if !strings.Contains(attente.Motif, attendu) {
			t.Errorf("le motif ne dit pas %q :\n%s", attendu, attente.Motif)
		}
	}
	if strings.Contains(attente.Motif, "pc-a") || strings.Contains(attente.Motif, "pc-d") {
		t.Errorf("le motif nomme une machine à jour :\n%s", attente.Motif)
	}
	// La page rejoue exactement cette demande.
	if attente.Rejouer.Get("value") != "10" || attente.Rejouer.Get("confirm") != "yes" ||
		attente.Rejouer.Get("setting") != cadence {
		t.Errorf("Rejouer = %v", attente.Rejouer)
	}
}

func TestLaConfirmationPoseLaValeurEtLeDit(t *testing.T) {
	ps := simulerParc(t, parcMixte(), nil)

	res, err := reglerDuree(quelquun, Params{"setting": cadence, "value": "10", "confirm": "yes"})
	if err != nil {
		t.Fatalf("confirmé, et pourtant refusé : %v", err)
	}
	if len(ps.ecrits) != 1 || ps.ecrits[0] != cadence+"=10 par alice" {
		t.Fatalf("écritures = %v", ps.ecrits)
	}
	if !strings.HasPrefix(res.Message, "Confirmé malgré l'avertissement") ||
		!strings.Contains(res.Message, "pc-b") {
		t.Errorf("le compte rendu ne rappelle pas ce qui a été assumé :\n%s", res.Message)
	}
}

// Une confirmation mal écrite n'en est pas une.
func TestSeulYesConfirme(t *testing.T) {
	for _, v := range []string{"", "no", "1", "true", "oui", "y"} {
		ps := simulerParc(t, parcMixte(), nil)
		_, err := reglerDuree(quelquun, Params{"setting": cadence, "value": "10", "confirm": v})
		var attente *ErrConfirmationRequise
		if !errors.As(err, &attente) || len(ps.ecrits) != 0 {
			t.Errorf("confirm=%q a été pris pour une confirmation (err=%v, écrits=%v)", v, err, ps.ecrits)
		}
	}
}

func TestUnParcAJourNeDemandeRien(t *testing.T) {
	ps := simulerParc(t, parcAJour(), nil)
	res, err := reglerDuree(quelquun, Params{"setting": cadence, "value": "30"})
	if err != nil || len(ps.ecrits) != 1 {
		t.Fatalf("parc à jour : err=%v, écrits=%v", err, ps.ecrits)
	}
	if strings.Contains(res.Message, "Confirmé") {
		t.Errorf("rien à confirmer, et pourtant : %s", res.Message)
	}
}

// Le seuil : 8 passe sans un mot, 9 demande. C'est la valeur du texte du
// réglage — si l'un bouge sans l'autre, ce test le voit.
func TestLeSeuilEstCeluiQueConseilleLeReglage(t *testing.T) {
	sure := reglages.CadenceSurePourAgentsAnterieurs
	d, _ := reglages.DefinitionDe(cadence)
	if !strings.Contains(d.Consequence, fmt.Sprintf("dépasser %d minutes", sure)) {
		t.Fatalf("la Consequence ne conseille plus %d minutes :\n%s", sure, d.Consequence)
	}

	ps := simulerParc(t, parcMixte(), nil)
	for v := d.Min; v <= sure; v++ {
		if _, err := reglerDuree(quelquun, Params{"setting": cadence, "value": fmt.Sprint(v)}); err != nil {
			t.Errorf("%d min refusé : %v", v, err)
		}
	}
	if len(ps.ecrits) != sure-d.Min+1 {
		t.Errorf("écritures = %v", ps.ecrits)
	}
	var attente *ErrConfirmationRequise
	if _, err := reglerDuree(quelquun, Params{"setting": cadence, "value": fmt.Sprint(sure + 1)}); !errors.As(err, &attente) {
		t.Errorf("%d min passé sans confirmation : %v", sure+1, err)
	}
}

// Ne pas pouvoir compter n'est pas compter zéro.
func TestUnParcIllisibleDemandeConfirmation(t *testing.T) {
	ps := simulerParc(t, nil, errors.New("base injoignable"))

	_, err := reglerDuree(quelquun, Params{"setting": cadence, "value": "15"})
	var attente *ErrConfirmationRequise
	if !errors.As(err, &attente) || len(ps.ecrits) != 0 {
		t.Fatalf("parc illisible : err=%v, écrits=%v", err, ps.ecrits)
	}
	if !strings.Contains(attente.Motif, "base injoignable") {
		t.Errorf("le motif ne dit pas pourquoi le parc n'a pas été compté :\n%s", attente.Motif)
	}
	if _, err := reglerDuree(quelquun, Params{"setting": cadence, "value": "15", "confirm": "yes"}); err != nil {
		t.Fatalf("parc illisible, confirmé : %v", err)
	}
}

// Une valeur hors bornes est refusée pour ce qu'elle est, sans demander de
// confirmation qui échouerait ensuite.
func TestHorsBornesAvantLeParc(t *testing.T) {
	simulerParc(t, parcMixte(), nil)
	_, err := reglerDuree(quelquun, Params{"setting": cadence, "value": "61", "confirm": "yes"})
	var attente *ErrConfirmationRequise
	if err == nil || errors.As(err, &attente) || !strings.Contains(err.Error(), "entre 1 et 60") {
		t.Fatalf("61 min : %v", err)
	}
}

// Les autres réglages ne lisent jamais le parc.
func TestLesAutresReglagesNeLisentPasLeParc(t *testing.T) {
	ps := simulerParc(t, nil, errors.New("ne doit pas être appelé"))
	if _, err := reglerDuree(quelquun, Params{"setting": reglages.CleSessionsDucky, "value": "60"}); err != nil {
		t.Fatalf("un autre réglage a buté sur le parc : %v", err)
	}
	if len(ps.ecrits) != 1 {
		t.Fatalf("écritures = %v", ps.ecrits)
	}
}

// La liste porte l'avertissement à côté de la valeur courante.
func TestLaListeAvertitSurLaValeurCourante(t *testing.T) {
	simulerParc(t, parcMixte(), nil)
	etatCourant = func() []reglages.Etat {
		out := reglages.EtatCourant()
		for i := range out {
			if out[i].Cle == cadence {
				out[i].Valeur = 12
			}
		}
		return out
	}

	res, err := listerDurees(quelquun, Params{})
	if err != nil {
		t.Fatal(err)
	}
	etats := res.Donnees.([]reglages.Etat)
	for _, e := range etats {
		switch {
		case e.Cle == cadence:
			if !strings.Contains(e.Avertissement, "à 12 min") || !strings.Contains(e.Avertissement, "pc-b") {
				t.Errorf("avertissement = %q", e.Avertissement)
			}
		case e.Avertissement != "":
			t.Errorf("%s porte un avertissement : %q", e.Cle, e.Avertissement)
		}
	}
	if !strings.Contains(res.Message, "1 avertissement(s)") {
		t.Errorf("message = %q", res.Message)
	}

	// Même parc, cadence sûre : rien.
	etatCourant = reglages.EtatCourant
	res, _ = listerDurees(quelquun, Params{})
	for _, e := range res.Donnees.([]reglages.Etat) {
		if e.Avertissement != "" {
			t.Errorf("cadence par défaut, et pourtant : %s : %q", e.Cle, e.Avertissement)
		}
	}
}
