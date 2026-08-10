package action

import (
	"errors"
	"strings"
	"testing"
)

// Tests de la ligne d'audit.
//
// Ce qui est gardé ici est la distinction LECTURE / ÉCRITURE.
//
// Toute action passait auparavant par Journal.Execution, lectures comprises.
// Chaque page du portail déclenchant au moins une lecture, le journal se
// remplissait de consultations et les modifications s'y perdaient. La
// régression consisterait à retirer le filtre, ou à donner une clé « read: »
// à une action qui écrit — et elle ne produirait aucune erreur, juste du bruit
// qui revient.

func lecture(nom string) Definition {
	return Definition{
		Nom:           nom,
		CleRBAC:       "read:get:user",
		Portee:        PorteeGlobale,
		Resume:        "lecture de test",
		FiltreInutile: "liste de test, sans entités à filtrer",
		Executer:      func(Appelant, Params) (Resultat, error) { return Resultat{Message: "ok"}, nil },
	}
}

func ecriture(nom string, err error) Definition {
	return Definition{
		Nom:      nom,
		CleRBAC:  "write:create:user",
		Portee:   PorteeGlobale,
		Resume:   "écriture de test",
		Executer: func(Appelant, Params) (Resultat, error) { return Resultat{Message: "ok"}, err },
	}
}

// executeurDAudit monte un exécuteur qui accorde tout, pour n'observer que le
// journal.
func executeurDAudit(t *testing.T, d Definition) (*Executeur, *journalMemoire) {
	t.Helper()
	r := NouveauRegistre()
	if err := r.Enregistrer(d); err != nil {
		t.Fatalf("enregistrement : %v", err)
	}
	j := &journalMemoire{}
	// droitsFixes{autorise: true} : on accorde tout, pour n'observer que le
	// journal. Ce que le contrôle décide est éprouvé ailleurs.
	return &Executeur{
		Registre: r,
		Droits:   &droitsFixes{autorise: true},
		Journal:  j,
	}, j
}

func TestUneLectureNeJournalisePas(t *testing.T) {
	e, j := executeurDAudit(t, lecture("user.list"))
	if _, err := e.Executer("user.list", Appelant{Username: "alice"}, Params{}); err != nil {
		t.Fatalf("exécution : %v", err)
	}
	if len(j.executions) != 0 || len(j.echecs) != 0 {
		t.Fatalf("une lecture a été journalisée : %v %v — chaque page du portail "+
			"en déclenche une, le journal se remplirait de consultations",
			j.executions, j.echecs)
	}
}

func TestUneEcritureJournaliseQuiFaitQuoiSurQuoi(t *testing.T) {
	e, j := executeurDAudit(t, ecriture("user.create", nil))
	_, err := e.Executer("user.create", Appelant{Username: "alice"}, Params{"username": "bob"})
	if err != nil {
		t.Fatalf("exécution : %v", err)
	}
	if len(j.executions) != 1 {
		t.Fatalf("%d ligne(s) d'audit, attendu 1", len(j.executions))
	}
	ligne := j.executions[0]
	for _, attendu := range []string{"alice", "user.create", "bob"} {
		if !strings.Contains(ligne, attendu) {
			t.Errorf("ligne = %q : %q manque — l'audit doit dire qui, quoi et sur quoi",
				ligne, attendu)
		}
	}
}

// TestUneEcritureEnEchecNestPasUneInformation : l'échec passe par Echec, donc
// en WARNING. Les deux passaient par Execution, au même niveau : un échec
// d'écriture se lisait comme une réussite dans un journal filtré sur INFO.
func TestUneEcritureEnEchecPasseParEchec(t *testing.T) {
	e, j := executeurDAudit(t, ecriture("user.create", errors.New("nom déjà pris")))
	if _, err := e.Executer("user.create", Appelant{Username: "alice"}, Params{"username": "bob"}); err == nil {
		t.Fatal("l'erreur de l'action n'a pas été remontée")
	}
	if len(j.executions) != 0 {
		t.Errorf("un échec a été journalisé comme une réussite : %v", j.executions)
	}
	if len(j.echecs) != 1 {
		t.Fatalf("%d ligne(s) d'échec, attendu 1", len(j.echecs))
	}
	if !strings.Contains(j.echecs[0], "nom déjà pris") {
		t.Errorf("ligne = %q : le motif de l'échec est perdu", j.echecs[0])
	}
}

// TestLaCibleEstNommeeSelonLaction : la cible n'est pas déclarée par les
// actions, elle est déduite d'une liste ordonnée de noms de paramètres. Un
// changement d'ordre ferait nommer la mauvaise entité — un rattachement porte
// à la fois un utilisateur et un groupe, et c'est l'utilisateur qui change de
// situation.
func TestLaCibleEstNommeeSelonLAction(t *testing.T) {
	cas := []struct {
		params  Params
		attendu string
	}{
		{Params{"username": "bob"}, "username bob"},
		{Params{"group": "paris"}, "group paris"},
		{Params{"username": "bob", "group": "paris"}, "username bob"},
		{Params{"gpo": "durcissement"}, "gpo durcissement"},
		{Params{}, "le serveur"},
		{Params{"inconnu": "x"}, "le serveur"},
	}
	for _, c := range cas {
		if got := cibleDe(c.params); got != c.attendu {
			t.Errorf("cibleDe(%v) = %q, attendu %q", c.params, got, c.attendu)
		}
	}
}

func TestEstEcritureSuitLaCleEtNonLeNom(t *testing.T) {
	cas := []struct {
		d       Definition
		attendu bool
	}{
		{Definition{CleRBAC: "write:create:user"}, true},
		{Definition{CleRBAC: "write:dns"}, true},
		{Definition{CleRBAC: "write:killswitch"}, true},
		{Definition{CleRBAC: "read:get:user"}, false},
		{Definition{CleRBAC: "read:log"}, false},
		{Definition{CleRBAC: "web_admin"}, false},
		// Sans clé mais réservée au groupe protégé : la suppression d'un
		// certificat interrompt un service, ne pas la tracer serait perdre
		// exactement ce qu'on veut retrouver.
		{Definition{CleRBAC: "", ExigeSuperadmin: true}, true},
		{Definition{CleRBAC: "", ExigeSuperadmin: false}, false},
	}
	for _, c := range cas {
		if got := estEcriture(c.d); got != c.attendu {
			t.Errorf("estEcriture(%q, superadmin=%v) = %v, attendu %v",
				c.d.CleRBAC, c.d.ExigeSuperadmin, got, c.attendu)
		}
	}
}
