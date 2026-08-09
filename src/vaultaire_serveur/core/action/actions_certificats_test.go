package action

import (
	"errors"
	"strings"
	"testing"
)

// Tests du contrôle par appartenance au groupe protégé.
//
// Ce mécanisme est né d'un cas que le registre ne savait pas exprimer : la
// suppression d'un certificat, qui ne relève d'aucune clé RBAC parce qu'un
// certificat ne porte pas de domaine.
//
// Le risque introduit est clair — une seconde voie d'autorisation est une
// seconde occasion de se tromper. Ces tests portent donc surtout sur ce qui
// pourrait mal tourner : le contrôle sauté, le vérificateur absent traité comme
// une autorisation, le cumul qui s'affaiblirait au lieu de s'ajouter.

type superadminFixe struct {
	membres map[string]bool
	appels  []string
}

func (s *superadminFixe) EstSuperadmin(username string) bool {
	s.appels = append(s.appels, username)
	return s.membres[username]
}

func registreCertificats(t *testing.T) *Registre {
	t.Helper()
	r := NouveauRegistre()
	EnregistrerActionsCertificat(r)
	return r
}

// TestActionSansCleMaisSuperadminEstAcceptee.
//
// C'est la correction du socle : une action sans clé RBAC était refusée à
// l'enregistrement, ce qui rendait ce cas inexprimable. Le registre exigeait
// « une clé » là où il fallait exiger « un contrôle ».
func TestActionSansCleMaisSuperadminEstAcceptee(t *testing.T) {
	r := NouveauRegistre()
	err := r.Enregistrer(Definition{
		Nom:             "certificate.delete",
		ExigeSuperadmin: true,
		Portee:          PorteeGlobale,
		Resume:          "test",
		Executer:        func(Appelant, Params) (Resultat, error) { return Resultat{}, nil },
	})
	if err != nil {
		t.Fatalf("action réservée au groupe protégé refusée : %v", err)
	}
}

// TestActionSansCleNiSuperadminTujoursRefusee.
//
// Le fail-closed ne doit pas avoir été affaibli au passage : une action qui ne
// déclare AUCUN contrôle reste refusée.
func TestActionSansCleNiSuperadminToujoursRefusee(t *testing.T) {
	r := NouveauRegistre()
	err := r.Enregistrer(Definition{
		Nom:      "sans.controle",
		Portee:   PorteeGlobale,
		Executer: func(Appelant, Params) (Resultat, error) { return Resultat{}, nil },
	})
	if err == nil {
		t.Fatal("action sans clé NI ExigeSuperadmin acceptée : le fail-closed est levé")
	}
	if !strings.Contains(err.Error(), "aucun contrôle") {
		t.Errorf("message %q : ne nomme pas la cause", err.Error())
	}
}

// TestNonMembreRefuse est le test central du mécanisme.
func TestNonMembreRefuse(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	r.MustEnregistrer(Definition{
		Nom:             "certificate.delete",
		ExigeSuperadmin: true,
		Portee:          PorteeGlobale,
		Resume:          "test",
		Executer: func(Appelant, Params) (Resultat, error) {
			aExecute = true
			return Resultat{}, nil
		},
	})

	sa := &superadminFixe{membres: map[string]bool{"root": true}}
	journal := &journalMemoire{}
	e := &Executeur{
		Registre:   r,
		Droits:     &droitsFixes{autorise: true},
		Superadmin: sa,
		Journal:    journal,
	}

	_, err := e.Executer("certificate.delete", Appelant{Username: "alice"}, Params{})
	if aExecute {
		t.Fatal("l'action a tourné pour un non-membre du groupe protégé")
	}
	var refus *ErrRefusee
	if !errors.As(err, &refus) {
		t.Fatalf("erreur de type %T, attendu *ErrRefusee", err)
	}
	if len(sa.appels) != 1 || sa.appels[0] != "alice" {
		t.Fatalf("vérificateur appelé %v, attendu une fois avec alice — le contrôle est contourné", sa.appels)
	}
	if len(journal.refus) != 1 {
		t.Error("refus non journalisé : la tentative ne laisserait aucune trace")
	}
}

// TestMembreAutorise : le contrôle ne doit pas tout refuser.
func TestMembreAutorise(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	r.MustEnregistrer(Definition{
		Nom:             "certificate.delete",
		ExigeSuperadmin: true,
		Portee:          PorteeGlobale,
		Resume:          "test",
		Executer: func(Appelant, Params) (Resultat, error) {
			aExecute = true
			return Resultat{Message: "fait"}, nil
		},
	})

	e := &Executeur{
		Registre:   r,
		Droits:     &droitsFixes{autorise: true},
		Superadmin: &superadminFixe{membres: map[string]bool{"root": true}},
	}
	if _, err := e.Executer("certificate.delete", Appelant{Username: "root"}, Params{}); err != nil {
		t.Fatalf("membre du groupe protégé refusé : %v", err)
	}
	if !aExecute {
		t.Fatal("action non exécutée pour un membre autorisé")
	}
}

// TestVerificateurAbsentRefuse.
//
// Un exécuteur sans vérificateur d'appartenance ne peut pas répondre à la
// question posée. Laisser passer reviendrait à traiter l'ignorance comme une
// autorisation — c'est la forme la plus discrète du fail-open, puisque le champ
// manquant ne provoque aucune erreur de compilation.
func TestVerificateurAbsentRefuse(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	r.MustEnregistrer(Definition{
		Nom:             "certificate.delete",
		ExigeSuperadmin: true,
		Portee:          PorteeGlobale,
		Resume:          "test",
		Executer: func(Appelant, Params) (Resultat, error) {
			aExecute = true
			return Resultat{}, nil
		},
	})

	e := &Executeur{Registre: r, Droits: &droitsFixes{autorise: true}} // Superadmin nil
	if _, err := e.Executer("certificate.delete", Appelant{Username: "root"}, Params{}); err == nil {
		t.Fatal("exécution acceptée sans vérificateur d'appartenance")
	}
	if aExecute {
		t.Fatal("l'action a tourné alors qu'aucun contrôle d'appartenance n'était possible")
	}
}

// TestCumulDesDeuxControles.
//
// Une action peut déclarer les deux. Le cumul doit être une CONJONCTION : les
// deux exigées. Une disjonction — l'un OU l'autre — affaiblirait chaque action
// qui les combine, en donnant aux membres du groupe protégé un contournement du
// RBAC qui n'a jamais été décidé.
func TestCumulDesDeuxControles(t *testing.T) {
	var aExecute bool
	r := NouveauRegistre()
	r.MustEnregistrer(Definition{
		Nom:             "cumul",
		CleRBAC:         "write:delete:client",
		ExigeSuperadmin: true,
		Portee:          PorteeGlobale,
		Resume:          "test",
		Executer: func(Appelant, Params) (Resultat, error) {
			aExecute = true
			return Resultat{}, nil
		},
	})

	// Membre du groupe protégé, mais SANS le droit RBAC.
	e := &Executeur{
		Registre:   r,
		Droits:     &droitsFixes{autorise: false, motif: "droit absent"},
		Superadmin: &superadminFixe{membres: map[string]bool{"root": true}},
	}
	if _, err := e.Executer("cumul", Appelant{Username: "root"}, Params{}); err == nil {
		t.Fatal("l'appartenance au groupe protégé contourne le contrôle RBAC")
	}
	if aExecute {
		t.Fatal("action exécutée sans le droit RBAC déclaré")
	}

	// Détenteur du droit RBAC, mais PAS membre du groupe.
	e2 := &Executeur{
		Registre:   r,
		Droits:     &droitsFixes{autorise: true},
		Superadmin: &superadminFixe{membres: map[string]bool{}},
	}
	if _, err := e2.Executer("cumul", Appelant{Username: "alice"}, Params{}); err == nil {
		t.Fatal("le droit RBAC contourne l'exigence d'appartenance")
	}
	if aExecute {
		t.Fatal("action exécutée sans appartenance au groupe protégé")
	}
}

// --- l'action elle-même -----------------------------------------------------

func TestCertificatIdentifiantInvalide(t *testing.T) {
	cas := []string{"", "abc", "0", "-1", "1.5"}
	for _, v := range cas {
		t.Run("id="+v, func(t *testing.T) {
			if _, err := supprimerCertificat(Appelant{}, Params{"certificate_id": v}); err == nil {
				t.Fatalf("identifiant %q accepté : la suppression porterait sur aucune ligne "+
					"et serait rapportée comme un succès", v)
			}
		})
	}
}

// TestMessageDeSuppressionDitLaConsequence.
//
// « Certificat supprimé » ne prépare pas l'administrateur à voir un service
// tomber au redémarrage suivant, ni les clients qui avaient importé l'ancien
// certificat à cesser de se connecter.
func TestMessageDeSuppressionDitLaConsequence(t *testing.T) {
	res, err := supprimerCertificat(Appelant{Username: "root"}, Params{"certificate_id": "3"})
	if err != nil {
		t.Fatalf("suppression : %v", err)
	}
	for _, attendu := range []string{"régénérera", "réimporter"} {
		if !strings.Contains(res.Message, attendu) {
			t.Errorf("message %q : ne contient pas %q", res.Message, attendu)
		}
	}
}

func TestCertificatEnregistreAvecSuperadmin(t *testing.T) {
	r := registreCertificats(t)
	d, ok := r.Definition("certificate.delete")
	if !ok {
		t.Fatal("certificate.delete absente du registre")
	}
	if !d.ExigeSuperadmin {
		t.Fatal("certificate.delete n'exige pas l'appartenance au groupe protégé : " +
			"n'importe quel délégué pourrait interrompre LDAPS")
	}
	if d.Portee == nil {
		t.Error("certificate.delete sans portée")
	}
}
