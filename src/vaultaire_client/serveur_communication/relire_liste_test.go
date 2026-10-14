package serveurcommunication

import (
	"strings"
	"testing"

	"vaultaire_client/serveur_communication/module"
)

// TO-DO 187 : la liste des nœuds est redemandée quand elle a pu changer.

func TestLaListeEstRelueALaReconnexion(t *testing.T) {
	m := motifDeRelecture(module.EtatConnexion{Adresse: "10.0.0.1:6666",
		Essayees: []string{"10.0.0.1:6666"}, Etablissements: 2})
	if m != "reconnexion" {
		t.Errorf("motif = %q, attendu « reconnexion »", m)
	}
}

// Le cas de la recette du 12/10 : le premier pair (un proxy qui a changé
// d'adresse) ne répond plus, l'agent joint le suivant.
func TestLaListeEstRelueQuandLePremierPairEstSaute(t *testing.T) {
	m := motifDeRelecture(module.EtatConnexion{Adresse: "10.0.0.9:6666",
		Essayees: []string{"10.0.0.2:6667", "10.0.0.9:6666"}, Etablissements: 1})
	if !strings.Contains(m, "10.0.0.2:6667") {
		t.Errorf("motif = %q, attendu le premier nœud nommé", m)
	}
}

// La boucle de découverte demande déjà la liste à son démarrage.
func TestLaPremiereConnexionOrdinaireNeRedemandePas(t *testing.T) {
	if m := motifDeRelecture(module.EtatConnexion{Adresse: "10.0.0.1:6666",
		Essayees: []string{"10.0.0.1:6666", "10.0.0.2:6666"}, Etablissements: 1}); m != "" {
		t.Errorf("motif = %q, attendu aucun", m)
	}
}

func TestRelireDemandeBienLaListe(t *testing.T) {
	ancien := demanderListe
	t.Cleanup(func() { demanderListe = ancien })
	n := 0
	demanderListe = func() { n++ }

	relireListeSiBesoin(module.EtatConnexion{Adresse: "a", Essayees: []string{"a"}, Etablissements: 1})
	relireListeSiBesoin(module.EtatConnexion{Adresse: "a", Essayees: []string{"a"}, Etablissements: 3})
	if n != 1 {
		t.Errorf("%d demande(s), attendu 1 : seule la reconnexion redemande", n)
	}
}
