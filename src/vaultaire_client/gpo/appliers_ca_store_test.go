package gpo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LE test de ce lot : la machine de recette du 24/09.
//
// Une Rocky 9 sur laquelle `/usr/local/share/ca-certificates` existait — un
// répertoire ordinaire sous /usr/local, que n'importe quel paquet peut créer —
// était prise pour une Debian, et l'agent lançait `update-ca-certificates`, qui
// n'y existe pas. Le module échouait sur « commande introuvable », sans dire
// quelle distribution avait été supposée.

// avecMagasins substitue la liste des magasins et la détection de commande, et
// rend la fonction qui remet tout en place.
func avecMagasins(t *testing.T, magasins []magasinCA, presentes map[string]bool) {
	t.Helper()
	ancienneListe := caStorePaths
	ancienneDetection := commandExists

	caStorePaths = magasins
	commandExists = func(nom string) bool { return presentes[nom] }

	t.Cleanup(func() {
		caStorePaths = ancienneListe
		commandExists = ancienneDetection
	})
}

// magasinsDeTest rend deux familles dont les répertoires vivent sous racine.
func magasinsDeTest(racine string) []magasinCA {
	return []magasinCA{
		{"Debian/Ubuntu", filepath.Join(racine, "debian"), ".crt", []string{"update-ca-certificates"}},
		{"RHEL/Rocky", filepath.Join(racine, "rocky"), ".pem", []string{"update-ca-trust", "extract"}},
	}
}

func TestUneRockyAvecLeRepertoireDebianResteUneRocky(t *testing.T) {
	racine := t.TempDir()
	magasins := magasinsDeTest(racine)

	// Les DEUX répertoires existent — c'est le cas qui piégeait —, mais seule
	// la commande RHEL est installée.
	for _, m := range magasins {
		if err := os.MkdirAll(m.dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	avecMagasins(t, magasins, map[string]bool{"update-ca-trust": true})

	store, ok := detectCAStore()
	if !ok {
		t.Fatal("aucun magasin detecte alors que update-ca-trust est present")
	}
	if store.refresh[0] != "update-ca-trust" {
		t.Errorf("commande %q : c'est la presence du REPERTOIRE qui a decide, "+
			"pas celle de la commande", store.refresh[0])
	}
	if store.suffix != ".pem" {
		t.Errorf("suffixe %q : le mauvais magasin a ete retenu", store.suffix)
	}
}

// Le répertoire garde un rôle : départager deux familles dont les deux
// commandes sont là, ce qui arrive sur une machine où l'on a installé les
// outils de l'autre distribution.
func TestLeRepertoireDepartageQuandLesDeuxCommandesExistent(t *testing.T) {
	racine := t.TempDir()
	magasins := magasinsDeTest(racine)
	if err := os.MkdirAll(magasins[1].dir, 0o755); err != nil {
		t.Fatal(err)
	}
	avecMagasins(t, magasins, map[string]bool{"update-ca-certificates": true, "update-ca-trust": true})

	store, ok := detectCAStore()
	if !ok {
		t.Fatal("aucun magasin detecte")
	}
	if store.famille != "RHEL/Rocky" {
		t.Errorf("famille %q : le repertoire present devait departager", store.famille)
	}
}

// Commande présente, répertoire absent : la machine sait faire, on crée le
// répertoire d'ancrage plutôt que de refuser.
func TestUnRepertoireDAncrageManquantEstCree(t *testing.T) {
	racine := t.TempDir()
	magasins := magasinsDeTest(racine)
	avecMagasins(t, magasins, map[string]bool{"update-ca-trust": true})

	store, ok := detectCAStore()
	if !ok {
		t.Fatal("magasin refuse alors que la commande existe")
	}
	if store.famille != "RHEL/Rocky" {
		t.Fatalf("famille %q", store.famille)
	}
	if info, err := os.Stat(store.dir); err != nil || !info.IsDir() {
		t.Errorf("le repertoire d'ancrage %s n'a pas ete cree", store.dir)
	}
}

// Aucune commande : on refuse. Retourner un magasin par défaut — ce que faisait
// la version précédente — faisait écrire un fichier dans un répertoire dont la
// régénération échouerait juste après.
func TestSansAucuneCommandeLeMagasinEstRefuse(t *testing.T) {
	racine := t.TempDir()
	magasins := magasinsDeTest(racine)
	for _, m := range magasins {
		if err := os.MkdirAll(m.dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	avecMagasins(t, magasins, map[string]bool{})

	if _, ok := detectCAStore(); ok {
		t.Error("un magasin a ete retenu alors qu'aucune commande de regeneration n'existe")
	}
}

// L'échec doit nommer ce qui a été cherché : un « aucun magasin reconnu » nu
// oblige à aller lire le code, et c'est ce qui a coûté une session de recette.
func TestLEchecNommeLesFamillesCherchees(t *testing.T) {
	texte := famillesConnues()
	for _, attendu := range []string{"Debian", "update-ca-certificates", "RHEL", "update-ca-trust"} {
		if !contient(texte, attendu) {
			t.Errorf("le message d'echec ne mentionne pas %q : %s", attendu, texte)
		}
	}
}

func contient(s, sous string) bool { return strings.Contains(s, sous) }
