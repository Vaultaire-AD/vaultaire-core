package testrunner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La suite `vaultaire_serveur --test`, jouée par `go test ./...` — TO-DO 150.
//
// # Pourquoi
//
// Cette suite éprouve ce qu'aucun test de paquet ne voit d'un seul regard : le
// catalogue RÉEL des actions, balayé en entier — chaque clé, chaque portée,
// chaque filtre. Elle ne se lançait qu'à la main, par le binaire. Personne ne
// le faisait : elle rendait 306 sur 316, puis 307 sur 317, et les dix échecs
// étaient devenus « ceux qu'il y a toujours ».
//
// Triés, ils se rangeaient ainsi :
//
//   - un vrai défaut : deux écritures qui se contentaient d'un domaine
//     (`gpo.refresh`, `cluster.refresh_nodes`) ;
//   - deux filtres jamais éprouvés (`domain.list_groups`,
//     `revocation.get_status`) ;
//   - sept contrôles qui décrivaient un registre d'avant PorteeOuverte, ou un
//     fichier qui avait déménagé — et qui, à force d'être rouges, ne
//     regardaient plus rien.
//
// Ici, un contrôle qui échoue fait échouer `go test`, donc l'intégration
// continue, donc le prochain merge.
//
// # Sans base
//
// La partie « base » de la suite ne joue que si une connexion est ouverte, ce
// qui n'arrive pas sous `go test`. Le binaire, lui, la joue quand sa
// configuration la lui donne.
func TestLaSuiteCritiquePasse(t *testing.T) {
	resultats := Resultats()
	if len(resultats) < 300 {
		t.Fatalf("la suite n'a rendu que %d contrôles : une famille entière a cessé d'être jouée", len(resultats))
	}
	echecs := 0
	for _, r := range resultats {
		if !r.OK {
			echecs++
			t.Errorf("[FAIL] %s : %s", r.Name, r.Msg)
		}
	}
	if echecs > 0 {
		t.Errorf("%d contrôle(s) sur %d en échec", echecs, len(resultats))
	}
}

// Un contrôle ne doit pas « passer » en ayant renoncé à vérifier. Le seul qui
// en ait le droit le dit dans son nom ; sous `go test`, lancé depuis les
// sources, il n'a aucune raison de renoncer.
func TestAucunControleNeRenonce(t *testing.T) {
	for _, r := range Resultats() {
		if strings.Contains(r.Name, "NON VÉRIFIÉ") {
			t.Errorf("contrôle sauté alors que les sources sont là : %s", r.Name)
		}
	}
}

// Le contrôle « l'agent n'écrit pas lui-même le nom du fichier d'empreinte »
// ne trouve rien aujourd'hui — et c'est le bon résultat. Encore faut-il qu'il
// sache trouver : on lui donne un faux agent qui commet la faute.
func TestLaRechercheDUnNomRecopieSaitTrouver(t *testing.T) {
	racine := t.TempDir()
	ecrire := func(rel, contenu string) {
		t.Helper()
		chemin := filepath.Join(racine, rel)
		if err := os.MkdirAll(filepath.Dir(chemin), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ecrire("propre/a.go", "package a\n// le fichier core_key_fingerprint est lu par le SDK\nconst x = \"prefixe_core_key_fingerprint\"\n")
	ecrire("propre/a_test.go", "package a\nconst x = \"core_key_fingerprint\"\n")
	ecrire("notes.md", "\"core_key_fingerprint\"\n")
	if fautifs, err := sourcesQuiEcrivent(racine, "core_key_fingerprint"); err != nil || len(fautifs) != 0 {
		t.Fatalf("un commentaire, un test ou un fichier qui n'est pas du Go sont comptés : %v (%v)", fautifs, err)
	}

	ecrire("fautif/b.go", "package b\nconst Nom = \"core_key_fingerprint\"\n")
	fautifs, err := sourcesQuiEcrivent(racine, "core_key_fingerprint")
	if err != nil || len(fautifs) != 1 || fautifs[0] != filepath.Join("fautif", "b.go") {
		t.Fatalf("la copie du nom n'est pas trouvée : %v (%v)", fautifs, err)
	}
}
