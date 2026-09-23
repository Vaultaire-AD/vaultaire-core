package gpomanager

import (
	"strconv"
	"strings"
	"testing"

	"vaultaire/core/gpo"
	"vaultaire/core/reglages"
)

// La cadence voyage en QUEUE des réponses machine, derrière un préfixe. Ces
// deux propriétés sont ce qui permet à un agent d'une version antérieure de
// continuer à lire ces trames : ce test les garde.

func lignesDe(trame string) []string { return strings.Split(trame, "\n") }

func TestLaCadenceEstEnQueueDuManifeste(t *testing.T) {
	m := gpo.Manifest{
		Scope: gpo.ScopeMachine, Version: 3, Fingerprint: "empreinte",
		ChunkCount: 2, TotalSize: 4096, ModuleCount: 7, Checksum: "somme",
	}
	lignes := lignesDe(replyManifest("cle", m))

	// Trois lignes d'en-tête (action, destination, clé) puis le manifeste : les
	// six champs doivent garder leur rang, sinon un agent ancien lit la cadence
	// à la place d'une somme de contrôle.
	attendu := []string{"05_02", "serveur_central", "cle", "3", "empreinte", "2", "4096", "7", "somme"}
	for i, a := range attendu {
		if i >= len(lignes) || lignes[i] != a {
			t.Fatalf("ligne %d = %q, attendu %q", i, lignesDe(replyManifest("cle", m))[i], a)
		}
	}

	derniere := lignes[len(lignes)-1]
	if !strings.HasPrefix(derniere, PrefixeCadence) {
		t.Fatalf("derniere ligne %q, attendu un %q", derniere, PrefixeCadence)
	}
}

// 05_03 — « rien à faire » — est le cas le plus fréquent, donc le seul chemin
// par lequel une cadence modifiée atteint un parc dont la politique ne bouge
// pas. L'oublier là rendrait le réglage inopérant sur un parc stable.
func TestLaCadencePartAussiQuandRienNeChange(t *testing.T) {
	lignes := lignesDe(replyUnchanged("cle", gpo.ScopeMachine, "", "empreinte"))
	if lignes[3] != "empreinte" {
		t.Fatalf("empreinte deplacee : %q", lignes[3])
	}
	if !strings.HasPrefix(lignes[len(lignes)-1], PrefixeCadence) {
		t.Fatalf("aucune cadence dans 05_03 : %q", lignes)
	}
}

// Le scope user n'a pas de boucle : un cycle utilisateur est déclenché par une
// ouverture de session. Y ajouter une cadence ferait croire à un réglage qui
// ne pilote rien.
func TestLeScopeUserNePorteAucuneCadence(t *testing.T) {
	m := gpo.Manifest{Scope: gpo.ScopeUser, Username: "alice", Fingerprint: "e"}
	for _, trame := range []string{
		replyManifest("cle", m),
		replyUnchanged("cle", gpo.ScopeUser, "alice", "e"),
	} {
		if strings.Contains(trame, PrefixeCadence) {
			t.Errorf("cadence presente en scope user : %q", trame)
		}
	}
}

// Le réglage est la SEULE source de la valeur envoyée : une constante restée
// dans le code aurait rendu le réglage muet, ce qui est le défaut que cette
// fonctionnalité corrige.
func TestLaValeurEnvoyeeVientDuReglage(t *testing.T) {
	attendu := PrefixeCadence + strconv.Itoa(reglages.Valeur(reglages.CleRafraichissementGPO))
	if got := ligneCadence(); got != attendu {
		t.Fatalf("ligneCadence() = %q, attendu %q", got, attendu)
	}
}
