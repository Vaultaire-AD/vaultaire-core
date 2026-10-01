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
	lignes := lignesDe(replyManifest("cle", "poste-1", m))

	// Trois lignes d'en-tête (action, destination, clé) puis le manifeste : les
	// six champs doivent garder leur rang, sinon un agent ancien lit la cadence
	// à la place d'une somme de contrôle.
	attendu := []string{"05_02", "serveur_central", "cle", "3", "empreinte", "2", "4096", "7", "somme"}
	for i, a := range attendu {
		if i >= len(lignes) || lignes[i] != a {
			t.Fatalf("ligne %d = %q, attendu %q", i, lignesDe(replyManifest("cle", "poste-1", m))[i], a)
		}
	}

	// La cadence est EN QUEUE — après les champs positionnels —, sans être
	// nécessairement la dernière ligne : d'autres lignes préfixées l'ont
	// rejointe depuis (voir signature.go). Ce qui compte est qu'elle ne soit
	// jamais à un RANG fixe, et qu'aucune ligne préfixée ne s'intercale avant
	// les champs que l'agent lit par position.
	if !enQueue(lignes, len(attendu), PrefixeCadence) {
		t.Fatalf("aucune ligne %q en queue du manifeste : %q", PrefixeCadence, lignes)
	}
}

// enQueue dit si une ligne préfixée figure APRÈS les champs positionnels.
func enQueue(lignes []string, positionnels int, prefixe string) bool {
	for i, l := range lignes {
		if !strings.HasPrefix(l, prefixe) {
			continue
		}
		return i >= positionnels
	}
	return false
}

// Les lignes ajoutées après coup ne doivent JAMAIS déplacer les champs que
// l'agent lit par rang. C'est la propriété qui permet à un agent d'une version
// antérieure de continuer à lire ces trames, et elle vaut pour chaque nouvelle
// ligne de queue — cadence hier, signature aujourd'hui.
func TestAucuneLigneDeQueueNeDeplaceLesChampsPositionnels(t *testing.T) {
	m := gpo.Manifest{
		Scope: gpo.ScopeMachine, Version: 3, Fingerprint: "empreinte",
		ChunkCount: 2, TotalSize: 4096, ModuleCount: 7, Checksum: "somme",
	}
	lignes := lignesDe(replyManifest("cle", "poste-1", m))

	// Trois lignes d'en-tête puis les six champs : rien de préfixé avant.
	for i := 0; i < 9 && i < len(lignes); i++ {
		for _, p := range []string{PrefixeCadence, PrefixeSignature, PrefixeSignatureExigee} {
			if strings.HasPrefix(lignes[i], p) {
				t.Fatalf("ligne %d = %q : une ligne de queue s'est intercalée dans les champs lus par rang",
					i, lignes[i])
			}
		}
	}

	// Et l'exigence de signature part TOUJOURS, y compris quand la signature
	// elle-même n'a pas pu être produite : c'est elle qui permet de constater
	// qu'un parc est prêt avant d'activer le refus.
	if !enQueue(lignes, 9, PrefixeSignatureExigee) {
		t.Errorf("aucune ligne %q dans le manifeste : %q", PrefixeSignatureExigee, lignes)
	}
}

// Le préfixe est déclaré des deux côtés du réseau et rien ne les lie à la
// compilation.
func TestLesPrefixesDeSignatureRestentCeuxDeLAgent(t *testing.T) {
	if PrefixeSignature != "sig:" {
		t.Errorf("PrefixeSignature = %q : la valeur doit rester identique à celle "+
			"de l'agent (gpo.PrefixeSignature)", PrefixeSignature)
	}
	if PrefixeSignatureExigee != "sigreq:" {
		t.Errorf("PrefixeSignatureExigee = %q : la valeur doit rester identique à "+
			"celle de l'agent (gpo.PrefixeSignatureExigee)", PrefixeSignatureExigee)
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
	// 05_03 ne porte AUCUNE ligne de signature : elle ne transporte pas de
	// politique, donc il n'y a rien à signer. En mettre une laisserait croire
	// qu'un document a été vérifié.
	for _, l := range lignes {
		if strings.HasPrefix(l, PrefixeSignature) {
			t.Errorf("signature dans une réponse « rien à faire » : %q", lignes)
		}
	}
}

// Le scope user n'a pas de boucle : un cycle utilisateur est déclenché par une
// ouverture de session. Y ajouter une cadence ferait croire à un réglage qui
// ne pilote rien.
func TestLeScopeUserNePorteAucuneCadence(t *testing.T) {
	m := gpo.Manifest{Scope: gpo.ScopeUser, Username: "alice", Fingerprint: "e"}
	for _, trame := range []string{
		replyManifest("cle", "poste-1", m),
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
