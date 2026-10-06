package clusterdatabase

import (
	"encoding/json"
	"testing"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// Le point 108 tient à un accord entre deux modules qui ne partagent aucun
// code : le proxy écrit la colonne `extra`, le core la relit. Ces tests portent
// sur ce contrat de format — la lecture en base, elle, est éprouvée en recette.

// LE test du point : le JSON que le proxy émet se relit ici, champ pour champ.
//
// L'échantillon est une COPIE de ce que compose `metriquesRelais` côté proxy.
// Le jour où l'un des deux change une étiquette, la vue se viderait sans qu'une
// seule erreur ne soit journalisée — c'est le genre de panne qu'on ne cherche
// pas, parce qu'une colonne vide se lit comme « rien à signaler ».
func TestLeFormatEmisParLeProxySeRelit(t *testing.T) {
	emis := `{
		"actives": 3,
		"total": 128,
		"refusees": 7,
		"rejetees": 2,
		"octets_montants": 1048576,
		"octets_descendants": 2097152,
		"relais": [
			{"nom":"ducky","type":"ducky","ecoute":"0.0.0.0:2222",
			 "actives":3,"total":128,"refusees":7,"rejetees":2,
			 "octets_ms":1048576,"octets_ds":2097152}
		]
	}`

	m, ok := decoderMetriquesRelais(emis)
	if !ok {
		t.Fatal("la mesure émise par le proxy n'est pas relue")
	}

	if m.Actives != 3 || m.Total != 128 {
		t.Errorf("connexions = %d actives / %d au total, attendu 3 / 128", m.Actives, m.Total)
	}
	if m.Ecartees() != 9 {
		t.Errorf("écartées = %d, attendu 9 (7 sans cible + 2 au plafond)", m.Ecartees())
	}
	if m.Octets() != 3145728 {
		t.Errorf("trafic = %d, attendu 3145728 (les deux sens)", m.Octets())
	}
	if len(m.Relais) != 1 {
		t.Fatalf("%d relais dans le détail, attendu 1", len(m.Relais))
	}
	r := m.Relais[0]
	if r.Nom != "ducky" || r.Ecoute != "0.0.0.0:2222" {
		t.Errorf("détail du relais = %+v", r)
	}
	if r.OctetsMontants != 1048576 || r.OctetsDescendants != 2097152 {
		t.Errorf("octets du relais = %d ↑ / %d ↓ — les étiquettes « octets_ms » et "+
			"« octets_ds » ne sont plus celles qu'écrit le proxy",
			r.OctetsMontants, r.OctetsDescendants)
	}
}

// Un champ que ce core ne connaît pas ne doit pas faire perdre la mesure.
//
// C'est la condition d'un déploiement échelonné : un proxy à jour parle à un
// core qui ne l'est pas encore, et l'inverse. Refuser la mesure entière pour un
// champ en trop viderait la vue pendant toute la montée de version.
func TestUnChampInconnuNeFaitPasPerdreLaMesure(t *testing.T) {
	m, ok := decoderMetriquesRelais(`{"actives":5,"total":9,"latence_ms":42}`)
	if !ok {
		t.Fatal("mesure rejetée à cause d'un champ inconnu")
	}
	if m.Actives != 5 || m.Total != 9 {
		t.Errorf("mesure = %d/%d, attendu 5/9", m.Actives, m.Total)
	}
}

// Une colonne vide ou illisible est IGNORÉE, pas rendue à zéro.
//
// La distinction est tout le point : une structure à zéro s'affiche « aucun
// trafic », alors qu'elle veut dire « ce core ne sait pas lire ce que ce nœud
// envoie ». C'est exactement le défaut que ce lot corrige, à l'envers.
func TestUneMesureIllisibleNEstPasUneMesureANeuf(t *testing.T) {
	for _, extra := range []string{"", "   ", "{}", "pas du json", `{"actives":`} {
		if _, ok := decoderMetriquesRelais(extra); ok {
			t.Errorf("extra %q accepté comme mesure", extra)
		}
	}
}

// Le nom de type est un mot de PROTOCOLE : il est écrit ici et dans le SDK, qui
// ne partagent aucun code. Le figer dans un test évite qu'un renommage de
// confort d'un côté ne vide la vue de l'autre — sans erreur, sans journal.
func TestLeNomDeLaMetriqueEstCeluiDuProtocole(t *testing.T) {
	if TypeMetriqueRelais != "relais" {
		t.Errorf("TypeMetriqueRelais = %q : le SDK écrit « relais » dans metric_type ; "+
			"changer ce nom d'un seul côté vide la vue en silence", TypeMetriqueRelais)
	}
}

// La structure doit rester décodable telle que le proxy la compose, y compris
// quand la mesure ne porte aucun détail par relais.
func TestUneMesureSansDetailResteValide(t *testing.T) {
	brut, err := json.Marshal(clusterstorage.MetriquesRelais{Actives: 1, Total: 2})
	if err != nil {
		t.Fatalf("encodage : %v", err)
	}
	if _, ok := decoderMetriquesRelais(string(brut)); !ok {
		t.Error("une mesure sans détail par relais est rejetée")
	}
}
