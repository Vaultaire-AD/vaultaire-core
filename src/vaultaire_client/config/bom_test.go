package config

import (
	"reflect"
	"testing"
)

// La configuration d'un poste Windows arrive souvent avec une marque d'ordre
// des octets en tête.
//
// `Set-Content -Encoding UTF8` de Windows PowerShell 5.1 en ajoute une, et le
// Bloc-notes aussi. `encoding/json` la refuse — la norme JSON ne l'autorise
// pas — et se plaint d'un « caractère invalide 'ï' », ce qui n'évoque rien pour
// personne. L'agent Windows ne lisait donc jamais sa configuration (recette du
// 24/09).
//
// L'installeur est corrigé ; ce filtre reste parce que le fichier sera rouvert
// dans un éditeur Windows pour ajouter un core, et qu'il n'y a aucune raison de
// refuser une configuration valide pour trois octets invisibles.

// Les trois octets, écrits en échappement : Go refuse un U+FEFF littéral
// ailleurs qu'en tête de fichier source.
const bom = "\xEF\xBB\xBF"

func TestUneConfigurationAvecBOMSeLit(t *testing.T) {
	p := fichier(t, bom+`{"servers":[{"ip":"10.0.0.1","port":6666}]}`)
	if err := LoadConfig(p); err != nil {
		t.Fatalf("configuration avec BOM refusée : %v", err)
	}
	if got := AdressesConnues(); !reflect.DeepEqual(got, []string{"10.0.0.1:6666"}) {
		t.Fatalf("adresses lues : %v", got)
	}
}

// Sans BOM, rien ne change : le filtre ne doit pas manger le premier caractère
// d'un fichier normal.
func TestUneConfigurationSansBOMSeLitPareil(t *testing.T) {
	p := fichier(t, `{"servers":[{"ip":"10.0.0.2","port":6667}]}`)
	if err := LoadConfig(p); err != nil {
		t.Fatal(err)
	}
	if got := AdressesConnues(); !reflect.DeepEqual(got, []string{"10.0.0.2:6667"}) {
		t.Fatalf("adresses lues : %v", got)
	}
}

// Le filtre ne retire QUE la marque de tête. Un fichier qui ne commence pas par
// elle n'est pas touché, et un JSON réellement malformé doit continuer d'être
// refusé — sinon on aurait remplacé un message obscur par un silence.
func TestUnJSONMalformeResteRefuse(t *testing.T) {
	for _, contenu := range []string{
		bom + `{"servers":`,
		`{"servers":[{"ip":`,
		bom + bom + `{"servers":[]}`, // une seule marque est retirée
	} {
		p := fichier(t, contenu)
		if err := LoadConfig(p); err == nil {
			t.Errorf("contenu %q accepté alors qu'il est malformé", contenu)
		}
	}
}
