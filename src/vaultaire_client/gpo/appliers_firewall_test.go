package gpo

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// lireSource rend le contenu d'un fichier du paquet.
//
// Deux tests de ce fichier inspectent le TEXTE plutôt que le comportement, et
// c'est délibéré : ce que fait un module de pare-feu est une commande externe.
// Rien dans les types ne dit s'il vide une chaîne ou en retire une règle, et
// l'éprouver en vrai demanderait nftables et les droits root.
func lireSource(t *testing.T, nom string) string {
	t.Helper()
	contenu, err := os.ReadFile(nom)
	if err != nil {
		t.Fatalf("lecture de %s : %v", nom, err)
	}
	return string(contenu)
}

// La suppression d'une règle de pare-feu.
//
// # Le défaut que ces tests ferment
//
// La suppression nftables vidait la CHAÎNE ENTIÈRE — `nft flush chain` — en
// expliquant que « le prochain cycle reposera les règles actives, donc l'état
// converge ».
//
// Il ne converge pas. `apply.go` saute les modules dont l'empreinte n'a pas
// changé : un module dont rien n'a bougé n'est jamais réappliqué. Retirer UNE
// règle supprimait donc TOUTES les autres, jusqu'à ce qu'un changement sans
// rapport vienne les remettre.
//
// Rien ne le signalait : le scan de conformité ne couvre que les fichiers, pas
// les effets de commande. La machine était déclarée conforme, pare-feu ouvert.
//
// Côté firewalld, le défaut était plus discret et de même nature : le texte de
// la rich rule à retirer était composé avec le verdict de SUPPRESSION et non
// celui de la règle posée. firewalld comparant les textes mot pour mot, aucune
// règle ne correspondait — le port restait ouvert à sa source.

// TestCleDeRegleIgnoreLeVerdict.
//
// Une règle posée en « accept », puis déclarée absente alors que le module est
// passé à « deny », doit quand même se retrouver. Ce qu'on exprime est « cette
// règle de port ne doit plus exister », pas « cette règle exactement telle
// qu'elle était ».
func TestCleDeRegleIgnoreLeVerdict(t *testing.T) {
	pose := cleRegleNft("tcp", "22", "10.0.0.0/8")
	retrait := cleRegleNft("tcp", "22", "10.0.0.0/8")

	if pose != retrait {
		t.Fatalf("clé de pose %q ≠ clé de retrait %q : la règle ne se retrouvera pas", pose, retrait)
	}
	if strings.Contains(pose, "accept") || strings.Contains(pose, "drop") {
		t.Errorf("clé = %q : elle porte le verdict, donc un changement d'action "+
			"empêcherait de retrouver la règle", pose)
	}
}

// TestCleDeRegleDistingueLesRegles.
//
// Deux règles différentes ne doivent pas partager leur clé : supprimer l'une
// emporterait l'autre, ce qui est exactement le défaut qu'on corrige.
func TestCleDeRegleDistingueLesRegles(t *testing.T) {
	vues := map[string]string{}
	cas := []struct{ proto, port, source string }{
		{"tcp", "22", ""},
		{"tcp", "22", "10.0.0.0/8"},
		{"udp", "22", ""},
		{"tcp", "443", ""},
		{"tcp", "22", "192.168.0.0/16"},
	}
	for _, c := range cas {
		cle := cleRegleNft(c.proto, c.port, c.source)
		desc := c.proto + "/" + c.port + "/" + c.source
		if autre, deja := vues[cle]; deja {
			t.Errorf("clé %q partagée par %q et %q : supprimer l'une emporterait l'autre",
				cle, autre, desc)
		}
		vues[cle] = desc
	}
}

// TestSourceAbsenteNestPasConfondueAvecUneSource.
//
// « any » est écrit explicitement plutôt que laissé vide : sans lui, la clé
// d'une règle sans source se terminerait par « : » et pourrait coïncider avec
// une clé mal formée.
func TestSourceAbsenteNestPasConfondueAvecUneSource(t *testing.T) {
	sans := cleRegleNft("tcp", "22", "")
	if !strings.HasSuffix(sans, ":any") {
		t.Errorf("clé sans source = %q, attendu un suffixe explicite", sans)
	}
	if sans == cleRegleNft("tcp", "22", "any") {
		t.Log("note : une source littérale « any » collisionne avec l'absence de source — " +
			"acceptable, « any » n'est pas une adresse valide")
	}
}

// TestLectureDuHandleDepuisLeJSONDeNft.
//
// Le handle est ce qui permet de supprimer UNE règle. Il est lu dans la sortie
// JSON de nft, l'interface destinée aux programmes — analyser la sortie texte
// dépendrait d'une mise en forme que nft ne s'engage pas à conserver.
//
// L'échantillon reproduit la structure réelle : un tableau « nftables » mêlant
// métadonnées, chaîne et règles.
func TestLectureDuHandleDepuisLeJSONDeNft(t *testing.T) {
	echantillon := `{"nftables":[
      {"metainfo":{"version":"1.0.9","json_schema_version":1}},
      {"chain":{"family":"inet","table":"vaultaire_gpo","name":"input","handle":1}},
      {"rule":{"family":"inet","table":"vaultaire_gpo","chain":"input","handle":4,
               "comment":"vlt:tcp:22:any","expr":[]}},
      {"rule":{"family":"inet","table":"vaultaire_gpo","chain":"input","handle":7,
               "comment":"vlt:tcp:443:10.0.0.0/8","expr":[]}}
    ]}`

	var doc struct {
		Nftables []regleNft `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(echantillon), &doc); err != nil {
		t.Fatalf("JSON illisible : %v", err)
	}

	trouve := map[string]int{}
	for _, r := range doc.Nftables {
		if r.Rule.Comment != "" {
			trouve[r.Rule.Comment] = r.Rule.Handle
		}
	}

	if len(trouve) != 2 {
		t.Fatalf("%d règle(s) reconnue(s), attendu 2 — les entrées « metainfo » et "+
			"« chain » ne doivent pas être prises pour des règles", len(trouve))
	}
	if trouve["vlt:tcp:22:any"] != 4 {
		t.Errorf("handle de vlt:tcp:22:any = %d, attendu 4", trouve["vlt:tcp:22:any"])
	}
	if trouve["vlt:tcp:443:10.0.0.0/8"] != 7 {
		t.Errorf("handle de vlt:tcp:443:10.0.0.0/8 = %d, attendu 7", trouve["vlt:tcp:443:10.0.0.0/8"])
	}
}

// TestAucunePurgeDeChaineDansLeCode.
//
// LE test de ce fichier. La correction consiste à ne PLUS vider la chaîne ; un
// `flush chain` qui reviendrait — en repli d'erreur, par exemple — ramènerait le
// défaut sans que rien ne le distingue d'une précaution raisonnable.
//
// L'inspection porte sur le texte parce que l'effet est une commande externe :
// rien dans les types ne dit ce que le module fait au système.
func TestAucunePurgeDeChaineDansLeCode(t *testing.T) {
	source := lireSource(t, "appliers_firewall.go")

	// Les occurrences en commentaire sont tolérées : le fichier EXPLIQUE
	// pourquoi il ne purge plus, et l'interdire rendrait la raison indicible.
	for _, ligne := range strings.Split(source, "\n") {
		nue := strings.TrimSpace(ligne)
		if strings.HasPrefix(nue, "//") {
			continue
		}
		if strings.Contains(nue, `"flush"`) {
			t.Errorf("appliers_firewall.go vide encore la chaîne : %q. "+
				"Un module qui retire SA règle emporterait toutes les autres, "+
				"et apply.go ne réapplique pas les modules dont l'empreinte n'a pas changé",
				nue)
		}
	}
}

// TestLeVerdictDeLaRichRuleSuitLaction.
//
// firewalld supprime une rich rule par comparaison EXACTE de son texte : pour
// retirer une règle, il faut lui repasser mot pour mot celle qui a été posée.
//
// L'ancienne version composait le texte avec `drop`, vrai dès qu'on supprime :
// elle demandait donc de retirer une règle « reject » alors que la règle posée
// disait « accept ». Aucune ne correspondait, et le port restait ouvert.
func TestLeVerdictDeLaRichRuleSuitLaction(t *testing.T) {
	source := lireSource(t, "appliers_firewall.go")

	if strings.Contains(source, `map[bool]string{true: "reject", false: "accept"}[drop]`) {
		t.Error("le verdict de la rich rule est encore composé depuis `drop` : " +
			"la suppression ne retrouvera pas la règle posée en « accept »")
	}
}
