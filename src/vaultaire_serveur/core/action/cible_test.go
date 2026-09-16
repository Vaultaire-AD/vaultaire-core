package action

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Tests de la désignation de cible dans la ligne d'audit.
//
// # Ce qu'ils gardent
//
// La ligne d'audit ne vaut que par ce qu'elle nomme. « root a fait
// permission.delete sur le serveur » est syntaxiquement correcte, journalisée au
// bon niveau, et parfaitement inutile : elle ne dit pas QUELLE permission a
// disparu.
//
// C'est exactement ce qui se passait. La liste des paramètres de cible avait été
// écrite d'après le vocabulaire du modèle — « permission », « certificate »,
// « record » — et non d'après les paramètres que les actions lisent réellement,
// qui sont « permission_name », « certificate_id », « record_name ». Un mot
// d'écart, et huit actions sur les permissions plus toutes celles sur les
// certificats et le DNS journalisaient « le serveur ».
//
// Le défaut est invisible en lisant le code qui écrit la ligne : il n'apparaît
// qu'en confrontant les deux listes. TestParametresDeCibleExistentVraiment fait
// cette confrontation, et c'est le test qui compte ici.

func TestCibleDeNommeChaqueEntite(t *testing.T) {
	cas := []struct {
		nom      string
		params   Params
		attendue string
	}{
		{"utilisateur", Params{"username": "bob"}, "username bob"},
		{"groupe", Params{"group": "paris"}, "groupe paris"},
		{"machine", Params{"computeur_id": "PC-01"}, "machine PC-01"},
		{"permission par nom", Params{"permission_name": "lecture"}, "permission lecture"},
		{"permission rattachée", Params{"permission": "lecture"}, "permission lecture"},
		{"permission client", Params{"client_permission": "admin"}, "permission client admin"},
		{"GPO", Params{"gpo": "durcissement"}, "GPO durcissement"},
		{"module", Params{"module_id": "sshd"}, "module sshd"},
		{"zone", Params{"zone_name": "exemple.fr"}, "zone exemple.fr"},
		{"enregistrement", Params{"record_name": "www"}, "enregistrement www"},
		{"certificat par nom", Params{"certificate_name": "ldaps"}, "certificat ldaps"},
		{"certificat par id", Params{"certificate_id": "3"}, "certificat 3"},
		{"clé", Params{"key_id": "7"}, "clé 7"},
		{"création", Params{"name": "lecture"}, "nom lecture"},
		{"aucune cible", Params{"debug": "on"}, "le serveur"},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := cibleDe(c.params); got != c.attendue {
				t.Errorf("cibleDe(%v) = %q, attendu %q", c.params, got, c.attendue)
			}
		})
	}
}

// TestCibleDeNommeLUtilisateurDansUnRattachement.
//
// Une action de rattachement porte DEUX cibles. C'est l'utilisateur qui est
// nommé : c'est lui qui change de situation, le groupe n'étant que l'endroit où
// il entre.
func TestCibleDeNommeLUtilisateurDansUnRattachement(t *testing.T) {
	got := cibleDe(Params{"group": "paris", "username": "bob"})
	if got != "username bob" {
		t.Errorf("cibleDe = %q, attendu « username bob » : c'est l'utilisateur qui change de situation", got)
	}
}

// TestNameNePrecedePasUneCiblePlusPrecise.
//
// « name » est le paramètre de toutes les créations et ne dit pas de QUOI.
// Placé en tête de liste, il masquerait une cible plus précise présente dans la
// même requête.
func TestNameNePrecedePasUneCiblePlusPrecise(t *testing.T) {
	got := cibleDe(Params{"name": "quelque chose", "username": "bob"})
	if got != "username bob" {
		t.Errorf("cibleDe = %q : le paramètre générique « name » a masqué une cible précise", got)
	}
}

// TestParametresDeCibleExistentVraiment confronte la liste aux actions.
//
// C'est LE test de ce fichier. Il lit les sources du paquet et vérifie que
// chaque paramètre déclaré dans parametresDeCible est effectivement lu quelque
// part — par un p.Get("…") littéral, ou passé à rattacher/detacher, qui lisent
// un paramètre dont le nom est un argument.
//
// Une entrée qui ne correspond à rien est du code mort qui SE LIT comme une
// couverture : on croit la cible nommée, elle ne l'est pas, et rien ne le
// signale puisque cibleDe retombe silencieusement sur « le serveur ».
//
// L'inspection porte sur le texte des fichiers, faute de mieux : les noms de
// paramètres sont des chaînes, il n'existe aucun type qui les relie.
func TestParametresDeCibleExistentVraiment(t *testing.T) {
	source := sourcesDuPaquet(t)

	litteral := regexp.MustCompile(`p\.Get\("([a-z_]+)"\)`)
	// rattacher("permission", "permission", …) : le SECOND argument est le nom
	// du paramètre lu.
	indirect := regexp.MustCompile(`(?:rattacher|detacher)\("[^"]*",\s*"([a-z_]+)"`)

	lus := map[string]bool{}
	for _, m := range litteral.FindAllStringSubmatch(source, -1) {
		lus[m[1]] = true
	}
	for _, m := range indirect.FindAllStringSubmatch(source, -1) {
		lus[m[1]] = true
	}

	for _, c := range parametresDeCible {
		if !lus[c.param] {
			t.Errorf("parametresDeCible déclare %q, qu'aucune action ne lit : "+
				"les actions qui visent cette entité journalisent « le serveur »", c.param)
		}
	}
}

// TestCiblesConnuesDesActionsSontDeclarees fait l'inverse.
//
// Un paramètre qui désigne manifestement une entité mais qui ne figure pas dans
// parametresDeCible produit la même panne silencieuse, dans l'autre sens. La
// liste est nommée à la main : tous les paramètres ne sont pas des cibles —
// « password », « propagation » ou « ttl » n'en sont pas.
func TestCiblesConnuesDesActionsSontDeclarees(t *testing.T) {
	declares := map[string]bool{}
	for _, c := range parametresDeCible {
		declares[c.param] = true
	}

	for _, param := range []string{
		"username", "group", "computeur_id",
		"permission", "permission_name", "client_permission",
		"gpo", "module_id",
		"zone", "zone_name", "record_name",
		"certificate_id", "certificate_name", "key_id",
		"domain", "name",
	} {
		if !declares[param] {
			t.Errorf("le paramètre de cible %q n'est pas déclaré : "+
				"les actions qui le portent journalisent « le serveur »", param)
		}
	}
}

// sourcesDuPaquet concatène les fichiers Go non-test du répertoire courant.
func sourcesDuPaquet(t *testing.T) string {
	t.Helper()

	entrees, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("lecture du répertoire : %v", err)
	}

	var b strings.Builder
	for _, e := range entrees {
		nom := e.Name()
		if e.IsDir() || filepath.Ext(nom) != ".go" || strings.HasSuffix(nom, "_test.go") {
			continue
		}
		contenu, err := os.ReadFile(nom)
		if err != nil {
			t.Fatalf("lecture de %s : %v", nom, err)
		}
		b.Write(contenu)
		b.WriteByte('\n')
	}

	if b.Len() == 0 {
		t.Fatal("aucune source lue : le test ne vérifierait rien")
	}
	return b.String()
}
