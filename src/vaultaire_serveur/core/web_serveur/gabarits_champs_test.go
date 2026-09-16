package webserveur

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"vaultaire/core/gpo"
	"vaultaire/core/storage"
)

// Les gabarits nomment-ils des champs qui existent ?
//
// # Le défaut que ce fichier ferme
//
// `admin_client_detail.html` écrivait `{{ .Client.Proc }}`. Le champ s'appelle
// `Processeur` ; `Proc` est le nom du CHAMP DE FORMULAIRE, que l'action lit à la
// soumission. Les deux vocabulaires se ressemblent assez pour qu'on les
// confonde, et rien ne le signalait.
//
// Un champ inexistant ne casse pas à la compilation : `html/template` résout les
// noms par réflexion, **à l'exécution**. La page ne tombait donc qu'au moment où
// un administrateur l'ouvrait :
//
//	template: admin_client_detail.html:53:44: executing … at <.Client.Proc>:
//	can't evaluate field Proc in type *storage.Software
//
// C'est tout le contraire de ce qu'on veut d'un défaut de frappe : invisible à
// l'écriture, invisible aux tests, visible en production.
//
// # Ce que le test couvre, et ce qu'il ne couvre pas
//
// Les chaînes `.<Entité>.<Champ>` dont l'entité est passée aux gabarits sous un
// TYPE NOMMÉ — c'est là que vit ce genre de bug, sur les pages de détail. Les
// structures anonymes des gestionnaires ne sont pas atteignables par réflexion
// depuis un test ; leurs champs de premier niveau restent donc hors couverture.
//
// Un balayage plus large a été fait à la main : aucun autre nom de champ des
// gabarits n'est absent de tout le code Go. Ce test garde la partie vérifiable
// automatiquement.

// entitesDesGabarits associe le nom employé dans les gabarits au type réel que
// le gestionnaire y place.
var entitesDesGabarits = map[string]any{
	"Client":      storage.Software{},
	"User":        storage.GetUserInfoSingle{},
	"Perm":        storage.UserPermission{},
	"Certificate": storage.Certificate{},
	"Policy":      gpo.Policy{},
}

func TestGabaritsNeNommentQueDesChampsExistants(t *testing.T) {
	gabarits, err := filepath.Glob(filepath.Join(RepertoireGabarits(), "*.html"))
	if err != nil {
		t.Fatalf("lecture des gabarits : %v", err)
	}
	if len(gabarits) == 0 {
		t.Fatalf("aucun gabarit trouvé dans %s : le test ne vérifierait rien",
			RepertoireGabarits())
	}

	for entite, exemple := range entitesDesGabarits {
		typ := reflect.TypeOf(exemple)
		// `.Client.Proc` mais pas `.Client.Proc.Sub` : on ne suit qu'un niveau,
		// au-delà le type dépend du champ et l'analyse deviendrait un
		// interpréteur de gabarits.
		motif := regexp.MustCompile(`\.` + entite + `\.([A-Z]\w*)`)

		for _, chemin := range gabarits {
			contenu, err := os.ReadFile(chemin)
			if err != nil {
				t.Fatalf("lecture de %s : %v", chemin, err)
			}
			nom := filepath.Base(chemin)

			for _, m := range motif.FindAllStringSubmatch(string(contenu), -1) {
				champ := m[1]
				if _, ok := typ.FieldByName(champ); ok {
					continue
				}
				if _, ok := reflect.PointerTo(typ).MethodByName(champ); ok {
					// Une méthode exportée est utilisable en gabarit.
					continue
				}
				t.Errorf("%s : .%s.%s n'existe pas dans %s — la page tombera "+
					"à l'exécution, quand quelqu'un l'ouvrira. Champs disponibles : %s",
					nom, entite, champ, typ, champsDe(typ))
			}
		}
	}
}

// champsDe liste les champs exportés d'un type, pour que le message d'échec
// donne la correction au lieu de la faire chercher.
func champsDe(t reflect.Type) string {
	var noms []string
	for i := 0; i < t.NumField(); i++ {
		if f := t.Field(i); f.IsExported() {
			noms = append(noms, f.Name)
		}
	}
	return strings.Join(noms, ", ")
}
