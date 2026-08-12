package webserveur

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Chaque page d'administration exige-t-elle la BONNE clé ?
//
// # Le défaut que ce fichier ferme
//
// Le registre `core/action` existe pour qu'une décision de droit soit prise à un
// seul endroit. Il ne protège que les chemins qui l'empruntent — et une page qui
// lit la base directement n'en emprunte aucun.
//
// C'est arrivé deux fois, et les deux fois de la même façon : la page a été
// écrite avant que la clé n'existe, puis la clé a été créée sans que la page
// soit reprise. Le commentaire d'origine, lui, est resté et affirmait le
// contraire de ce que le code faisait.
//
//	AdminCertificatesHandler   « web_admin only (no specific RBAC key for
//	                           certificates) » — alors que read:certificate
//	                           existait. Tout compte web_admin voyait les
//	                           certificats du serveur.
//
//	AdminEnrollHandler         « même clé RBAC que le CLI » — alors que le CLI
//	                           exigeait read:enrollment et la page
//	                           read:get:client, c'est-à-dire le droit de lire
//	                           les MACHINES, délégué par domaine.
//
// Dans les deux cas la ligne de commande refusait correctement : les deux
// façades répondaient l'inverse l'une de l'autre à la même question.
//
// # Pourquoi une inspection du TEXTE
//
// Éprouver ces pages en les appelant demanderait un serveur HTTP, une base et un
// annuaire peuplé. Ce test-là n'existerait pas. Celui-ci lit les sources et
// vérifie qu'une garde nommant la bonne clé se trouve dans le corps du
// gestionnaire — ce qui aurait suffi à attraper les deux défauts.

// gardeAttendue associe un gestionnaire à la clé qu'il DOIT nommer.
var gardeAttendue = map[string]string{
	"AdminCertificatesHandler": "ActionReadCertificate",
	"AdminEnrollHandler":       "ActionReadEnrollment",
	"AdminLogsHandler":         "ActionReadLog",
	"AdminLogsAPIHandler":      "ActionReadLog",
}

func TestChaquePageExigeSaCle(t *testing.T) {
	source := sourcesDuPaquetWeb(t)

	for gestionnaire, cle := range gardeAttendue {
		corps := corpsDeFonction(source, gestionnaire)
		if corps == "" {
			t.Errorf("%s introuvable : le test ne vérifie plus rien", gestionnaire)
			continue
		}
		if !strings.Contains(corps, "permission."+cle) {
			t.Errorf("%s ne nomme pas permission.%s : la page s'ouvrirait à qui "+
				"détient seulement web_admin, alors que la ligne de commande refuse",
				gestionnaire, cle)
		}
	}
}

// TestPageDesCertificatsPasseParLaction.
//
// La garde seule ne suffit pas : c'est un `if` qu'un remaniement peut déplacer
// sans que rien ne le signale — et c'est exactement ce qui manquait. Passer par
// l'action met la décision hors d'atteinte du remaniement, puisque l'action
// refuse quel que soit l'appelant.
func TestPageDesCertificatsPasseParLaction(t *testing.T) {
	corps := corpsDeFonction(sourcesDuPaquetWeb(t), "AdminCertificatesHandler")
	if corps == "" {
		t.Fatal("AdminCertificatesHandler introuvable")
	}

	if strings.Contains(corps, "dbcertificates.GetAllCertificates()") {
		t.Error("la liste est lue directement en base : le contrôle ne tient " +
			"plus qu'au `if` de la page. Passer par act.Executer(\"certificate.list\")")
	}
	if !strings.Contains(corps, `act.Executer("certificate.list"`) {
		t.Error("la page n'appelle pas l'action certificate.list")
	}
	if !strings.Contains(corps, `act.Defaut.Controler("certificate.list"`) {
		t.Error("la fiche d'un certificat ne passe par aucun contrôle du registre : " +
			"elle se lit par identifiant, l'action prend un nom, mais Controler " +
			"applique la même clé et la même portée sans rien exécuter")
	}
}

// --- outillage --------------------------------------------------------------

func sourcesDuPaquetWeb(t *testing.T) string {
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

// corpsDeFonction extrait le corps d'une fonction de premier niveau.
//
// L'accolade fermante en début de ligne délimite la fonction : c'est la
// convention que gofmt impose, donc un repère fiable dans du code formaté.
func corpsDeFonction(source, nom string) string {
	debut := regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(nom) + `\(`)
	loc := debut.FindStringIndex(source)
	if loc == nil {
		return ""
	}
	reste := source[loc[0]:]
	if fin := strings.Index(reste, "\n}\n"); fin >= 0 {
		return reste[:fin]
	}
	return reste
}
