package dbusers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// racineDuServeur remonte jusqu'au dossier qui porte go.mod.
//
// Un chemin relatif écrit en dur — « ../../.. » — se romprait au premier
// déplacement du paquet, et le test se contenterait alors de ne rien parcourir,
// donc de passer au vert sans rien mesurer.
func racineDuServeur(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("répertoire courant : %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod introuvable en remontant : le test ne parcourt rien")
		}
		dir = parent
	}
}

// fichiersGo rend tous les .go du serveur, chemin relatif à la racine.
func fichiersGo(t *testing.T) map[string]string {
	t.Helper()
	racine := racineDuServeur(t)
	out := map[string]string{}
	err := filepath.Walk(racine, func(chemin string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(chemin, ".go") {
			return nil
		}
		contenu, err := os.ReadFile(chemin)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(racine, chemin)
		out[filepath.ToSlash(rel)] = string(contenu)
		return nil
	})
	if err != nil {
		t.Fatalf("parcours des sources : %v", err)
	}
	if len(out) < 50 {
		t.Fatalf("seulement %d fichiers .go trouvés : le parcours ne voit pas les sources", len(out))
	}
	return out
}

// TestUneSeulePorteVerifieLesMotsDePasse — le garde-fou de la migration.
//
// # Ce qu'il empêche
//
// Le réencodage transparent n'a lieu qu'à l'instant d'une connexion réussie. Il
// vit donc dans VerifierMotDePasse, et nulle part ailleurs. Un chemin
// d'authentification qui lirait l'empreinte lui-même et la comparerait de son
// côté fonctionnerait parfaitement — et laisserait en SHA-256 tous les comptes
// qui passent par lui, sans que rien ne le signale.
//
// C'est le mode d'échec le plus probable de ce chantier : pas une erreur, un
// oubli. Il ne se voit ni à la compilation, ni à l'usage, ni dans les journaux.
// D'où ce contrôle sur les sources.
//
// Get_User_Password_By_ID est le point de lecture de l'empreinte : quiconque
// l'appelle est en train de vérifier un mot de passe à la main.
func TestUneSeulePorteVerifieLesMotsDePasse(t *testing.T) {
	autorises := map[string]bool{
		"core/database/db_users/get_user_password_by_id.go": true, // la définition
		"core/database/db_users/verify_password.go":         true, // la porte unique
		"core/database/db_users/verify_password_test.go":    true, // ce test
	}

	for chemin, contenu := range fichiersGo(t) {
		if autorises[chemin] {
			continue
		}
		if strings.Contains(contenu, "Get_User_Password_By_ID(") {
			t.Errorf("%s lit l'empreinte du mot de passe directement.\n"+
				"    Passer par dbusers.VerifierMotDePasse, sinon ce chemin n'assure pas le réencodage\n"+
				"    et les comptes qui l'empruntent resteront en SHA-256 indéfiniment.", chemin)
		}
	}
}

// TestAucunHachageDeMotDePasseHorsDuSocle : trois endroits produisaient
// l'empreinte, chacun avec sa copie du calcul. Les faire diverger créait des
// comptes qu'un autre chemin ne savait plus relire.
func TestAucunHachageDeMotDePasseHorsDuSocle(t *testing.T) {
	autorises := map[string]bool{
		"core/global/security/password.go":      true,
		"core/global/security/password_test.go": true,
		// Ce fichier-ci porte les motifs recherchés en clair, sans quoi il ne
		// pourrait pas les chercher.
		"core/database/db_users/verify_password_test.go": true,
	}

	for chemin, contenu := range fichiersGo(t) {
		if autorises[chemin] || !strings.Contains(contenu, "sha256.Sum256") {
			continue
		}
		// On ne cherche pas tout SHA-256 — il sert aussi aux empreintes de
		// fichiers GPO et aux clés. Seule la conjonction avec un sel de mot de
		// passe désigne un hachage d'identifiant.
		if strings.Contains(contenu, "saltedPassword") ||
			strings.Contains(contenu, "GenerateSalt") ||
			strings.Contains(contenu, "sel...") {
			t.Errorf("%s hache un mot de passe hors de core/global/security.\n"+
				"    Une seconde définition du calcul finit toujours par diverger de la première.", chemin)
		}
	}
}

// TestLeControleVoitUnAppelDirect éprouve les deux contrôles ci-dessus.
//
// Un test qui parcourt des sources à la recherche d'un motif passe au vert
// aussi bien quand tout va bien que quand il ne regarde plus au bon endroit.
// Celui-ci vérifie que le motif recherché est bien celui qui figure dans le
// code réel — et non une chaîne devenue obsolète.
func TestLeControleVoitUnAppelDirect(t *testing.T) {
	fichiers := fichiersGo(t)

	def, ok := fichiers["core/database/db_users/get_user_password_by_id.go"]
	if !ok {
		t.Fatal("get_user_password_by_id.go introuvable : le motif recherché ne désigne plus rien")
	}
	if !strings.Contains(def, "func Get_User_Password_By_ID(") {
		t.Error("Get_User_Password_By_ID a été renommée : le contrôle ne surveille plus rien")
	}

	porte, ok := fichiers["core/database/db_users/verify_password.go"]
	if !ok {
		t.Fatal("verify_password.go introuvable")
	}
	if !strings.Contains(porte, "Get_User_Password_By_ID(") {
		t.Error("la porte unique n'appelle plus la lecture : elle ne vérifie plus rien")
	}
	if !strings.Contains(porte, "security.Verifier(") {
		t.Error("la porte unique ne vérifie plus le mot de passe")
	}
	// L'APPEL, pas la déclaration. Chercher « reencoder( » tout court passerait
	// au vert sur un fichier où la fonction existe encore mais n'est plus
	// appelée — c'est-à-dire exactement le cas où la migration s'arrête. La
	// déclaration porte des types (`db *sql.DB`), l'appel porte les variables.
	if !strings.Contains(porte, "reencoder(db, userID, motDePasse)") {
		t.Error("la porte unique n'appelle plus le réencodage : " +
			"les comptes resteront en SHA-256 indéfiniment")
	}
}
