package testrunner

import (
	"database/sql"
	"fmt"
	"strconv"

	"vaultaire/core/command"
	"vaultaire/core/database"
	"vaultaire/core/permission"
)

// Result indique le résultat d'un test
type Result struct {
	Name string
	OK   bool
	Msg  string
}

// Run exécute la suite de tests critiques et retourne le code de sortie (0 = succès, 1 = échec).
func Run() int {
	var results []Result

	// --- Unit: SanitizeInput ---
	results = append(results, testSanitizeInput())

	// --- Unit: SanitizeIdentifier (liste blanche) ---
	results = append(results, testSanitizeIdentifier()...)

	// --- Unit: SplitArgsPreserveBlocks ---
	results = append(results, testSplitArgs()...)

	// --- Unit: ParsePermissionContent ---
	results = append(results, testPermissionParser()...)

	// --- Unit: ExecuteCommand (sans DB: help, inconnu) ---
	results = append(results, testExecuteCommand()...)

	// --- Unit: immuabilité de l'identité d'amorçage vaultaire ---
	results = append(results, testProtectedIdentity()...)

	// --- Unit: garde-fous GPO (catalogue, scopes, chemins, restrictions, résolution) ---
	results = append(results, testGPO()...)

	// --- Unit: detection de derive et reporting de conformite GPO (05_15 a 05_17) ---
	results = append(results, testGPODrift()...)

	// --- Unit: conformite au protocole LDAP (RFC 4511/4512/4514) ---
	results = append(results, testLDAP()...)

	// --- Unit: TOTP contre les vecteurs de la RFC 6238 ---
	results = append(results, testTOTP()...)

	// --- Unit: états de la politique d'expiration des mots de passe ---
	results = append(results, testPasswordPolicy()...)

	// --- Intégration optionnelle: DB (si config chargée et connexion OK) ---
	if db := database.GetDatabase(); db != nil {
		results = append(results, testDatabase(db)...)
	}

	// Affichage et code de sortie
	passed := 0
	for _, r := range results {
		if r.OK {
			passed++
			fmt.Printf("  [PASS] %s\n", r.Name)
		} else {
			fmt.Printf("  [FAIL] %s: %s\n", r.Name, r.Msg)
		}
	}
	fmt.Printf("\n--- %d/%d tests passés ---\n", passed, len(results))
	if passed < len(results) {
		return 1
	}
	return 0
}

func testSanitizeInput() Result {
	// Entrées sûres
	if database.SanitizeInput("alice") != nil {
		return Result{"SanitizeInput(safe)", false, "alice rejeté"}
	}
	if database.SanitizeInput("user_name", "client-1") != nil {
		return Result{"SanitizeInput(safe multi)", false, "rejeté"}
	}
	// Injection
	if database.SanitizeInput("alice'; DROP TABLE users;--") == nil {
		return Result{"SanitizeInput(injection)", false, "devrait rejeter"}
	}
	if database.SanitizeInput("x\"y") == nil {
		return Result{"SanitizeInput(quote)", false, "devrait rejeter"}
	}
	return Result{"SanitizeInput", true, ""}
}

// testSanitizeIdentifier vérifie la liste blanche des identifiants.
//
// Les cas de REFUS comptent autant que les cas d'acceptation : c'est la
// séparation entre identifiant et texte libre qui est testée ici. Un
// identifiant qui accepterait un espace ou une parenthèse trahirait un retour
// à la liste noire.
func testSanitizeIdentifier() []Result {
	var out []Result

	accepte := []string{"alice", "admin@vaultaire.fr", "compta.vaultaire.fr", "poste-042", "user_name"}
	for _, v := range accepte {
		out = append(out, Result{
			"SanitizeIdentifier accepte " + v,
			database.SanitizeIdentifier(v) == nil,
			"identifiant légitime rejeté",
		})
	}

	refuse := []string{
		"alice bob",                   // espace
		"Intel(R) Core",               // parenthèses
		"groupe[1]",                   // crochets
		"a<b",                         // chevrons
		"alice'; DROP TABLE users;--", // injection classique
		"",                            // vide
		"admin\ttab",                  // caractère de contrôle
	}
	for _, v := range refuse {
		out = append(out, Result{
			"SanitizeIdentifier refuse " + strconv.Quote(v),
			database.SanitizeIdentifier(v) != nil,
			"devrait refuser",
		})
	}

	// Le texte libre reste autorisé par SanitizeInput : c'est toute la raison
	// d'avoir gardé deux fonctions. Si ces cas venaient à échouer, les mots de
	// passe, les modèles de processeur et les motifs des restrictions GPO
	// cesseraient de fonctionner.
	libre := []string{"mot de passe avec espaces", "Intel(R) Core(TM) i7", `^[a-z0-9._-]+\.service$`, "/etc/mon-app/"}
	for _, v := range libre {
		out = append(out, Result{
			"SanitizeInput accepte le texte libre " + strconv.Quote(v),
			database.SanitizeInput(v) == nil,
			"texte libre légitime rejeté",
		})
	}

	return out
}

func testSplitArgs() []Result {
	var out []Result
	// help
	args := command.SplitArgsPreserveBlocks("help")
	if len(args) != 1 || args[0] != "help" {
		out = append(out, Result{"SplitArgs(help)", false, fmt.Sprintf("got %v", args)})
	} else {
		out = append(out, Result{"SplitArgs(help)", true, ""})
	}
	// create -u user domain pass
	args = command.SplitArgsPreserveBlocks("create -u alice domain secret 01/02/1990 alice@test.com")
	if len(args) < 5 {
		out = append(out, Result{"SplitArgs(create -u)", false, fmt.Sprintf("got len=%d", len(args))})
	} else {
		out = append(out, Result{"SplitArgs(create -u)", true, ""})
	}
	// --key value
	args = command.SplitArgsPreserveBlocks("create -gpo mygpo --scope machine --desc \"durcissement SSH\"")
	if len(args) < 3 {
		out = append(out, Result{"SplitArgs(--key value)", false, fmt.Sprintf("got %v", args)})
	} else {
		out = append(out, Result{"SplitArgs(--key value)", true, ""})
	}
	return out
}

func testPermissionParser() []Result {
	var out []Result
	// nil
	p := permission.ParsePermissionContent("nil")
	if !p.Deny {
		out = append(out, Result{"ParsePermission(nil)", false, "Deny pas mis"})
	} else {
		out = append(out, Result{"ParsePermission(nil)", true, ""})
	}
	// all
	p = permission.ParsePermissionContent("all")
	if !p.All {
		out = append(out, Result{"ParsePermission(all)", false, "All pas mis"})
	} else {
		out = append(out, Result{"ParsePermission(all)", true, ""})
	}
	// (1:domain.fr)
	p = permission.ParsePermissionContent("(1:domain.fr)")
	if len(p.WithPropagation) != 1 || p.WithPropagation[0] != "domain.fr" {
		out = append(out, Result{"ParsePermission(1:domain)", false, fmt.Sprintf("got %v", p.WithPropagation)})
	} else {
		out = append(out, Result{"ParsePermission(1:domain)", true, ""})
	}
	return out
}

func testExecuteCommand() []Result {
	var out []Result
	// help
	s := command.ExecuteCommand("help", "vaultaire")
	if s == "" || len(s) < 10 {
		out = append(out, Result{"ExecuteCommand(help)", false, "réponse vide ou courte"})
	} else {
		out = append(out, Result{"ExecuteCommand(help)", true, ""})
	}
	// commande inconnue
	s = command.ExecuteCommand("inconnue_xyz", "vaultaire")
	if s == "" || len(s) < 5 {
		out = append(out, Result{"ExecuteCommand(unknown)", false, "réponse vide"})
	} else {
		out = append(out, Result{"ExecuteCommand(unknown)", true, ""})
	}
	return out
}

func testDatabase(db *sql.DB) []Result {
	var out []Result
	if db == nil {
		return out
	}
	if err := db.Ping(); err != nil {
		out = append(out, Result{"DB.Ping", false, err.Error()})
	} else {
		out = append(out, Result{"DB.Ping", true, ""})
	}
	return out
}

// RunFromMain doit être appelé depuis main quand --test est passé.
// Si la DB a été initialisée (main a fait LoadConfig + InitDatabase), les tests DB sont exécutés.
// Sinon, seuls les tests unitaires (SanitizeInput, SplitArgs, permission, commandes) sont exécutés.
func RunFromMain() int {
	fmt.Println("=== Vaultaire --test ===")
	return Run()
}
