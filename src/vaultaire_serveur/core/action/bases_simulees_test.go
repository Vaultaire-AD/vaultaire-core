package action

import (
	"database/sql"
	"testing"
)

// Substitution des accès à la base, pour les tests qui appellent une action
// directement.
//
// # Ce que cela change
//
// Plusieurs tests de ce paquet vérifient le MESSAGE rendu par une action — ce
// qu'il nomme, ce qu'il annonce comme conséquence. Ils appellent donc l'action
// pour de vrai, et l'action écrit en base. Ils exigeaient jusqu'ici une base
// vivante alors qu'ils ne mesurent qu'une chaîne de caractères.
//
// Le coût n'est pas seulement d'avoir besoin d'une base : quand elle manque,
// database.GetDatabase() rend nil et le premier Exec PANIQUE. Un panic dans un
// test ne fait pas échouer ce seul test — il fait tomber le BINAIRE de test du
// paquet. Les dizaines d'autres contrôles, matrice RBAC comprise, ne rendent
// alors plus rien. Un test qui ne mesure qu'un message ne devrait pas pouvoir
// emporter les autres.
//
// Tous les tests du paquet ne sont pas encore affranchis : ceux qui évaluent
// une PORTÉE résolvent les domaines d'une permission en base, et cette
// résolution n'est pas encore substituable. Ils restent tributaires du
// conteneur de test.

// Les vraies fonctions, saisies AVANT toute substitution.
//
// Go initialise ces variables après celles dont elles dépendent : elles portent
// donc bien les accès réels, et non le bouchon d'un test antérieur.
var (
	vraiSupprimerClient     = supprimerEnBaseClient
	vraiCreerPermUtilAdmin  = creerPermUtilAdmin
	vraiCreerPermUtilDéfaut = creerPermUtilDefaut
	vraiCreerPermClient     = creerPermClientEnBase
	vraiModifierPermClient  = modifierPermClientEnBase
)

// baseSimulee neutralise les écritures pour la durée du test.
func baseSimulee(t *testing.T) {
	t.Helper()

	supprimerEnBaseClient = func(*sql.DB, string) error { return nil }
	creerPermUtilAdmin = func(*sql.DB, string, string, string, string, string, string, string) (int64, error) {
		return 1, nil
	}
	creerPermUtilDefaut = func(*sql.DB, string, string) (int64, error) { return 1, nil }
	creerPermClientEnBase = func(*sql.DB, string, bool) (int64, error) { return 1, nil }
	modifierPermClientEnBase = func(*sql.DB, string, bool) error { return nil }

	t.Cleanup(func() {
		supprimerEnBaseClient = vraiSupprimerClient
		creerPermUtilAdmin = vraiCreerPermUtilAdmin
		creerPermUtilDefaut = vraiCreerPermUtilDéfaut
		creerPermClientEnBase = vraiCreerPermClient
		modifierPermClientEnBase = vraiModifierPermClient
	})
}
