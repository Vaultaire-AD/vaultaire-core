package action

import (
	"database/sql"
	"errors"
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
// Les LECTURES de domaines le sont désormais aussi — voir `portees_acces.go`.
// C'était le dernier chemin qui exigeait une base, et le plus gênant des deux :
// la portée EST le mécanisme de délégation. La règle « une écriture exige le
// droit sur TOUS les domaines de la cible » est ce qui empêche un délégué de
// Paris d'agir sur un compte à cheval sur Lyon, et elle n'était vérifiée par
// aucun test.

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

	vraiDomainesUtilisateur    = domainesDeLUtilisateur
	vraiDomainesGroupe         = domainesDuGroupe
	vraiDomainesMachine        = domainesDeLaMachine
	vraiDomainesPermissionUtil = domainesDeLaPermissionUtil
	vraiDomainesPermissionCli  = domainesDeLaPermissionCli
	vraiDomainesGPO            = domainesDeLaGPO
	vraiGroupesUtilisateur     = groupesDeLUtilisateur
	vraiDomainesGroupes        = domainesDesGroupes
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

// annuaireSimule substitue les LECTURES de domaines.
//
// `domaines` associe une clé « genre:nom » — « utilisateur:alice »,
// « groupe:paris », « permission:lecture » — aux domaines de cette entité. Une
// entité absente rend une liste vide SANS erreur : c'est le cas qui compte le
// plus, puisque c'est lui qui déclenche le repli sur « * ».
//
// Le préfixe de genre n'est pas une coquetterie : sans lui, un utilisateur et un
// groupe portant le même nom partageraient leur entrée, et un test croirait
// éprouver l'un en décrivant l'autre.
func annuaireSimule(t *testing.T, domaines map[string][]string) {
	t.Helper()

	lire := func(genre string) func(string) ([]string, error) {
		return func(nom string) ([]string, error) { return domaines[genre+":"+nom], nil }
	}

	domainesDeLUtilisateur = lire("utilisateur")
	domainesDuGroupe = lire("groupe")
	domainesDeLaMachine = lire("machine")
	domainesDeLaPermissionUtil = lire("permission")
	domainesDeLaPermissionCli = lire("permission_client")
	domainesDeLaGPO = lire("gpo")
	groupesDeLUtilisateur = func(string) ([]int, error) { return nil, nil }
	domainesDesGroupes = func([]int) ([]string, error) { return nil, nil }

	t.Cleanup(func() {
		domainesDeLUtilisateur = vraiDomainesUtilisateur
		domainesDuGroupe = vraiDomainesGroupe
		domainesDeLaMachine = vraiDomainesMachine
		domainesDeLaPermissionUtil = vraiDomainesPermissionUtil
		domainesDeLaPermissionCli = vraiDomainesPermissionCli
		domainesDeLaGPO = vraiDomainesGPO
		groupesDeLUtilisateur = vraiGroupesUtilisateur
		domainesDesGroupes = vraiDomainesGroupes
	})
}

// annuaireEnPanne fait échouer toutes les lectures de domaines.
//
// Pour éprouver le repli : une erreur de lecture ne doit pas empêcher un
// administrateur global d'agir — c'est souvent pour réparer le rattachement
// illisible qu'il intervient — mais elle ne doit rien accorder à un délégué.
func annuaireEnPanne(t *testing.T) {
	t.Helper()

	echec := func(string) ([]string, error) { return nil, errors.New("base injoignable") }

	domainesDeLUtilisateur = echec
	domainesDuGroupe = echec
	domainesDeLaMachine = echec
	domainesDeLaPermissionUtil = echec
	domainesDeLaPermissionCli = echec
	domainesDeLaGPO = echec

	t.Cleanup(func() {
		domainesDeLUtilisateur = vraiDomainesUtilisateur
		domainesDuGroupe = vraiDomainesGroupe
		domainesDeLaMachine = vraiDomainesMachine
		domainesDeLaPermissionUtil = vraiDomainesPermissionUtil
		domainesDeLaPermissionCli = vraiDomainesPermissionCli
		domainesDeLaGPO = vraiDomainesGPO
	})
}
