package action

import (
	"strings"
	"testing"
)

// Tests du lot groupe.
//
// Le fil conducteur : les trois défauts systématiques de l'ancienne version web
// — paramètre vide silencieux, erreur avalée, cause devinée — venaient tous de
// la même chose, un résultat qu'on n'avait pas de moyen de rendre. Ces tests
// vérifient qu'aucun des trois ne peut revenir.

// --- inventaire et clés RBAC ------------------------------------------------

// TestActionsGroupeToutesEnregistrees fixe l'inventaire ET les clés.
//
// L'ancienne table `action → clé` vivait dans un switch séparé de l'action.
// Ici les deux sont solidaires, et ce test verrouille la correspondance : un
// changement de clé devient un changement visible, pas un effet de bord.
func TestActionsGroupeToutesEnregistrees(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsGroupe(r)

	attendues := map[string]string{
		"group.create":                   "write:create:group",
		"group.delete":                   "write:delete:group",
		"group.add_user":                 "write:add:user",
		"group.remove_user":              "write:delete:user",
		"group.add_client":               "write:add:client",
		"group.remove_client":            "write:delete:client",
		"group.add_permission":           "write:add:permission",
		"group.remove_permission":        "write:delete:permission",
		"group.add_client_permission":    "write:add:permission",
		"group.remove_client_permission": "write:delete:permission",
		"group.add_gpo":                  "write:add:gpo",
		"group.remove_gpo":               "write:delete:gpo",
		"group.set_mfa_required":         "write:mfa",
	}

	defs := r.Definitions()
	if len(defs) != len(attendues) {
		t.Fatalf("%d actions enregistrées, attendu %d", len(defs), len(attendues))
	}
	for _, d := range defs {
		cle, connue := attendues[d.Nom]
		if !connue {
			t.Errorf("action inattendue : %q", d.Nom)
			continue
		}
		if d.CleRBAC != cle {
			t.Errorf("action %q : clé %q, attendu %q", d.Nom, d.CleRBAC, cle)
		}
		if d.Portee == nil {
			t.Errorf("action %q sans portée", d.Nom)
		}
		if d.Resume == "" {
			t.Errorf("action %q sans résumé", d.Nom)
		}
	}
}

// TestRetraitDePermissionNexigePlusLaSuppressionDuGroupe.
//
// L'ancienne table web associait « remove_permission » à « write:delete:group ».
// Retirer une permission n'est pas supprimer le groupe : la clé paraissait être
// une faute de recopie, et elle est corrigée.
//
// Le test fixe la correction pour qu'une relecture distraite ne la défasse pas
// en croyant rétablir l'existant.
func TestRetraitDePermissionNexigePlusLaSuppressionDuGroupe(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsGroupe(r)

	d, ok := r.Definition("group.remove_permission")
	if !ok {
		t.Fatal("group.remove_permission absente")
	}
	if d.CleRBAC == "write:delete:group" {
		t.Fatal("retirer une permission exige encore le droit de supprimer le groupe : " +
			"deux opérations de poids très différents partagent la même clé")
	}
	if d.CleRBAC != "write:delete:permission" {
		t.Fatalf("clé %q, attendu write:delete:permission", d.CleRBAC)
	}
}

// TestCreationDeGroupeExigeLeDroitGlobal : la cible n'existe pas encore.
func TestCreationDeGroupeExigeLeDroitGlobal(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsGroupe(r)

	d, _ := r.Definition("group.create")
	domaines, err := d.Portee(Params{"group": "paris"})
	if err != nil {
		t.Fatalf("portée : %v", err)
	}
	if len(domaines) != 1 || domaines[0] != "*" {
		t.Fatalf("portée %v, attendu [*]", domaines)
	}
}

// TestPorteeDeRattachementCouvreLesDeuxEntites.
//
// Le test qui compte pour la correction d'incohérence — et que la première
// version de TestPorteeDesActionsDeRattachement ne faisait PAS : celle-ci
// vérifiait seulement que la portée n'était ni vide ni globale, ce qui passe
// aussi bien avec la portée du seul groupe. Une mutation ramenant PorteeGroupe
// n'était pas détectée.
//
// Ce qu'il faut établir est que le droit est exigé sur les domaines des DEUX
// entités : sans quoi un délégué de « paris » pourrait rattacher un compte de
// son domaine à un groupe de « lyon », et lui donner des droits sur lyon.
func TestPorteeDeRattachementCouvreLesDeuxEntites(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsGroupe(r)

	// Le stub de permission rend « dom-<nom> » pour un groupe ou un
	// utilisateur, et « dom-<id> » pour une machine.
	cas := []struct {
		action  string
		params  Params
		attendu []string
	}{
		{"group.add_user", Params{"group": "paris", "username": "alice"},
			[]string{"dom-paris", "dom-alice"}},
		{"group.remove_user", Params{"group": "paris", "username": "alice"},
			[]string{"dom-paris", "dom-alice"}},
		{"group.add_client", Params{"group": "paris", "computeur_id": "poste1"},
			[]string{"dom-paris", "dom-poste1"}},
		{"group.remove_client", Params{"group": "paris", "computeur_id": "poste1"},
			[]string{"dom-paris", "dom-poste1"}},
	}

	for _, c := range cas {
		t.Run(c.action, func(t *testing.T) {
			d, ok := r.Definition(c.action)
			if !ok {
				t.Fatalf("%s absente", c.action)
			}
			domaines, err := d.Portee(c.params)
			if err != nil {
				t.Fatalf("portée : %v", err)
			}

			presents := map[string]bool{}
			for _, dom := range domaines {
				presents[dom] = true
			}
			for _, attendu := range c.attendu {
				if !presents[attendu] {
					t.Errorf("domaine %q absent de la portée %v — "+
						"le droit ne serait pas exigé de ce côté, "+
						"un délégué pourrait agir hors de son périmètre",
						attendu, domaines)
				}
			}
		})
	}
}

// TestUnionDomainesSansDoublon.
//
// Les doublons ne fausseraient pas le contrôle, mais ils apparaîtraient dans
// les journaux de refus — où l'on cherche justement à comprendre quels domaines
// étaient exigés.
func TestUnionDomainesSansDoublon(t *testing.T) {
	got := unionDomaines([]string{"paris", "lyon"}, []string{"lyon", "nice", ""})
	if len(got) != 3 {
		t.Fatalf("union = %v, attendu 3 domaines distincts", got)
	}
	vus := map[string]int{}
	for _, d := range got {
		vus[d]++
		if d == "" {
			t.Error("domaine vide conservé dans l'union")
		}
	}
	for d, n := range vus {
		if n > 1 {
			t.Errorf("domaine %q présent %d fois", d, n)
		}
	}
}

// TestPorteeDesActionsDeRattachement.
//
// Les rattachements exigent le droit sur les domaines DU GROUPE. C'est le
// groupe qui porte les permissions et les GPO de ses membres : y ajouter
// quelqu'un revient à distribuer des droits dans ces domaines-là.
func TestPorteeDesActionsDeRattachement(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsGroupe(r)

	for _, nom := range []string{
		"group.add_user", "group.remove_user",
		"group.add_client", "group.remove_client",
		"group.add_permission", "group.remove_permission",
		"group.add_gpo", "group.remove_gpo",
		"group.set_mfa_required",
	} {
		d, ok := r.Definition(nom)
		if !ok {
			t.Fatalf("%s absente", nom)
		}
		domaines, err := d.Portee(Params{"group": "paris"})
		if err != nil {
			t.Fatalf("%s : portée en erreur : %v", nom, err)
		}
		// Le stub de permission rend « dom-<groupe> » ; ce qui compte est que
		// la portée dépende du GROUPE et non d'une valeur fixe.
		if len(domaines) == 0 {
			t.Errorf("%s : portée vide — le contrôle ne porterait sur rien", nom)
			continue
		}
		if domaines[0] == "*" {
			t.Errorf("%s : portée globale — un administrateur de domaine ne pourrait "+
				"plus gérer ses propres groupes", nom)
		}
	}
}

// --- paramètre vide : erreur, plus silence -----------------------------------

// TestParametreVideProduitUneErreur est le test du premier défaut.
//
// Sur l'ancienne version, `if u != "" && ...` faisait qu'un formulaire soumis
// sans sélection rechargeait la page à l'identique, sans un mot. L'administrateur
// ne pouvait pas savoir si l'action avait eu lieu.
func TestParametreVideProduitUneErreur(t *testing.T) {
	cas := []struct {
		nom     string
		params  Params
		attendu string
	}{
		{"utilisateur absent", Params{"group": "paris"}, "utilisateur requis"},
		{"groupe absent", Params{"username": "alice"}, "groupe requis"},
		{"les deux absents", Params{}, "groupe requis"},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			executer := rattacher("utilisateur", "username", func(string, string) error {
				t.Fatal("l'opération de base a été appelée avec un paramètre vide")
				return nil
			})
			_, err := executer(Appelant{}, c.params)
			if err == nil {
				t.Fatal("aucune erreur : le formulaire soumis à vide resterait sans réponse")
			}
			if !strings.Contains(err.Error(), c.attendu) {
				t.Fatalf("message %q, attendu contenant %q", err.Error(), c.attendu)
			}
		})
	}
}

// TestLibelleDuParametreManquantEstPrecis.
//
// « permission client requise » plutôt que « paramètre requis ». Un message
// générique oblige à ouvrir le code pour savoir quel champ remplir.
func TestLibelleDuParametreManquantEstPrecis(t *testing.T) {
	executer := rattacher("permission client", "client_permission", func(string, string) error { return nil })
	_, err := executer(Appelant{}, Params{"group": "paris"})
	if err == nil {
		t.Fatal("aucune erreur sur paramètre absent")
	}
	if !strings.Contains(err.Error(), "permission client") {
		t.Fatalf("message %q : il ne nomme pas le champ manquant", err.Error())
	}
}

// --- erreur de la base : transmise, plus avalée ------------------------------

// TestErreurDeBaseEstTransmise est le test du deuxième défaut.
//
// Pour remove_user, add_client et remove_client, l'ancienne version n'avait
// aucune branche `else` : l'échec ne produisait aucun message. L'action échouait,
// et la page affirmait le contraire par son silence.
func TestErreurDeBaseEstTransmise(t *testing.T) {
	executer := detacher("utilisateur", "username", func(string, string) error {
		return errSimulee("contrainte de clé étrangère violée")
	})

	_, err := executer(Appelant{}, Params{"group": "paris", "username": "alice"})
	if err == nil {
		t.Fatal("l'échec de la base ne produit aucune erreur : " +
			"l'action a échoué et rien ne le dit")
	}
	// Le message de la base doit apparaître : c'est lui qui distingue un groupe
	// inexistant d'une base injoignable.
	if !strings.Contains(err.Error(), "contrainte de clé étrangère") {
		t.Fatalf("message %q : l'erreur réelle de la base est perdue, "+
			"remplacée par une hypothèse", err.Error())
	}
	// Le vocabulaire d'échec attendu par rbac_fixture.sh.
	if !strings.Contains(strings.ToLower(err.Error()), "erreur") {
		t.Errorf("message %q : ne contient pas « erreur », "+
			"les scripts qui analysent la sortie ne le verraient pas comme un échec", err.Error())
	}
}

type errSimulee string

func (e errSimulee) Error() string { return string(e) }

// TestSuccesNommeLEntiteEtLeGroupe.
//
// Un message de succès qui ne nomme rien — « Utilisateur ajouté. » — laisse
// l'administrateur sans confirmation de ce qui a effectivement changé, en
// particulier après une série d'opérations.
func TestSuccesNommeLEntiteEtLeGroupe(t *testing.T) {
	executer := rattacher("utilisateur", "username", func(string, string) error { return nil })
	res, err := executer(Appelant{}, Params{"group": "paris", "username": "alice"})
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	for _, attendu := range []string{"alice", "paris"} {
		if !strings.Contains(res.Message, attendu) {
			t.Errorf("message %q : ne nomme pas %q", res.Message, attendu)
		}
	}
}

// --- ordre des arguments ----------------------------------------------------

// TestOrdreDesArgumentsPermission est le test du piège des signatures.
//
// La base inverse l'ordre entre l'ajout et le retrait :
//
//	Command_ADD_UserPermissionToGroup(db, permission, groupe)
//	Command_Remove_UserPermissionFromGroup(db, groupe, permission)
//
// Une inversion ne produit AUCUNE erreur de compilation — les deux paramètres
// sont des chaînes — et se traduit par une opération sur des entités qui
// n'existent pas, donc par un silence.
//
// Le test vérifie que les fonctions intermédiaires reçoivent bien
// (entité, groupe) dans cet ordre, quel que soit l'ordre attendu en dessous.
func TestOrdreDesArgumentsPermission(t *testing.T) {
	var vuEntite, vuGroupe string

	ajout := rattacher("permission", "permission", func(entite, groupe string) error {
		vuEntite, vuGroupe = entite, groupe
		return nil
	})
	if _, err := ajout(Appelant{}, Params{"group": "paris", "permission": "read:get:user"}); err != nil {
		t.Fatalf("ajout : %v", err)
	}
	if vuEntite != "read:get:user" || vuGroupe != "paris" {
		t.Fatalf("ajout : entité=%q groupe=%q, attendu (read:get:user, paris) — "+
			"les arguments sont inversés", vuEntite, vuGroupe)
	}

	retrait := detacher("permission", "permission", func(entite, groupe string) error {
		vuEntite, vuGroupe = entite, groupe
		return nil
	})
	if _, err := retrait(Appelant{}, Params{"group": "paris", "permission": "read:get:user"}); err != nil {
		t.Fatalf("retrait : %v", err)
	}
	if vuEntite != "read:get:user" || vuGroupe != "paris" {
		t.Fatalf("retrait : entité=%q groupe=%q, attendu (read:get:user, paris) — "+
			"l'ordre diffère entre ajout et retrait, c'est exactement le piège", vuEntite, vuGroupe)
	}
}

// --- création de groupe : le dépassement d'indice ---------------------------

// TestCreationSansDomaineRefusee reproduit le bug de la ligne de commande.
//
// L'ancienne version :
//
//	if len(command_list) < 2 { return "Erreur : ..." }
//	else { CreateGroup(db, command_list[1], command_list[2]) }
//
// La garde teste `< 2`, le corps lit l'indice 2. Avec exactement deux éléments —
// `create -g monGroupe`, sans domaine — l'accès sort du tableau et la goroutine
// panique, ce qui arrête le processus entier.
//
// Ici, le domaine absent est une erreur ordinaire.
func TestCreationSansDomaineRefusee(t *testing.T) {
	_, err := creerGroupe(Appelant{}, Params{"group": "monGroupe"})
	if err == nil {
		t.Fatal("groupe créé sans domaine")
	}
	if !strings.Contains(err.Error(), "domaine") {
		t.Fatalf("message %q : ne nomme pas le domaine manquant", err.Error())
	}
}

func TestCreationSansNomRefusee(t *testing.T) {
	if _, err := creerGroupe(Appelant{}, Params{"domain": "vaultaire.fr"}); err == nil {
		t.Fatal("groupe créé sans nom")
	}
}

// --- second facteur ---------------------------------------------------------

// TestCaseNonCocheeVautFaux.
//
// Un navigateur n'envoie PAS une case à cocher décochée : le paramètre est
// absent. Traiter l'absence comme une erreur rendrait impossible de lever le
// second facteur depuis l'interface, puisque décocher revient à ne rien envoyer.
func TestCaseNonCocheeVautFaux(t *testing.T) {
	cas := map[string]bool{
		"on": true, "true": true, "oui": true, "1": true,
		"": false, "off": false, "false": false, "non": false, "0": false,
	}
	for v, attendu := range cas {
		got, err := booleen(v)
		if err != nil {
			t.Errorf("valeur %q refusée : %v", v, err)
			continue
		}
		if got != attendu {
			t.Errorf("valeur %q → %v, attendu %v", v, got, attendu)
		}
	}

	if _, err := booleen("peut-être"); err == nil {
		t.Error("une valeur incompréhensible est acceptée : " +
			"elle vaudrait silencieusement « faux », donc lèverait le second facteur")
	}
}

// --- accord grammatical -----------------------------------------------------

// TestAccordDesMessages : détail de langue, visible à chaque opération.
//
// « Permission ajouté » se remarque, et donne le sentiment d'un produit
// approximatif — sur une interface d'administration, ce sentiment se reporte
// sur le reste.
func TestAccordDesMessages(t *testing.T) {
	cas := map[string]string{
		"permission":        "e",
		"permission client": "e",
		"machine":           "e",
		"GPO":               "e",
		"utilisateur":       "",
	}
	for libelle, attendu := range cas {
		if got := accord(libelle); got != attendu {
			t.Errorf("accord(%q) = %q, attendu %q", libelle, got, attendu)
		}
	}
}
