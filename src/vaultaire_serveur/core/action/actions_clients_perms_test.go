package action

import (
	"strings"
	"sync"
	"testing"
)

// garnirCatalogueUneFois protège l'appel à EnregistrerTout, qui écrit dans une
// variable globale et refuse les doublons.
var garnirCatalogueUneFois sync.Once

// --- machines ---------------------------------------------------------------

func TestActionsClientToutesEnregistrees(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsClient(r)

	attendues := map[string]string{
		"client.create": "write:create:client",
		"client.update": "write:update:client",
		"client.delete": "write:delete:client",
	}
	verifierInventaire(t, r, attendues)
}

// TestInventaireNestPasEfface est le test du défaut le plus coûteux du lot.
//
// L'ancienne version web passait systématiquement les quatre valeurs du
// formulaire à UpdateHostname. Un formulaire partiel — celui qui ne corrige que
// le nom d'hôte — envoyait donc des chaînes vides pour l'OS, la RAM et le
// processeur, et les écrasait.
//
// L'inventaire disparaissait sans erreur, et personne ne faisait le lien avec
// la correction de nom d'hôte effectuée la veille.
func TestInventaireNestPasEfface(t *testing.T) {
	courant := "Rocky Linux 9"

	// Champ absent du formulaire : la valeur en base est conservée.
	if got := valeurOuCourante(Params{"hostname": "poste-12"}, "os", courant); got != courant {
		t.Fatalf("champ absent → %q, attendu %q : "+
			"un formulaire partiel effacerait l'inventaire", got, courant)
	}

	// Champ présent et vide : l'effacement est demandé, on obéit.
	if got := valeurOuCourante(Params{"os": ""}, "os", courant); got != "" {
		t.Fatalf("champ vide → %q, attendu vide : "+
			"impossible d'effacer une valeur devenue fausse", got)
	}

	// Champ renseigné : la nouvelle valeur gagne.
	if got := valeurOuCourante(Params{"os": "Debian 12"}, "os", courant); got != "Debian 12" {
		t.Fatalf("champ renseigné → %q, attendu Debian 12", got)
	}
}

// TestMessageDeSuppressionDitCeQuiResteEnPlace.
//
// « Client supprimé. » laisse croire au nettoyage du poste. Or l'agent y tourne
// toujours, avec sa clé privée et les comptes locaux qu'il a créés. Un
// administrateur qui compte sur cette action pour retirer un poste compromis se
// tromperait — et c'est précisément dans ce cas qu'il ne faut pas se tromper.
func TestMessageDeSuppressionDitCeQuiResteEnPlace(t *testing.T) {
	res, err := supprimerClient(Appelant{}, Params{"computeur_id": "ABC-123"})
	if err != nil {
		t.Fatalf("suppression : %v", err)
	}
	for _, attendu := range []string{"ABC-123", "agent reste installé"} {
		if !strings.Contains(res.Message, attendu) {
			t.Errorf("message %q : ne contient pas %q", res.Message, attendu)
		}
	}
}

func TestClientCibleVideRefusee(t *testing.T) {
	if _, err := supprimerClient(Appelant{}, Params{}); err == nil {
		t.Error("suppression acceptée sans identifiant de machine")
	}
	if _, err := modifierClient(Appelant{}, Params{}); err == nil {
		t.Error("mise à jour acceptée sans identifiant de machine")
	}
}

// --- permissions ------------------------------------------------------------

func TestActionsPermissionToutesEnregistrees(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsPermission(r)

	attendues := map[string]string{
		"permission.create":        "write:create:permission",
		"permission.delete":        "write:delete:permission",
		"client_permission.create": "write:create:permission",
		"client_permission.update": "write:update:permission",
		"client_permission.delete": "write:delete:permission",
	}
	verifierInventaire(t, r, attendues)
}

// TestNomDePermissionSansDeuxPoints.
//
// Le « : » sépare les composants d'une clé d'action — catégorie:action:objet.
// Un nom de permission qui en contient rendrait ambigus les journaux et toute
// comparaison, sans qu'aucun contrôle ne le signale aujourd'hui.
func TestNomDePermissionSansDeuxPoints(t *testing.T) {
	_, err := creerPermissionUtilisateur(Appelant{}, Params{"name": "read:get:user"})
	if err == nil {
		t.Fatal("nom de permission contenant « : » accepté")
	}
	if !strings.Contains(err.Error(), "réservé") {
		t.Errorf("message %q : n'explique pas pourquoi", err.Error())
	}

	// Un saut de ligne casserait les journaux, qui sont lus ligne par ligne.
	if _, err := creerPermissionUtilisateur(Appelant{}, Params{"name": "lecture\nfausse"}); err == nil {
		t.Error("nom de permission contenant un saut de ligne accepté")
	}
}

// TestMessageDeCreationAdminEstExplicite.
//
// « Permission créée. » ne dit pas que celle-ci ouvre l'administration. Le
// message doit nommer la conséquence, parce que c'est le moment où l'on peut
// encore revenir en arrière sans avoir rien cassé.
func TestMessageDeCreationAdminEstExplicite(t *testing.T) {
	res, err := creerPermissionUtilisateur(Appelant{Username: "alice"},
		Params{"name": "admins", "web_admin": "on"})
	if err != nil {
		t.Fatalf("création : %v", err)
	}
	if !strings.Contains(strings.ToLower(res.Message), "administration") {
		t.Fatalf("message %q : ne signale pas que la permission ouvre l'administration", res.Message)
	}

	// Sans le drapeau, le message ne doit PAS alarmer inutilement.
	ordinaire, err := creerPermissionUtilisateur(Appelant{}, Params{"name": "lecteurs"})
	if err != nil {
		t.Fatalf("création : %v", err)
	}
	if strings.Contains(strings.ToLower(ordinaire.Message), "administrer vaultaire") {
		t.Errorf("message %q : alarme sur une permission ordinaire", ordinaire.Message)
	}
}

// TestPermissionClientAdminEstSignalee : même exigence côté machines.
//
// Le cas est même moins visible : le privilège s'exerce sans qu'aucun humain
// soit identifié derrière.
func TestPermissionClientAdminEstSignalee(t *testing.T) {
	res, err := creerPermissionClient(Appelant{Username: "alice"},
		Params{"name": "postes-admin", "is_admin": "on"})
	if err != nil {
		t.Fatalf("création : %v", err)
	}
	if !strings.Contains(res.Message, "ADMIN") {
		t.Fatalf("message %q : ne signale pas le privilège accordé aux machines", res.Message)
	}
}

// TestRetraitDAdministrationEgalementTrace.
//
// Perdre un privilège explique des refus qui paraîtraient autrement
// inexplicables. Ne tracer que l'octroi laisserait le diagnostic sans point de
// départ.
func TestRetraitDAdministrationEgalementTrace(t *testing.T) {
	res, err := modifierPermissionClient(Appelant{Username: "alice"},
		Params{"permission_name": "postes-admin", "is_admin": "off"})
	if err != nil {
		t.Fatalf("mise à jour : %v", err)
	}
	if !strings.Contains(strings.ToLower(res.Message), "retirée") {
		t.Fatalf("message %q : ne dit pas que l'administration a été retirée", res.Message)
	}
}

// TestPermissionNomVideRefuse : plus de « break » silencieux.
//
// L'ancienne version faisait `if name == "" { break }` pour
// update_client_permission et delete_client_permission : le formulaire soumis
// sans nom rechargeait la page sans un mot.
func TestPermissionNomVideRefuse(t *testing.T) {
	appels := map[string]func(Appelant, Params) (Resultat, error){
		"permission.create":        creerPermissionUtilisateur,
		"permission.delete":        supprimerPermissionUtilisateur,
		"client_permission.create": creerPermissionClient,
		"client_permission.update": modifierPermissionClient,
		"client_permission.delete": supprimerPermissionClient,
	}
	for nom, f := range appels {
		t.Run(nom, func(t *testing.T) {
			if _, err := f(Appelant{}, Params{}); err == nil {
				t.Fatal("nom vide accepté : le formulaire resterait sans réponse")
			}
		})
	}
}

// TestPorteeDesPermissionsNestPasGlobalePourLaSuppression.
//
// Une permission porte des domaines : la supprimer revient à agir sur eux. Une
// portée globale laisserait un délégué de Paris supprimer une permission qui
// accorde des droits à Lyon.
func TestPorteeDesPermissionsNestPasGlobalePourLaSuppression(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsPermission(r)

	for _, nom := range []string{"permission.delete", "client_permission.delete", "client_permission.update"} {
		d, ok := r.Definition(nom)
		if !ok {
			t.Fatalf("%s absente", nom)
		}
		domaines, err := d.Portee(Params{"permission_name": "lecture"})
		if err != nil {
			t.Fatalf("%s : %v", nom, err)
		}
		if len(domaines) == 1 && domaines[0] == "*" {
			t.Errorf("%s : portée globale — un délégué ne pourrait plus gérer ses "+
				"propres permissions, ou pourrait toucher à celles des autres", nom)
		}
	}
}

// --- outil partagé ----------------------------------------------------------

func verifierInventaire(t *testing.T, r *Registre, attendues map[string]string) {
	t.Helper()

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

// TestCatalogueCompletNaPasDeDoublon.
//
// EnregistrerTout appelle les quatre enregistrements. Un nom d'action employé
// deux fois y ferait paniquer MustEnregistrer — ce test le provoque
// délibérément dans un registre neuf, plutôt que de l'apprendre au démarrage du
// serveur en production.
func TestCatalogueCompletNaPasDeDoublon(t *testing.T) {
	// EnregistrerTout et non les appels un par un : recopier la liste ici
	// ferait que ce test cesserait de couvrir un lot ajouté ailleurs, sans que
	// rien ne le signale. C'est arrivé au lot certificat, resté hors du test
	// pendant qu'il prétendait vérifier « le catalogue complet ».
	r := NouveauRegistre()
	enregistrerTousLesLots(r)

	defs := r.Definitions()
	vus := map[string]bool{}
	for _, d := range defs {
		if vus[d.Nom] {
			t.Errorf("action %q enregistrée deux fois", d.Nom)
		}
		vus[d.Nom] = true

		// Le fail-closed, vérifié sur le catalogue COMPLET et non plus lot par
		// lot : c'est l'inventaire réel du serveur.
		//
		// « Un contrôle déclaré » et non « une clé RBAC » : certaines actions
		// ne relèvent d'aucune clé — un certificat ne porte pas de domaine —
		// et sont réservées au groupe protégé. Ce que ce test doit interdire,
		// c'est l'action qui ne déclare RIEN.
		if strings.TrimSpace(d.CleRBAC) == "" && !d.ExigeSuperadmin {
			t.Errorf("action %q sans aucun contrôle déclaré dans le catalogue complet", d.Nom)
		}
		if d.Portee == nil {
			t.Errorf("action %q sans portée dans le catalogue complet", d.Nom)
		}
	}

	// 3 utilisateur + 13 groupe + 3 client + 5 permission + 1 certificat
	// + 2 enrôlement + 3 DNS + 2 clés SSH + 1 politique + 1 suppression + 1 MFA + 2 DNS
	if len(defs) != 37 {
		t.Fatalf("%d actions au catalogue, attendu 37 — "+
			"un lot a disparu de EnregistrerTout, ou en a gagné une non recensée", len(defs))
	}
}

// enregistrerTousLesLots garnit un registre de test.
//
// # Pourquoi cette fonction n'est PAS une seconde liste
//
// Une première version recopiait les appels de EnregistrerTout, et un test
// comparait les deux listes. C'était tautologique : les deux étaient écrites à
// la main, donc les faire diverger demandait exactement le même oubli des deux
// côtés — et le test aurait passé avec le lot manquant partout.
//
// Le défaut s'est produit : les lots enrôlement et DNS sont restés absents de
// cette liste alors qu'elle prétendait couvrir « tous les lots ».
//
// Elle appelle donc EnregistrerTout, la vraie, sur le catalogue partagé, puis
// recopie son contenu. Il n'y a plus qu'une liste.
func enregistrerTousLesLots(r *Registre) {
	for _, d := range catalogueDeReference().Definitions() {
		r.MustEnregistrer(d)
	}
}

// catalogueDeReference garnit le catalogue partagé une seule fois.
//
// EnregistrerTout écrit dans la variable globale Catalogue et refuse les
// doublons : deux tests qui l'appelleraient feraient paniquer le second. Le
// sync.Once rend l'appel idempotent du point de vue des tests.
func catalogueDeReference() *Registre {
	garnirCatalogueUneFois.Do(EnregistrerTout)
	return Catalogue
}

// TestCatalogueReelEstNonVideEtCoherent.
//
// Porte sur le catalogue que le SERVEUR utilisera, pas sur une reconstruction.
// C'est la différence avec le test précédent : ici, un lot oublié dans
// EnregistrerTout se voit, puisque c'est elle qu'on interroge.
func TestCatalogueReelEstNonVideEtCoherent(t *testing.T) {
	defs := catalogueDeReference().Definitions()
	if len(defs) == 0 {
		t.Fatal("catalogue vide : EnregistrerTout n'enregistre rien")
	}

	for _, d := range defs {
		if strings.TrimSpace(d.CleRBAC) == "" && !d.ExigeSuperadmin {
			t.Errorf("action %q sans aucun contrôle déclaré dans le catalogue du serveur", d.Nom)
		}
		if d.Portee == nil {
			t.Errorf("action %q sans portée dans le catalogue du serveur", d.Nom)
		}
		if d.Executer == nil {
			t.Errorf("action %q sans fonction d'exécution", d.Nom)
		}
		// Le nom doit suivre « objet.verbe » : c'est ce que les formulaires web
		// enverront et ce que les journaux afficheront. Un nom sans point
		// passerait, mais rendrait l'inventaire illisible dès qu'il grandit.
		if !strings.Contains(d.Nom, ".") {
			t.Errorf("action %q : nom attendu sous la forme « objet.verbe »", d.Nom)
		}
	}
}
