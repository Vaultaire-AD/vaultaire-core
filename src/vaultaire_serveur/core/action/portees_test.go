package action

import (
	"sort"
	"strings"
	"testing"
)

// Les portées elles-mêmes, enfin éprouvables.
//
// # Ce qui n'était pas testé, et pourquoi c'est gênant
//
// La portée EST le mécanisme de délégation : elle décide sur quels domaines la
// clé est exigée. Tant que les lectures de domaines étaient appelées en dur,
// aucune de ces fonctions ne pouvait tourner sans base — et
// `database.GetDatabase()` rendant un `*sql.DB` nul, l'appel ne rendait pas une
// erreur mais PANIQUAIT, emportant le binaire de test du paquet entier.
//
// Deux règles de sécurité n'étaient donc vérifiées nulle part :
//
//   - l'UNION pour les rattachements. Ajouter un utilisateur à un groupe touche
//     les domaines des deux ; exiger le droit sur les seuls domaines de l'un
//     laisserait agir depuis un périmètre qui ne couvre pas l'autre ;
//   - le REPLI sur « * » quand la cible n'a aucun domaine. Sans lui,
//     `CheckPermissionsAllDomains` sur une liste vide n'a rien à vérifier et
//     autorise tout le monde : l'entité la moins rattachée serait la plus
//     accessible.
//
// Voir `portees_acces.go` pour la couture qui rend ces tests possibles.

func trie(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func memeEnsemble(a, b []string) bool {
	return strings.Join(trie(a), "|") == strings.Join(trie(b), "|")
}

func TestPorteesLisentLaBonneEntite(t *testing.T) {
	annuaireSimule(t, map[string][]string{
		"utilisateur:alice":       {"paris.fr"},
		"groupe:equipe":           {"lyon.fr"},
		"machine:PC-01":           {"nice.fr"},
		"permission:lecture":      {"rennes.fr"},
		"permission_client:admin": {"brest.fr"},
		"gpo:durcissement":        {"lille.fr"},
	})

	cas := []struct {
		nom      string
		portee   PorteeFunc
		params   Params
		attendus []string
	}{
		{"utilisateur", PorteeUtilisateur, Params{"username": "alice"}, []string{"paris.fr"}},
		{"groupe", PorteeGroupe, Params{"group": "equipe"}, []string{"lyon.fr"}},
		{"machine", PorteeClient, Params{"computeur_id": "PC-01"}, []string{"nice.fr"}},
		{"permission utilisateur", porteePermissionUtilisateur, Params{"permission_name": "lecture"}, []string{"rennes.fr"}},
		{"permission client", porteePermissionClient, Params{"permission_name": "admin"}, []string{"brest.fr"}},
		{"GPO", porteeGPO, Params{"gpo": "durcissement"}, []string{"lille.fr"}},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			got, err := c.portee(c.params)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if !memeEnsemble(got, c.attendus) {
				t.Errorf("domaines = %v, attendus %v", got, c.attendus)
			}
		})
	}
}

// TestRattachementExigeLUnionDesDeuxCotes.
//
// Rattacher un utilisateur à un groupe a deux effets : l'utilisateur gagne les
// droits du groupe, et le groupe distribue les siens à un membre de plus. Les
// deux périmètres sont engagés.
//
// Ne prendre que l'un des deux laisserait un délégué de `paris` verser un compte
// de `paris` dans un groupe de `lyon` — c'est-à-dire lui accorder des droits sur
// un domaine où le délégué n'a rien à faire.
func TestRattachementExigeLUnionDesDeuxCotes(t *testing.T) {
	annuaireSimule(t, map[string][]string{
		"utilisateur:alice": {"paris.fr"},
		"groupe:equipe":     {"lyon.fr"},
		"machine:PC-01":     {"nice.fr"},
	})

	got, err := PorteeGroupeEtUtilisateur(Params{"username": "alice", "group": "equipe"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !memeEnsemble(got, []string{"paris.fr", "lyon.fr"}) {
		t.Errorf("domaines = %v, attendus les deux côtés du rattachement", got)
	}

	got, err = PorteeGroupeEtClient(Params{"computeur_id": "PC-01", "group": "equipe"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !memeEnsemble(got, []string{"nice.fr", "lyon.fr"}) {
		t.Errorf("domaines = %v, attendus les deux côtés du rattachement", got)
	}
}

// TestCibleSansDomaineExigeLeDroitGlobal.
//
// LE test de ce fichier. Une entité sans domaine — un compte fraîchement créé,
// un groupe non rattaché — rend une liste vide. Or
// `CheckPermissionsAllDomains` sur une liste vide n'a RIEN à vérifier : elle
// autoriserait tout le monde.
//
// L'entité la moins rattachée serait alors la plus accessible, ce qui est
// exactement l'inverse de ce qu'on veut. Le repli sur « * » ferme cela.
func TestCibleSansDomaineExigeLeDroitGlobal(t *testing.T) {
	annuaireSimule(t, map[string][]string{}) // annuaire vide : rien n'a de domaine

	portees := map[string]struct {
		f PorteeFunc
		p Params
	}{
		"utilisateur":            {PorteeUtilisateur, Params{"username": "inconnu"}},
		"groupe":                 {PorteeGroupe, Params{"group": "inconnu"}},
		"machine":                {PorteeClient, Params{"computeur_id": "inconnue"}},
		"permission utilisateur": {porteePermissionUtilisateur, Params{"permission_name": "inconnue"}},
		"permission client":      {porteePermissionClient, Params{"permission_name": "inconnue"}},
		"GPO":                    {porteeGPO, Params{"gpo": "inconnue"}},
		"rattachement":           {PorteeGroupeEtUtilisateur, Params{"username": "x", "group": "y"}},
	}

	for nom, c := range portees {
		t.Run(nom, func(t *testing.T) {
			got, err := c.f(c.p)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(got) != 1 || got[0] != "*" {
				t.Errorf("domaines = %v, attendu [*] : une portée vide n'a rien à "+
					"vérifier, donc autoriserait tout le monde", got)
			}
		})
	}
}

// TestLectureEnPanneExigeLeDroitGlobal.
//
// Même règle, autre cause. Une erreur de lecture ne doit pas empêcher un
// administrateur global d'agir — c'est souvent pour réparer un rattachement
// illisible qu'il intervient — mais elle ne doit rien accorder à un délégué.
//
// Propager l'erreur bloquerait tout le monde ; rendre une liste vide
// autoriserait tout le monde. « * » est la seule réponse qui distingue les deux.
func TestLectureEnPanneExigeLeDroitGlobal(t *testing.T) {
	annuaireEnPanne(t)

	for nom, f := range map[string]struct {
		portee PorteeFunc
		params Params
	}{
		"utilisateur": {PorteeUtilisateur, Params{"username": "alice"}},
		"groupe":      {PorteeGroupe, Params{"group": "equipe"}},
		"machine":     {PorteeClient, Params{"computeur_id": "PC-01"}},
		"permission":  {porteePermissionUtilisateur, Params{"permission_name": "lecture"}},
	} {
		t.Run(nom, func(t *testing.T) {
			got, err := f.portee(f.params)
			if err != nil {
				t.Fatalf("erreur propagée : un administrateur global ne pourrait "+
					"plus réparer un rattachement illisible (%v)", err)
			}
			if len(got) != 1 || got[0] != "*" {
				t.Errorf("domaines = %v, attendu [*]", got)
			}
		})
	}
}

// TestPorteeLitLeBonParametre.
//
// Chaque portée lit UN nom de paramètre précis. Une action qui nommerait sa
// cible autrement recevrait une chaîne vide — donc les domaines de personne,
// donc le repli sur « * », donc une exigence de droit global là où une
// délégation devrait suffire. Le refus serait correct mais inexplicable.
func TestPorteeLitLeBonParametre(t *testing.T) {
	annuaireSimule(t, map[string][]string{
		"utilisateur:alice": {"paris.fr"},
	})

	// Le bon paramètre : la portée trouve le compte.
	got, _ := PorteeUtilisateur(Params{"username": "alice"})
	if !memeEnsemble(got, []string{"paris.fr"}) {
		t.Fatalf("domaines = %v avec le bon paramètre", got)
	}

	// Un autre nom : la portée ne trouve rien et se replie sur « * ».
	got, _ = PorteeUtilisateur(Params{"user": "alice"})
	if len(got) != 1 || got[0] != "*" {
		t.Errorf("domaines = %v avec un paramètre mal nommé, attendu [*]", got)
	}
}
