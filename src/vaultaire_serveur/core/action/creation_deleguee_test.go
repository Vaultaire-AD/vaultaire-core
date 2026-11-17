package action

import (
	"errors"
	"strings"
	"testing"
)

// Création déléguée d'un compte — TO-DO 265.
//
// « Qui administre users.admin.local peut y créer des comptes, à condition de
// les placer dans un de ses groupes. » Ces tests éprouvent les trois pièces
// sans base : la portée, la clé supplémentaire, et l'annulation quand le
// rattachement échoue.

// droitsParCle accorde une clé sur une liste de domaines, et rien d'autre.
type droitsParCle struct {
	accorde map[string][]string // clé → domaines (« * » = partout)
	appels  []appelDroit
}

func (d *droitsParCle) Autorise(_ []int, cle string, domaines []string) (bool, string) {
	d.appels = append(d.appels, appelDroit{cle: cle, domaines: domaines})
	permis := d.accorde[cle]
	for _, dom := range domaines {
		ok := false
		for _, p := range permis {
			if p == "*" || p == dom {
				ok = true
			}
		}
		if !ok {
			return false, "droit manquant sur " + dom
		}
	}
	return true, "ok"
}
func (d *droitsParCle) AutoriseSurUnDomaine(g []int, cle string, dom []string) (bool, string) {
	return d.Autorise(g, cle, dom)
}
func (d *droitsParCle) AutorisePartout(_ []int, cle string) (bool, string) {
	return len(d.accorde[cle]) > 0, ""
}

func TestPorteeCreationUtilisateur(t *testing.T) {
	annuaireSimule(t, map[string][]string{
		"groupe:admin-users": {"users.admin.local"},
		"groupe:deux":        {"users.admin.local", "lyon.fr"},
	})
	cas := []struct {
		nom      string
		params   Params
		attendus []string
	}{
		{"sans groupe : global", Params{"username": "bob", "domain": "users.admin.local"}, []string{"*"}},
		{"groupe et compte du même domaine", Params{"group": "admin-users", "domain": "users.admin.local"}, []string{"users.admin.local"}},
		{"compte d'un autre domaine : les deux", Params{"group": "admin-users", "domain": "autre.fr"}, []string{"users.admin.local", "autre.fr"}},
		{"groupe à deux domaines : les deux", Params{"group": "deux", "domain": "users.admin.local"}, []string{"users.admin.local", "lyon.fr"}},
		{"groupe sans domaine : global", Params{"group": "inconnu", "domain": "users.admin.local"}, []string{"*"}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			got, err := PorteeCreationUtilisateur(c.params)
			if err != nil {
				t.Fatal(err)
			}
			if !memeEnsemble(got, c.attendus) {
				t.Errorf("domaines = %v, attendus %v", got, c.attendus)
			}
		})
	}
}

func TestPorteeCreationGroupeIllisibleExigeLeGlobal(t *testing.T) {
	annuaireEnPanne(t)
	got, err := PorteeCreationUtilisateur(Params{"group": "admin-users", "domain": "users.admin.local"})
	if err != nil || len(got) != 1 || got[0] != "*" {
		t.Fatalf("got %v, %v : une lecture en échec ne doit rien accorder à un délégué", got, err)
	}
}

// Le contrôle complet, tel que la production le fait.
func TestCreationDelegueeControle(t *testing.T) {
	annuaireSimule(t, map[string][]string{
		"groupe:admin-users": {"users.admin.local"},
		"groupe:compta":      {"compta.local"},
	})
	r := NouveauRegistre()
	EnregistrerActionsUtilisateur(r)

	delegue := map[string][]string{
		"write:create:user": {"users.admin.local"},
		"write:add:user":    {"users.admin.local"},
	}
	appelant := Appelant{Username: "chef", GroupIDs: []int{7}}

	cas := []struct {
		nom     string
		accorde map[string][]string
		params  Params
		refusOK bool
		cleNom  string
	}{
		{"délégué, son groupe, son domaine", delegue,
			Params{"username": "bob", "domain": "users.admin.local", "group": "admin-users"}, false, ""},
		{"délégué, sans groupe : global exigé", delegue,
			Params{"username": "bob", "domain": "users.admin.local"}, true, "write:create:user"},
		{"délégué, groupe d'un autre domaine", delegue,
			Params{"username": "bob", "domain": "users.admin.local", "group": "compta"}, true, "write:create:user"},
		{"délégué, compte « @autre.fr » dans son groupe", delegue,
			Params{"username": "bob", "domain": "autre.fr", "group": "admin-users"}, true, "write:create:user"},
		{"création sans droit de rattacher",
			map[string][]string{"write:create:user": {"users.admin.local"}},
			Params{"username": "bob", "domain": "users.admin.local", "group": "admin-users"}, true, "write:add:user"},
		{"administrateur global, sans groupe",
			map[string][]string{"write:create:user": {"*"}},
			Params{"username": "bob", "domain": "users.admin.local"}, false, ""},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			droits := &droitsParCle{accorde: c.accorde}
			e := &Executeur{Registre: r, Droits: droits}
			_, err := e.Controler("user.create", appelant, c.params)
			if !c.refusOK {
				if err != nil {
					t.Fatalf("refusé à tort : %v", err)
				}
				return
			}
			var refus *ErrRefusee
			if !errors.As(err, &refus) {
				t.Fatalf("accepté à tort (err=%v, appels %v)", err, droits.appels)
			}
			if refus.Cle != c.cleNom {
				t.Errorf("refusé sur %q, attendu %q", refus.Cle, c.cleNom)
			}
		})
	}
}

// ClesAussi n'a de sens que sur une écriture qui a déjà sa clé.
func TestClesAussiRefuseeSurUneLecture(t *testing.T) {
	r := NouveauRegistre()
	d := actionValide("user.create", nil)
	d.UnDomaineSuffit = true
	d.ClesAussi = func(Params) []string { return []string{"write:add:user"} }
	if err := r.Enregistrer(d); err == nil || !strings.Contains(err.Error(), "ClesAussi") {
		t.Fatalf("ClesAussi + UnDomaineSuffit accepté : %v", err)
	}
}

// Un groupe inconnu est refusé AVANT la création : aucun compte orphelin.
// (L'annulation sur échec du rattachement exige une base : recette A_TESTER § 129.)
func TestGroupeInconnuAucunCompteCree(t *testing.T) {
	vraiExiste, vraiRattacher, vraiAnnuler := groupeExistePourCreation, rattacherCompteNeuf, annulerCompteNeuf
	t.Cleanup(func() {
		groupeExistePourCreation, rattacherCompteNeuf, annulerCompteNeuf = vraiExiste, vraiRattacher, vraiAnnuler
	})

	groupeExistePourCreation = func(string) (bool, error) { return false, nil }
	_, err := creerUtilisateur(Appelant{Username: "chef"},
		Params{"username": "bob", "domain": "users.admin.local", "password": "x", "group": "fantome"})
	if err == nil || !strings.Contains(err.Error(), "introuvable") {
		t.Fatalf("groupe inconnu : %v — aucun compte ne doit être créé", err)
	}
}
