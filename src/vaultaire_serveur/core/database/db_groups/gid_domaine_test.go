package dbgroups

import "testing"

// TestLaRegleEstCelleDeLAgent.
//
// La règle de calcul du GID est écrite DEUX FOIS : ici, et dans
// `vaultaire_client/tools/local_user_management/gid_domaine.go`. Deux modules Go
// distincts, qu'aucune compilation ne relie.
//
// L'agent recalcule au lieu de recevoir le nombre, et c'est délibéré : la trame
// 03_09 ne porte que des `id_group`. Envoyer le GID déjà calculé aurait laissé un
// serveur en imposer un arbitraire — dont 0, qui est `root`.
//
// Le prix de ce choix est cette duplication. Une divergence ne casserait rien à
// la compilation : le serveur annoncerait un groupe, l'agent le créerait avec un
// numéro que le reste du parc ne partage pas, et l'écart n'apparaîtrait qu'au
// premier partage NFS — sous la forme de droits qui ne s'appliquent pas, sans
// message d'erreur nulle part. Ces valeurs sont donc figées aux deux bouts.
func TestLaRegleEstCelleDeLAgent(t *testing.T) {
	if BaseGIDDomaine != 100000 {
		t.Errorf("BaseGIDDomaine = %d : doit rester identique à l'agent", BaseGIDDomaine)
	}
	if IDGroupMax != 60000 {
		t.Errorf("IDGroupMax = %d : doit rester identique à l'agent", IDGroupMax)
	}
	if GIDMaxDomaine != BaseGIDDomaine+IDGroupMax {
		t.Errorf("GIDMaxDomaine = %d, incohérent avec %d + %d",
			GIDMaxDomaine, BaseGIDDomaine, IDGroupMax)
	}
}

// TestLaPlageEviteCelleDesComptes.
//
// Côté agent, UIDMin et UIDMax sont des constantes du même paquet et le test
// jumeau les compare directement. Ici elles n'existent pas — le serveur n'attribue
// aucun UID. La valeur est donc recopiée dans le test, et NON dans le code : ce
// qui compte est que la borne haute des comptes reste sous la base des groupes.
//
// 60000 est la valeur qu'applique le module NSS en lecture. La changer sans
// toucher à BaseGIDDomaine ferait échouer ici.
func TestLaPlageEviteCelleDesComptes(t *testing.T) {
	const uidMaxCoteAgent = 60000
	if BaseGIDDomaine <= uidMaxCoteAgent {
		t.Fatalf("BaseGIDDomaine = %d : les groupes du domaine empiéteraient sur "+
			"les groupes primaires des comptes, dont le GID vaut l'UID (jusqu'à %d)",
			BaseGIDDomaine, uidMaxCoteAgent)
	}
}

func TestGIDDeGroupe(t *testing.T) {
	cas := []struct {
		nom     string
		idGroup int
		gid     int
		erreur  bool
	}{
		{"premier groupe", 1, 100001, false},
		{"groupe courant", 42, 100042, false},
		{"borne haute", IDGroupMax, GIDMaxDomaine, false},
		{"au-delà de la borne", IDGroupMax + 1, 0, true},
		{"zéro", 0, 0, true},
		{"négatif", -1, 0, true},
	}

	for _, c := range cas {
		gid, err := GIDDeGroupe(c.idGroup)
		if c.erreur {
			if err == nil {
				t.Errorf("%s : id_group %d accepté, GID %d", c.nom, c.idGroup, gid)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s : %v", c.nom, err)
			continue
		}
		if gid != c.gid {
			t.Errorf("%s : GID = %d, attendu %d", c.nom, gid, c.gid)
		}
	}
}
