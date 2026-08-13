package localusermanagement

import "testing"

// TestLaPlageDesGroupesNeChevauchePasCelleDesUID.
//
// LE test de ce fichier, et le seul qui garde une propriété que rien d'autre ne
// garde.
//
// Chaque compte reçoit un groupe primaire dont le GID vaut son UID : la plage
// UIDMin–UIDMax est donc entièrement consommée par des GID. Faire descendre les
// groupes du domaine dedans donnerait deux groupes différents portant le même
// numéro — et sous Unix, c'est le numéro qui décide des droits. Les fichiers du
// groupe « comptabilité » deviendraient lisibles par le compte dont l'UID tombe
// sur le même chiffre.
//
// Rien dans le compilateur ne relie ces deux plages. Ce test est ce lien.
func TestLaPlageDesGroupesNeChevauchePasCelleDesUID(t *testing.T) {
	if BaseGIDDomaine <= UIDMax {
		t.Fatalf("BaseGIDDomaine = %d, UIDMax = %d : les groupes du domaine "+
			"empiètent sur les groupes primaires des comptes, qui portent le GID "+
			"de leur UID", BaseGIDDomaine, UIDMax)
	}
	if UIDMin <= 0 || UIDMin >= UIDMax {
		t.Fatalf("plage d'UID incohérente : %d-%d", UIDMin, UIDMax)
	}
}

// TestLaRegleEstCelleDuServeur.
//
// La règle est écrite dans deux modules Go qu'aucune compilation ne relie. Ce
// test et son jumeau côté serveur (db_groups/gid_domaine_test.go) figent les
// mêmes valeurs aux deux bouts.
//
// Une divergence ne casserait rien à la compilation : le serveur annoncerait un
// groupe, l'agent le créerait avec un autre numéro que le reste du parc, et
// l'écart n'apparaîtrait qu'au premier partage NFS — sous la forme de droits qui
// ne s'appliquent pas, sans message d'erreur nulle part.
func TestLaRegleEstCelleDuServeur(t *testing.T) {
	if BaseGIDDomaine != 100000 {
		t.Errorf("BaseGIDDomaine = %d : doit rester identique au serveur", BaseGIDDomaine)
	}
	if IDGroupMax != 60000 {
		t.Errorf("IDGroupMax = %d : doit rester identique au serveur", IDGroupMax)
	}
	if GIDMaxDomaine != BaseGIDDomaine+IDGroupMax {
		t.Errorf("GIDMaxDomaine = %d, incohérent avec %d + %d",
			GIDMaxDomaine, BaseGIDDomaine, IDGroupMax)
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
				t.Errorf("%s : id_group %d accepté, GID %d — un appelant qui "+
					"ignorerait l'erreur écrirait ce numéro dans /etc/group",
					c.nom, c.idGroup, gid)
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

// TestZeroNEstJamaisRendu : le GID 0 est `root`. Un identifiant invalide qui y
// mènerait donnerait les droits du groupe root à tous les membres du groupe.
func TestZeroNEstJamaisRendu(t *testing.T) {
	for _, id := range []int{0, -1, -100000, IDGroupMax + 1, 1 << 30} {
		gid, err := GIDDeGroupe(id)
		if err == nil {
			t.Errorf("id_group %d accepté et rendu %d", id, gid)
		}
		if gid != 0 || err == nil {
			continue
		}
		// gid vaut 0 ET err est non nul : c'est le contrat attendu.
	}
}

func TestEstGIDDeDomaine(t *testing.T) {
	cas := []struct {
		gid    int
		dedans bool
	}{
		{0, false},                 // root
		{UIDMin, false},            // premier compte du domaine
		{UIDMax, false},            // dernier compte du domaine
		{BaseGIDDomaine, false},    // la base elle-même n'est le GID d'aucun groupe
		{BaseGIDDomaine + 1, true}, // id_group = 1
		{GIDMaxDomaine, true},
		{GIDMaxDomaine + 1, false},
	}
	for _, c := range cas {
		if got := EstGIDDeDomaine(c.gid); got != c.dedans {
			t.Errorf("EstGIDDeDomaine(%d) = %v, attendu %v", c.gid, got, c.dedans)
		}
	}
}
