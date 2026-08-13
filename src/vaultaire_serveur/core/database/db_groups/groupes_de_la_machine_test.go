package dbgroups

import "testing"

// La mise en forme d'un groupe pour la trame 03_09.
//
// # Pourquoi la validation est ici et pas seulement chez l'agent
//
// L'agent revalide, et c'est indispensable — il écrit dans `/etc/group`. Mais un
// groupe que le core ne devrait pas annoncer ne doit pas partir du tout : sinon
// l'anomalie n'apparaît que dans le journal d'une machine du parc, là où personne
// ne la cherchera, au lieu du journal du core, là où elle a sa cause.

func TestLigneDeGroupe(t *testing.T) {
	cas := []struct {
		quoi   string
		groupe GroupeDuDomaine
		ligne  string
		erreur bool
	}{
		{"groupe normal", GroupeDuDomaine{Nom: "devs", IDGroup: 12}, "devs:12", false},
		{"borne haute", GroupeDuDomaine{Nom: "g", IDGroup: IDGroupMax}, "g:60000", false},
		{"nom vide", GroupeDuDomaine{Nom: "", IDGroup: 12}, "", true},
		{"identifiant nul", GroupeDuDomaine{Nom: "devs", IDGroup: 0}, "", true},
		{"identifiant négatif", GroupeDuDomaine{Nom: "devs", IDGroup: -1}, "", true},
		{"au-delà de la borne", GroupeDuDomaine{Nom: "devs", IDGroup: IDGroupMax + 1}, "", true},
		{"deux-points dans le nom", GroupeDuDomaine{Nom: "a:b", IDGroup: 12}, "", true},
		{"virgule dans le nom", GroupeDuDomaine{Nom: "a,b", IDGroup: 12}, "", true},
		{"saut de ligne dans le nom", GroupeDuDomaine{Nom: "a\nb", IDGroup: 12}, "", true},
		{"espace dans le nom", GroupeDuDomaine{Nom: "a b", IDGroup: 12}, "", true},
	}

	for _, c := range cas {
		ligne, err := LigneDeGroupe(c.groupe)
		if c.erreur {
			if err == nil {
				t.Errorf("%s : accepté et rendu %q", c.quoi, ligne)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s : %v", c.quoi, err)
			continue
		}
		if ligne != c.ligne {
			t.Errorf("%s : %q, attendu %q", c.quoi, ligne, c.ligne)
		}
	}
}

// TestLaLigneNePorteJamaisLeGID.
//
// Le réseau ne transporte que des identifiants : la règle de calcul appartient
// au code des deux côtés. Envoyer le numéro déjà calculé laisserait un serveur
// en imposer un arbitraire — dont 0, qui est `root`.
//
// Ce test constate que la ligne porte bien l'identifiant, et non le GID.
func TestLaLigneNePorteJamaisLeGID(t *testing.T) {
	ligne, err := LigneDeGroupe(GroupeDuDomaine{Nom: "devs", IDGroup: 12})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ligne != "devs:12" {
		t.Fatalf("ligne = %q, attendu %q", ligne, "devs:12")
	}

	gid, err := GIDDeGroupe(12)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ligne == "devs:100012" || gid != 100012 {
		t.Errorf("la ligne %q semble porter le GID %d au lieu de l'identifiant",
			ligne, gid)
	}
}
