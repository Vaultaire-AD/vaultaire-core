package scope

import (
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// LE POINT 127 : une recherche `one` rend un niveau.
//
// Elle était silencieusement promue en `sub` quand le conteneur s'appelait
// « users ». Écrit pour JumpServer ; subi par tous les autres, dont un
// administrateur qui croyait restreindre un périmètre en configurant
// `scope=one`. Ce qu'il lisait dans sa configuration ne décrivait plus ce qui lui
// était servi.

// Le réglage est livré à FAUX : `one` rend enfin ce qu'il dit.
//
// C'est le choix inverse de `MFABypass` et `RequireTLSForBind`, livrés de façon à
// ne rien casser. Assumé, et documenté : un client qui dépendait de la promotion
// voit moins d'entrées, sans erreur.
func TestLeReglageDElargissementEstLivreAFaux(t *testing.T) {
	if ldapstorage.OneLevelSubtree {
		t.Error("ldap.onelevel_subtree est livré à vrai : une recherche « one » " +
			"rendrait encore toute l'arborescence")
	}
}

// SEULE LA PORTÉE DEMANDÉE ET LE RÉGLAGE ENTRENT DANS LA DÉCISION.
//
// Ni le nom du conteneur — c'était le défaut : `ou=users` élargissait,
// `ou=people` non, et rien ne le disait — ni la forme du DN.
func TestSeulLeReglageElargit(t *testing.T) {
	original := ldapstorage.OneLevelSubtree
	defer func() { ldapstorage.OneLevelSubtree = original }()

	ldapstorage.OneLevelSubtree = false
	for _, scope := range []int{0, 1, 2} {
		if obtenu := porteeDeChargement(scope); obtenu != scope {
			t.Errorf("réglage désactivé, scope=%d chargé comme %d", scope, obtenu)
		}
	}

	ldapstorage.OneLevelSubtree = true
	if obtenu := porteeDeChargement(1); obtenu != 2 {
		t.Errorf("réglage activé, scope=1 chargé comme %d, attendu 2", obtenu)
	}
	// Et il n'élargit QUE `one` : une recherche `base` reste une recherche
	// `base`, sans quoi le réglage ferait d'un DN exact une arborescence.
	if obtenu := porteeDeChargement(0); obtenu != 0 {
		t.Errorf("réglage activé, scope=0 chargé comme %d — une recherche « base » "+
			"ne doit jamais être élargie", obtenu)
	}
	if obtenu := porteeDeChargement(2); obtenu != 2 {
		t.Errorf("réglage activé, scope=2 chargé comme %d", obtenu)
	}
}
