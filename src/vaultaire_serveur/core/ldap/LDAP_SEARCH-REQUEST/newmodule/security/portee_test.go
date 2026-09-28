package security

import (
	"testing"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/permission"
)

// Le point 120 tient à une règle : une entrée n'est rendue que si l'un de SES
// rattachements est autorisé, pas seulement le domaine qui a été demandé. La
// règle s'éprouve sans base — c'est pour cela que NouvellePortee est séparée de
// la lecture des permissions.

// entrée est une entrée d'annuaire réduite à ce que le filtre regarde.
type entrée struct {
	dn       string
	domaines []string
}

func (e entrée) DN() string         { return e.dn }
func (e entrée) Domaines() []string { return e.domaines }
func (e entrée) ObjectClasses() []string {
	return []string{"inetOrgPerson"}
}
func (e entrée) GetAttribute(string) []string { return nil }
func (e entrée) GetAttributes([]string, bool) map[string][]string {
	return nil
}

const (
	parent = "enov.local"
	enfant = "admin.enov.local"
	voisin = "autre.local"
)

func parentEtEnfant() []ldapinterface.LDAPEntry {
	return []ldapinterface.LDAPEntry{
		entrée{dn: "uid=alice,ou=users,dc=enov,dc=local", domaines: []string{parent}},
		entrée{dn: "uid=bob,ou=users,dc=enov,dc=local", domaines: []string{enfant}},
	}
}

// LE test du point : sans propagation, une entrée de sous-domaine ne sort pas.
//
// C'était le défaut. Le contrôle d'accès s'évaluait une seule fois, sur le
// baseDN demandé ; le résolveur, lui, charge le domaine ET ses sous-domaines.
// Un délégué autorisé sur enov.local SANS propagation passait le contrôle, puis
// recevait les comptes de admin.enov.local — le mode « sans propagation » étant
// alors sans aucun effet, alors que c'est sa seule raison d'être.
//
// Noter les DEUX DN du jeu d'essai : ils sont IDENTIQUES au nom près. `ToRootDN`
// ne garde que les deux derniers labels, donc rien dans le DN ne distingue une
// entrée de sous-domaine. Le rattachement est la seule chose qui les sépare.
func TestSansPropagationUnSousDomaineNeSortPas(t *testing.T) {
	p := NouvellePortee([]string{"(0:" + parent + ")"})

	// Le contrôle d'entrée passe : c'est bien le domaine autorisé qui est demandé.
	if !p.Autorise(parent) {
		t.Fatalf("le domaine explicitement autorisé %q est refusé", parent)
	}

	retenues, écartées := p.Filtrer(parentEtEnfant())
	if écartées != 1 {
		t.Errorf("%d entrée(s) écartée(s), attendu 1", écartées)
	}
	if len(retenues) != 1 {
		t.Fatalf("%d entrée(s) rendue(s), attendu 1", len(retenues))
	}
	if retenues[0].Domaines()[0] != parent {
		t.Errorf("l'entrée rendue est rattachée à %q : une permission sans propagation "+
			"ne doit pas donner accès à un sous-domaine", retenues[0].Domaines())
	}
}

// AVEC propagation, le sous-domaine sort : c'est ce que « propagation » veut dire,
// et le correctif ne doit pas le casser.
//
// Sans ce test, la façon la plus simple de faire passer le précédent serait de
// refuser tout ce qui n'est pas exactement le domaine demandé — ce qui couperait
// la recherche subtree de tous les délégués du produit.
func TestAvecPropagationLeSousDomaineSort(t *testing.T) {
	p := NouvellePortee([]string{"(1:" + parent + ")"})

	retenues, écartées := p.Filtrer(parentEtEnfant())
	if écartées != 0 {
		t.Errorf("%d entrée(s) écartée(s) alors que la propagation est accordée", écartées)
	}
	if len(retenues) != 2 {
		t.Errorf("%d entrée(s) rendue(s), attendu 2", len(retenues))
	}
}

// UN COMPTE RATTACHÉ À PLUSIEURS DOMAINES sort dès que l'UN d'eux est autorisé.
//
// Un compte appartient à des groupes qui peuvent vivre dans des domaines
// différents. Exiger que TOUS soient autorisés rendrait invisible, pour un
// délégué de `enov.local`, un compte qui est pourtant membre d'un groupe de
// `enov.local` — au seul motif qu'il est aussi membre d'un groupe ailleurs.
func TestUnRattachementAutoriseSuffit(t *testing.T) {
	p := NouvellePortee([]string{"(0:" + parent + ")"})

	retenues, écartées := p.Filtrer([]ldapinterface.LDAPEntry{
		entrée{dn: "uid=carol,ou=users,dc=enov,dc=local", domaines: []string{enfant, parent}},
		entrée{dn: "uid=dave,ou=users,dc=enov,dc=local", domaines: []string{enfant, voisin}},
	})
	if len(retenues) != 1 || écartées != 1 {
		t.Fatalf("%d rendue(s) et %d écartée(s), attendu 1 et 1", len(retenues), écartées)
	}
	if retenues[0].DN() != "uid=carol,ou=users,dc=enov,dc=local" {
		t.Errorf("entrée rendue %q : c'est carol, membre d'un groupe du domaine autorisé, "+
			"qui doit sortir", retenues[0].DN())
	}
}

// « all » autorise tout, y compris un domaine sans rapport.
func TestAllAutoriseTout(t *testing.T) {
	p := NouvellePortee([]string{"all"})

	entrées := append(parentEtEnfant(),
		entrée{dn: "uid=carol,ou=users,dc=autre,dc=local", domaines: []string{voisin}})

	retenues, écartées := p.Filtrer(entrées)
	if écartées != 0 || len(retenues) != 3 {
		t.Errorf("%d rendue(s) et %d écartée(s) pour « all », attendu 3 et 0",
			len(retenues), écartées)
	}
}

// Aucune permission : rien ne sort. C'est le cas d'un compte lié sans droit de
// recherche, et celui d'une lecture de droits qui a échoué.
func TestSansPermissionRienNeSort(t *testing.T) {
	for nom, p := range map[string]*PorteeDeRecherche{
		"portée vide":    NouvellePortee(nil),
		"permission nil": NouvellePortee([]string{"nil"}),
		"portée absente": nil,
	} {
		retenues, écartées := p.Filtrer(parentEtEnfant())
		if len(retenues) != 0 {
			t.Errorf("%s : %d entrée(s) rendue(s), attendu 0", nom, len(retenues))
		}
		if écartées != 2 {
			t.Errorf("%s : %d écartée(s), attendu 2", nom, écartées)
		}
	}
}

// UN RATTACHEMENT ABSENT EST ÉCARTÉ, jamais laissé passer.
//
// C'est ce que rendrait une entrée construite sans renseigner ses rattachements —
// une UserEntry oubliée dans un futur chemin de résolution, par exemple. L'oubli
// doit rendre l'entrée invisible, pas la diffuser : c'est la différence entre un
// bogue qu'on voit et une fuite qu'on ne voit pas.
func TestUnRattachementAbsentEstEcarte(t *testing.T) {
	p := NouvellePortee([]string{"all"})

	if p.Autorise("") {
		t.Fatal("un domaine vide est autorisé, même sous « all » : une entrée dont " +
			"le rattachement n'a pas été renseigné serait diffusée à tous")
	}
	if p.AutoriseUnDes(nil) {
		t.Fatal("une entrée sans aucun rattachement est autorisée sous « all »")
	}

	retenues, écartées := p.Filtrer([]ldapinterface.LDAPEntry{
		entrée{dn: "cn=sans-rattachement", domaines: nil},
		entrée{dn: "cn=rattachement-vide", domaines: []string{""}},
	})
	if len(retenues) != 0 || écartées != 2 {
		t.Errorf("%d rendue(s), %d écartée(s) pour des entrées sans rattachement",
			len(retenues), écartées)
	}
}

// Un domaine voisin, qui n'est ni le domaine autorisé ni l'un de ses
// sous-domaines, ne passe pas — y compris quand son nom se termine par le même
// texte sans être un sous-domaine.
//
// « faux-enov.local » finit par « enov.local » : une comparaison par simple
// suffixe, sans le point, l'accepterait. C'est l'erreur classique de ce genre de
// règle, et elle donnerait accès à un domaine qu'il suffit de nommer pour
// l'obtenir.
func TestUnSuffixeNEstPasUnSousDomaine(t *testing.T) {
	p := NouvellePortee([]string{"(1:" + parent + ")"})

	for _, d := range []string{voisin, "faux-enov.local", "enov.local.attaquant.fr"} {
		if p.Autorise(d) {
			t.Errorf("le domaine %q est autorisé par une permission sur %q", d, parent)
		}
	}
}

// LA CASSE ET LE POINT FINAL ne doivent pas décider des droits.
//
// `GetGroupsUnderDomain`, qui décide des groupes CHARGÉS, compare après mise en
// minuscules et retrait d'un point final. Si le filtre comparait octet à octet,
// un groupe dont `domain_name` vaut « Admin.Enov.Local » serait chargé puis
// écarté : un compte qui le voyait avant le correctif ne le verrait plus, sans
// qu'aucun message ne dise pourquoi. Les deux comparaisons doivent s'accorder.
func TestLaCasseNeDecidePasDesDroits(t *testing.T) {
	p := NouvellePortee([]string{"(1:Enov.Local)"})

	for _, d := range []string{"enov.local", "ENOV.LOCAL", "Enov.Local", "enov.local.",
		"admin.enov.local", "Admin.Enov.Local"} {
		if !p.Autorise(d) {
			t.Errorf("%q refusé alors que la permission porte sur « Enov.Local »", d)
		}
	}

	// Et cela ne doit rien ouvrir de plus : la règle reste la même, seule
	// l'écriture est normalisée.
	if p.Autorise("AUTRE.LOCAL") {
		t.Error("« AUTRE.LOCAL » autorisé : la normalisation a élargi la règle")
	}
}

// La décision est mémorisée par domaine, et la mémorisation ne la change pas.
//
// Une recherche ramène des milliers d'entrées réparties sur une poignée de
// domaines : sans mémorisation, la liste des permissions serait ré-analysée à
// chaque entrée. Ce qui compte ici est qu'elle rende la MÊME réponse aux appels
// suivants — une mémorisation qui se trompe de clé ouvrirait un domaine sur la
// foi d'un autre.
func TestLaMemorisationNeChangePasLaDecision(t *testing.T) {
	p := NouvellePortee([]string{"(0:" + parent + ")"})

	for i := 0; i < 3; i++ {
		if !p.Autorise(parent) {
			t.Fatalf("appel %d : %q refusé alors qu'il est autorisé", i, parent)
		}
		if p.Autorise(enfant) {
			t.Fatalf("appel %d : %q autorisé alors qu'il ne l'est pas", i, enfant)
		}
		// Deux écritures du même domaine doivent donner la même réponse, quel que
		// soit l'ordre dans lequel elles arrivent.
		if !p.Autorise("ENOV.LOCAL") {
			t.Fatalf("appel %d : « ENOV.LOCAL » refusé après mémorisation de %q", i, parent)
		}
	}
}

// Plusieurs permissions se cumulent : c'est ce que rend la base pour un compte
// membre de plusieurs groupes.
func TestLesPermissionsSeCumulent(t *testing.T) {
	p := NouvellePortee([]string{"(0:" + parent + ")", "(1:" + voisin + ")"})

	if !p.Autorise(parent) {
		t.Errorf("%q refusé", parent)
	}
	if p.Autorise(enfant) {
		t.Errorf("%q autorisé : aucune des deux permissions ne le couvre", enfant)
	}
	if !p.Autorise("service." + voisin) {
		t.Errorf("un sous-domaine de %q est refusé alors que la propagation est accordée", voisin)
	}
}

// LA RÈGLE RESTE CELLE DU RBAC, et ce test est là pour l'y tenir.
//
// `decider` réécrit la règle de `permission.IsUserAuthorizedToSearch` — non par
// goût, mais parce que celle-là prend des permissions BRUTES et les analyse
// elle-même, donc ne peut pas comparer des domaines normalisés. Deux écritures
// d'une même règle finissent par diverger ; ce test compare les deux verdicts,
// cas par cas, sur des entrées déjà en minuscules où elles doivent s'accorder.
func TestLaRegleEstCelleDuRBAC(t *testing.T) {
	permissions := [][]string{
		{"all"},
		{"nil"},
		{},
		{"(0:enov.local)"},
		{"(1:enov.local)"},
		{"(1:enov.local)(0:autre.local)"},
		{"(0:enov.local)", "(1:autre.local)"},
		{"(1:a.b.c)"},
		{"(0:enov.local,autre.local)"},
	}
	domaines := []string{
		"enov.local", "admin.enov.local", "a.admin.enov.local",
		"autre.local", "service.autre.local",
		"faux-enov.local", "enov.local.attaquant.fr",
		"a.b.c", "x.a.b.c", "b.c",
	}

	for _, perms := range permissions {
		p := NouvellePortee(perms)
		for _, d := range domaines {
			nôtre := p.Autorise(d)
			leur := permission.IsUserAuthorizedToSearch(perms, d)
			if nôtre != leur {
				t.Errorf("permissions %v, domaine %q : portée dit %v, le RBAC dit %v — "+
					"les deux écritures de la règle ont divergé", perms, d, nôtre, leur)
			}
		}
	}
}

// UNE NORMALISATION NE DOIT JAMAIS ÉLARGIR UN DROIT.
//
// La première version mettait la chaîne de permission entière en minuscules,
// croyant sa grammaire faite de chiffres et de ponctuation. Elle porte aussi les
// mots-clés « all » et « nil », comparés littéralement : une valeur « ALL »
// écrite à la main en base était lue comme un « custom » sans domaine, donc
// REFUSÉE — et serait devenue « tous les domaines ».
func TestUneNormalisationNElargitAucunDroit(t *testing.T) {
	for _, brut := range []string{"ALL", "All", "aLL"} {
		p := NouvellePortee([]string{brut})
		if p.Autorise(parent) {
			t.Errorf("la permission %q autorise %q : la normalisation a transformé "+
				"une valeur non reconnue en droit total", brut, parent)
		}
		// Et le verdict reste celui du RBAC, qui refuse lui aussi.
		if permission.IsUserAuthorizedToSearch([]string{brut}, parent) {
			t.Errorf("le RBAC accepte %q : ce test ne prouve plus rien", brut)
		}
	}
}
