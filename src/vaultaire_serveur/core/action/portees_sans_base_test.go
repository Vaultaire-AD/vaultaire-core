package action

import (
	"os"
	"regexp"
	"testing"
)

// Aucune portée ne doit appeler la base en dur.
//
// # Ce que ce test garde
//
// `database.GetDatabase()` rend un `*sql.DB` NUL tant que personne ne s'est
// connecté. Un appel de méthode sur ce nil ne rend pas une erreur : il PANIQUE.
// Et une panique dans un test ne fait pas échouer ce seul test — elle emporte le
// binaire de test du paquet entier. Les dizaines d'autres contrôles, matrice
// RBAC comprise, cessent de rendre quoi que ce soit, et le compte rendu ne dit
// plus qu'un mot : « panic ».
//
// C'est un mode de panne particulièrement trompeur, parce qu'il ne désigne pas
// le coupable : le test qui a paniqué peut être le dernier ajouté, ou n'importe
// lequel des autres. On cherche alors la régression dans le code qu'on vient
// d'écrire, alors qu'elle est dans une portée touchée trois mois plus tôt.
//
// Les portées sont le dernier chemin à s'en être affranchi, et le plus important
// à garder : la portée EST le mécanisme de délégation.
//
// # Pourquoi une inspection du TEXTE
//
// Il n'existe pas d'autre moyen. Rien dans le type d'une fonction ne dit si elle
// interroge la base ; seul son corps le montre. L'inspection porte donc sur les
// sources, comme pour `cible_test.go` et `web_cles_des_pages_test.go`.

// resolveursAutorises : les seules fonctions par lesquelles une portée peut lire
// des domaines. Déclarées dans portees_acces.go, substituables par les tests.
var resolveursAutorises = map[string]bool{
	"domainesDeLUtilisateur":     true,
	"domainesDuGroupe":           true,
	"domainesDeLaMachine":        true,
	"domainesDeLaPermissionUtil": true,
	"domainesDeLaPermissionCli":  true,
	"domainesDeLaGPO":            true,
	"groupesDeLUtilisateur":      true,
	"domainesDesGroupes":         true,
}

func TestAucunePorteeNAppelleLaBaseEnDur(t *testing.T) {
	source := sourcesDuPaquet(t)

	// Une fonction de portée : son nom commence par « Portee » ou « portee », ou
	// c'est un des deux auxiliaires que les portées de permission emploient.
	estPortee := regexp.MustCompile(`^(?:P|p)ortee[A-Za-z]*$|^permissionDomaines[A-Za-z]*$`)
	// Un appel direct au paquet permission ou à une couche db*.
	appelDirect := regexp.MustCompile(`\b(permission\.Get\w+|db[a-z]+\.\w+|database\.GetDatabase)\(`)

	for nom, corps := range fonctionsDuPaquet(source) {
		if !estPortee.MatchString(nom) {
			continue
		}
		for _, m := range appelDirect.FindAllStringSubmatch(corps, -1) {
			t.Errorf("la portée %s appelle %s en dur : elle exigera une base "+
				"vivante, et paniquera sans elle — ce qui emporte le binaire de "+
				"test du paquet entier. Passez par une variable de portees_acces.go",
				nom, m[1])
		}
	}
}

// TestLesResolveursSontDeclaresAuBonEndroit.
//
// Le fichier portees_acces.go est le seul endroit où ces lectures sont nommées.
// Un résolveur déclaré ailleurs échapperait au helper de test qui les substitue,
// et le test suivant qui l'emprunterait paniquerait — sans qu'on comprenne
// pourquoi, puisque la couture *semble* en place.
func TestLesResolveursSontDeclaresAuBonEndroit(t *testing.T) {
	contenu, err := os.ReadFile("portees_acces.go")
	if err != nil {
		t.Fatalf("portees_acces.go illisible : %v", err)
	}

	// L'espacement est souple : gofmt aligne les « = » d'un bloc var sur le nom
	// le plus long, donc le nombre d'espaces dépend des voisins. Le vérifier
	// ferait échouer ce test au prochain résolveur ajouté, pour une raison qui
	// n'a rien à voir avec ce qu'il garde.
	for nom := range resolveursAutorises {
		declare := regexp.MustCompile(`\b` + regexp.QuoteMeta(nom) + `\s*=\s*permission\.`)
		if !declare.Match(contenu) {
			t.Errorf("le résolveur %s n'est pas déclaré dans portees_acces.go : "+
				"le helper de test ne le substituera pas", nom)
		}
	}
}

// fonctionsDuPaquet découpe les sources en fonctions de premier niveau.
//
// L'accolade fermante en début de ligne délimite la fonction : c'est la
// convention que gofmt impose, donc un repère fiable dans du code formaté.
func fonctionsDuPaquet(source string) map[string]string {
	out := map[string]string{}
	entete := regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?([A-Za-z_]\w*)\(`)

	positions := entete.FindAllStringSubmatchIndex(source, -1)
	for i, p := range positions {
		nom := source[p[2]:p[3]]
		fin := len(source)
		if i+1 < len(positions) {
			fin = positions[i+1][0]
		}
		out[nom] = source[p[0]:fin]
	}
	return out
}

// `sourcesDuPaquet` vit dans cible_test.go : même paquet, une seule
// implémentation pour les trois tests qui inspectent les sources.
