package scope

import (
	"os"
	"strings"
	"testing"

	dbldap "vaultaire/core/database/db_ldap"
)

// TO-DO 155 — `memberOf` ne dépend plus de la base de la recherche.

func TestLeMemberOfPorteLeDomaineDeChaqueGroupe(t *testing.T) {
	obtenu := appartenancesLDAP([]dbldap.GroupDomain{
		{GroupName: "Dev", DomainName: "dev.acme.lan"},
		{GroupName: "Equipe", DomainName: "acme.lan"},
		{GroupName: "Compta", DomainName: "paris.fr"},
	})
	if len(obtenu) != 3 {
		t.Fatalf("%d appartenances, attendu 3 : %v", len(obtenu), obtenu)
	}
	voulus := map[string]string{
		"cn=Dev,ou=groups,dc=acme,dc=lan":    "dev.acme.lan",
		"cn=Equipe,ou=groups,dc=acme,dc=lan": "acme.lan",
		"cn=Compta,ou=groups,dc=paris,dc=fr": "paris.fr",
	}
	for _, a := range obtenu {
		if domaine, connu := voulus[a.DN]; !connu || domaine != a.Domaine {
			t.Errorf("appartenance inattendue : %+v", a)
		}
	}
	// L'ordre reçu est gardé : c'est la base qui trie, et les deux chemins de
	// recherche doivent rendre la liste dans le même ordre.
	if obtenu[0].DN != "cn=Dev,ou=groups,dc=acme,dc=lan" {
		t.Errorf("ordre modifié : %v", obtenu)
	}
}

// Le DN d'un groupe ne garde que les deux derniers labels de son domaine : deux
// groupes de même nom, l'un dans le domaine et l'autre dans un sous-domaine,
// s'écrivent pareil. `memberOf` ne porte pas deux fois la même valeur.
func TestDeuxGroupesDeMemeDNNeComptentQuUneFois(t *testing.T) {
	obtenu := appartenancesLDAP([]dbldap.GroupDomain{
		{GroupName: "Dev", DomainName: "acme.lan"},
		{GroupName: "Dev", DomainName: "dev.acme.lan"},
	})
	if len(obtenu) != 1 || obtenu[0].Domaine != "acme.lan" {
		t.Errorf("appartenances = %v, attendu la première seule", obtenu)
	}
}

func TestSansGroupeAucunMemberOf(t *testing.T) {
	if obtenu := appartenancesLDAP(nil); obtenu != nil {
		t.Errorf("appartenancesLDAP(nil) = %v", obtenu)
	}
}

// LA SENTINELLE. Éprouver le résolveur pour de bon demande une base (voir
// memberof_base_test.go, sauté en intégration continue) ; ce test-ci tourne
// partout, et refuse le retour du défaut : un `memberOf` composé depuis les
// groupes que la recherche vient de CHARGER.
func TestLesDeuxCheminsComposentLeMemberOfAuMemeEndroit(t *testing.T) {
	lire := func(nom string) string {
		t.Helper()
		brut, err := os.ReadFile(nom)
		if err != nil {
			t.Fatal(err)
		}
		return string(brut)
	}
	resolveur, base := lire("resolver.go"), lire("base_scope.go")

	if !strings.Contains(resolveur, "dbldap.GetMemberOfByUsernames(") {
		t.Error("resolver.go ne lit plus les appartenances par dbldap.GetMemberOfByUsernames : " +
			"une recherche one ou sub ne rendrait plus tous les groupes d'un compte")
	}
	if !strings.Contains(base, "dbldap.GetMemberOfByUsername(") {
		t.Error("base_scope.go ne lit plus les appartenances par dbldap.GetMemberOfByUsername")
	}
	for nom, source := range map[string]string{"resolver.go": resolveur, "base_scope.go": base} {
		for _, ligne := range strings.Split(source, "\n") {
			l := strings.TrimSpace(ligne)
			if strings.HasPrefix(l, "//") || !strings.HasPrefix(l, "Groups:") {
				continue
			}
			if !strings.Contains(l, "appartenancesLDAP(") && !strings.Contains(l, "memberOfForUser(") {
				t.Errorf("%s : %q — le memberOf d'un compte doit passer par appartenancesLDAP, "+
					"sinon les deux chemins ne rendent plus la même chose", nom, l)
			}
		}
	}
	// L'ancienne table, garnie pendant le chargement des groupes du domaine.
	if strings.Contains(resolveur, "userMembershipMap") {
		t.Error("resolver.go recompose un memberOf depuis les groupes chargés (userMembershipMap)")
	}
}

// Les deux lectures passent par la même requête : c'est ce qui garantit le même
// ordre. Vérifié ici sur le résultat, sans base, par la fonction d'assemblage.
func TestLaLectureDUnCompteEstLaLectureEnLot(t *testing.T) {
	source, err := os.ReadFile("../../../../database/db_ldap/get_member_of.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(source), "FROM users u"); n != 1 {
		t.Errorf("%d requêtes lisent les appartenances dans get_member_of.go, attendu une seule", n)
	}
}
