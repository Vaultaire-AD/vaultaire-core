package ldapstorage

import (
	"strings"
	"testing"
)

// TO-DO 145 : le filtre figure sur la ligne de journal de l'opération, sous la
// forme que l'administrateur a saisie chez son client.

func TestLeFiltreSeRelitCommeIlAEteSaisi(t *testing.T) {
	egal := func(a, v string) *LDAPFilter { return &LDAPFilter{Type: FilterEquality, Attribute: a, Value: v} }

	for attendu, f := range map[string]*LDAPFilter{
		"(uid=alice)":       egal("uid", "alice"),
		"(objectClass=*)":   {Type: FilterPresent, Attribute: "objectClass"},
		"(cn=jo*n*doe)":     {Type: FilterSubstring, Attribute: "cn", SubInitial: "jo", SubAny: []string{"n"}, SubFinal: "doe"},
		"(cn=*dupont*)":     {Type: FilterSubstring, Attribute: "cn", SubAny: []string{"dupont"}},
		"(cn=al*)":          {Type: FilterSubstring, Attribute: "cn", SubInitial: "al"},
		"(uidNumber>=1000)": {Type: FilterGreaterOrEqual, Attribute: "uidNumber", Value: "1000"},
		"(uidNumber<=2000)": {Type: FilterLessOrEqual, Attribute: "uidNumber", Value: "2000"},
		"(sn~=dupon)":       {Type: FilterApprox, Attribute: "sn", Value: "dupon"},
		"(&(objectClass=person)(|(uid=alice)(uid=bob))(!(mail=*)))": {Type: FilterAnd, SubFilters: []*LDAPFilter{
			egal("objectClass", "person"),
			{Type: FilterOr, SubFilters: []*LDAPFilter{egal("uid", "alice"), egal("uid", "bob")}},
			{Type: FilterNot, SubFilters: []*LDAPFilter{{Type: FilterPresent, Attribute: "mail"}}},
		}},
	} {
		if got := f.Texte(); got != attendu {
			t.Errorf("Texte() = %q, attendu %q", got, attendu)
		}
	}
}

// Une recherche sans filtre est une recherche sur tout : c'est ce que le
// serveur applique, et c'est ce que la ligne doit dire.
func TestUnFiltreAbsentSeLitCommeTout(t *testing.T) {
	var f *LDAPFilter
	if got := f.Texte(); got != "(objectClass=*)" {
		t.Errorf("Texte() d'un filtre nil = %q", got)
	}
}

// LE test de sécurité : ce texte vient du client et part dans un journal. Un
// retour à la ligne dans une valeur y écrirait une fausse ligne ; une
// parenthèse ferait lire un autre filtre que celui qui a été évalué.
func TestUneValeurNePeutNiForgerUneLigneNiChangerLeFiltre(t *testing.T) {
	f := &LDAPFilter{Type: FilterEquality, Attribute: "uid",
		Value: "x)(uid=*\n2026-10-03 12:00:00 [INFO    ] ldap bind: success user=admin \"\\"}

	texte := f.Texte()

	if strings.ContainsAny(texte, "\n\r\"") {
		t.Fatalf("le texte du filtre porte un retour à la ligne ou un guillemet : %q", texte)
	}
	if strings.Count(texte, "(") != 1 || strings.Count(texte, ")") != 1 {
		t.Errorf("le texte laisse lire plusieurs filtres : %q", texte)
	}
	for _, attendu := range []string{`\29`, `\28`, `\2a`, `\0a`, `\22`, `\5c`} {
		if !strings.Contains(texte, attendu) {
			t.Errorf("%s manque dans %q : un caractère n'a pas été échappé", attendu, texte)
		}
	}
}

func TestLesCodesDeResultatPortentLeurNom(t *testing.T) {
	for code, attendu := range map[int]string{
		ResultSuccess:            "0 success",
		ResultNoSuchObject:       "32 noSuchObject",
		ResultInvalidCredentials: "49 invalidCredentials",
		ResultBusy:               "51 busy",
		// Un code que le serveur n'émet pas : le nombre seul, pas un nom inventé.
		80: "80",
	} {
		if got := NomDuResultat(code); got != attendu {
			t.Errorf("NomDuResultat(%d) = %q, attendu %q", code, got, attendu)
		}
	}
}
