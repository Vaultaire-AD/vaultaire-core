package candidate

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// LA SENTINELLE DU POINT 125 : le sous-schéma doit être le reflet exact de ce
// que les entrées annoncent et servent.
//
// Il ne l'était pas, et l'écart s'était creusé sans que rien ne le dise : cinq
// classes annoncées mais non déclarées, sept attributs servis mais non déclarés,
// deux OID faux et un qui n'en était pas un.
//
// Un sous-schéma ne sert qu'aux clients qui le LISENT, c'est-à-dire aux plus
// stricts. Ceux-là s'arrêtent à la première ligne qu'ils ne savent pas analyser.

// nomsDeclares extrait les NAME d'une liste de déclarations de schéma.
//
// Une déclaration porte soit `NAME 'x'`, soit `NAME ( 'x' 'y' )` — la seconde
// forme donne plusieurs noms au même type, et c'est ainsi que `distinguishedName`
// porte aussi `dn`.
func nomsDeclares(declarations []string) map[string]bool {
	nom := regexp.MustCompile(`NAME\s+(?:\(\s*((?:'[^']+'\s*)+)\)|'([^']+)')`)
	simple := regexp.MustCompile(`'([^']+)'`)

	noms := map[string]bool{}
	for _, d := range declarations {
		m := nom.FindStringSubmatch(d)
		if m == nil {
			continue
		}
		if m[2] != "" {
			noms[strings.ToLower(m[2])] = true
			continue
		}
		for _, n := range simple.FindAllStringSubmatch(m[1], -1) {
			noms[strings.ToLower(n[1])] = true
		}
	}
	return noms
}

// entreesDuDIT rend une de chaque sorte d'entrée que le serveur place dans
// l'arborescence.
//
// Le RootDSE n'y est PAS, et ce n'est pas un oubli : il est hors de
// l'arborescence (RFC 4512 §5.1), sa classe `LDAProotDSE` n'appartient à aucun
// sous-schéma, et il est servi sans authentification par un chemin à part.
func entreesDuDIT() map[string]ldapinterface.LDAPEntry {
	u := UserEntry{BaseDN: "enov.local", Rattachements: []string{"enov.local"}}
	u.User.Username = "alice"
	u.User.Firstname = "Alice"
	u.User.Lastname = "Martin"
	u.User.Email = "alice@enov.local"
	u.User.Created_at = "2026-03-15 12:00:00"
	u.User.Modified_at = "2026-03-16 09:30:00"
	u.Groups = []string{"cn=admins,ou=groups,dc=enov,dc=local"}
	u.ServiceRights = []string{"read:nexus"}

	return map[string]ldapinterface.LDAPEntry{
		"compte": u,
		"groupe": GroupEntry{
			Name: "admins", BaseDN: "enov.local",
			Members:    []string{"uid=alice,ou=users,dc=enov,dc=local"},
			Created_at: "2026-03-15 12:00:00", Modified_at: "2026-03-16 09:30:00",
		},
		"unité d'organisation": OUEntry{Name: "users", BaseDN: "enov.local"},
		"domaine":              DomainEntry{DNName: "enov.local"},
		"sous-schéma":          NewSchemaEntry(),
	}
}

func TestChaqueClasseAnnonceeEstDeclaree(t *testing.T) {
	declarees := nomsDeclares(NewSchemaEntry().ObjectClassDefs)

	for nom, e := range entreesDuDIT() {
		for _, classe := range e.ObjectClasses() {
			if !declarees[strings.ToLower(classe)] {
				t.Errorf("%s annonce la classe %q, que le sous-schéma ne déclare pas — "+
					"un client qui lit le schéma pour valider l'entrée la refusera",
					nom, classe)
			}
		}
	}
}

func TestChaqueAttributServiEstDeclare(t *testing.T) {
	declares := nomsDeclares(NewSchemaEntry().AttributeTypes)

	// « * » et « + » ensemble : tous les attributs utilisateur ET opérationnels.
	// C'est la seule façon de voir ce que l'entrée est capable de servir.
	for nom, e := range entreesDuDIT() {
		if nom == "sous-schéma" {
			// Le sous-schéma sert les attributs QUI DÉCRIVENT un schéma —
			// `objectClasses`, `attributeTypes`, `matchingRules`… Ce sont des
			// attributs opérationnels du serveur, définis par la RFC 4512 §4.2 et
			// non par ce sous-schéma-ci. Les exiger ici reviendrait à demander au
			// schéma de se décrire lui-même.
			continue
		}
		for attr := range e.GetAttributes([]string{"*", "+"}, false) {
			if !declares[strings.ToLower(attr)] {
				t.Errorf("%s sert l'attribut %q, que le sous-schéma ne déclare pas — "+
					"c'est le défaut du point 125 : servir ce qu'on ne déclare pas",
					nom, attr)
			}
		}
	}
}

// Les règles de correspondance et les syntaxes CITÉES doivent être déclarées.
//
// Une règle nommée dans un `EQUALITY` sans être déclarée arrête le même
// analyseur que l'attribut manquant. C'est la moitié du problème qu'on ne voit
// pas en relisant la liste des attributs.
func TestChaqueRegleEtSyntaxeCiteeEstDeclaree(t *testing.T) {
	sch := NewSchemaEntry()
	regles := nomsDeclares(sch.MatchingRules)

	citation := regexp.MustCompile(`(?:EQUALITY|ORDERING|SUBSTR)\s+(\w+)`)
	syntaxe := regexp.MustCompile(`SYNTAX\s+([\d.]+)`)

	syntaxesDeclarees := map[string]bool{}
	oid := regexp.MustCompile(`\(\s*([\d.]+)`)
	for _, s := range sch.LdapSyntaxes {
		if m := oid.FindStringSubmatch(s); m != nil {
			syntaxesDeclarees[m[1]] = true
		}
	}

	for _, d := range sch.AttributeTypes {
		for _, m := range citation.FindAllStringSubmatch(d, -1) {
			if !regles[strings.ToLower(m[1])] {
				t.Errorf("la règle %q est citée sans être déclarée : %s", m[1], d)
			}
		}
		for _, m := range syntaxe.FindAllStringSubmatch(d, -1) {
			if !syntaxesDeclarees[m[1]] {
				t.Errorf("la syntaxe %q est citée sans être déclarée : %s", m[1], d)
			}
		}
	}
	for _, d := range sch.MatchingRules {
		for _, m := range syntaxe.FindAllStringSubmatch(d, -1) {
			if !syntaxesDeclarees[m[1]] {
				t.Errorf("la syntaxe %q est citée sans être déclarée : %s", m[1], d)
			}
		}
	}
}

// UN OID EST UN NUMERICOID, ET IL EST UNIQUE.
//
// Les deux défauts qui rendaient le sous-schéma inutilisable. `2.5.6.0` portait
// `top` ET `subschema`, et `vaultaireServiceRights-oid` n'était pas un OID du
// tout — sur cette seule ligne, un analyseur strict rejette TOUTE la liste des
// attributs.
func TestLesOIDSontValidesEtUniques(t *testing.T) {
	numericoid := regexp.MustCompile(`^\d+(\.\d+)+$`)
	tete := regexp.MustCompile(`^\(\s*([^\s)]+)`)

	for nom, liste := range map[string][]string{
		"classes":   NewSchemaEntry().ObjectClassDefs,
		"attributs": NewSchemaEntry().AttributeTypes,
		"règles":    NewSchemaEntry().MatchingRules,
		"syntaxes":  NewSchemaEntry().LdapSyntaxes,
	} {
		vus := map[string]string{}
		for _, d := range liste {
			m := tete.FindStringSubmatch(strings.TrimSpace(d))
			if m == nil {
				t.Errorf("%s : déclaration sans OID de tête : %s", nom, d)
				continue
			}
			if !numericoid.MatchString(m[1]) {
				t.Errorf("%s : %q n'est pas un numericoid — un analyseur strict rejette "+
					"TOUTE la liste sur cette seule ligne : %s", nom, m[1], d)
				continue
			}
			if precedent, déjà := vus[m[1]]; déjà {
				t.Errorf("%s : l'OID %s est porté deux fois — par %q et par %q",
					nom, m[1], precedent, d)
			}
			vus[m[1]] = d
		}
	}
}

// LA DATE DU SCHÉMA SUIT LE SCHÉMA — la sentinelle qui l'y oblige.
//
// Les deux dates étaient figées au jour où quelqu'un les a tapées : un client qui
// s'en sert pour savoir si le schéma a changé lisait toujours la même réponse.
// Les remplacer par l'heure de démarrage aurait été pire — deux nœuds du cluster
// auraient servi des dates différentes pour un schéma identique.
//
// Une constante, donc, et ce test pour qu'elle ne mente pas : il calcule
// l'empreinte de ce qui est servi et la compare à une valeur enregistrée.
// Modifier une déclaration sans toucher à la date fait échouer ce test.
func TestLaDateDuSchemaSuitLeSchema(t *testing.T) {
	// À METTRE À JOUR EN MÊME TEMPS QUE HorodatageDuSchema, et seulement avec lui.
	const empreinteAttendue = "fd46988ec5fe36d744371b692d18cc89a4d872a667015c3ee698caab6ceef74e"

	sch := NewSchemaEntry()
	h := sha256.New()
	for _, liste := range [][]string{
		sch.ObjectClassDefs, sch.AttributeTypes, sch.MatchingRules, sch.LdapSyntaxes,
	} {
		for _, d := range liste {
			h.Write([]byte(d))
			h.Write([]byte{0})
		}
	}
	empreinte := hex.EncodeToString(h.Sum(nil))

	if empreinteAttendue == "" {
		t.Fatalf("empreinte du schéma non enregistrée. Écrivez-la dans ce test :\n\n"+
			"    const empreinteAttendue = %q\n\n"+
			"et mettez HorodatageDuSchema à la date du jour.", empreinte)
	}
	if empreinte != empreinteAttendue {
		t.Errorf("le sous-schéma a changé (%s) sans que HorodatageDuSchema bouge.\n"+
			"Mettez la date du jour dans HorodatageDuSchema, et cette empreinte ici :\n\n"+
			"    const empreinteAttendue = %q\n\n"+
			"Sans quoi un client qui relit le schéma ne saura pas qu'il a changé.",
			empreinte[:12], empreinte)
	}
}

// Et la forme de la date, qui doit rester un GeneralizedTime UTC.
func TestLaDateDuSchemaEstUnGeneralizedTime(t *testing.T) {
	sch := NewSchemaEntry()
	for nom, valeurs := range map[string][]string{
		"createTimestamp": sch.CreateTimestamp,
		"modifyTimestamp": sch.ModifyTimestamp,
	} {
		if len(valeurs) != 1 {
			t.Fatalf("%s : %d valeur(s)", nom, len(valeurs))
		}
		if valeurs[0] == "20260314210522Z" {
			t.Errorf("%s vaut encore la date figée d'origine", nom)
		}
		if !strings.HasSuffix(valeurs[0], "Z") || len(valeurs[0]) != 15 {
			t.Errorf("%s = %q : ce n'est pas un GeneralizedTime UTC", nom, valeurs[0])
		}
	}
}
