package ldapparser

import (
	"runtime/debug"
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// valeurPagination encode la valeur du contrôle comme un client le fait.
func valeurPagination(taille int64, cookie string) []byte {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, taille, ""))
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, cookie, ""))
	return seq.Bytes()
}

// messageRecherche construit un SearchRequest RootDSE portant un contrôle, tel
// qu'il arrive sur le fil. critique == nil : le champ est OMIS, ce que fait
// tout client pour un contrôle non critique (DEFAULT FALSE).
func messageAvecControle(oid string, critique *bool, valeur []byte) []byte {
	recherche := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "SearchRequest")
	recherche.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "base"))
	recherche.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "scope"))
	recherche.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "deref"))
	recherche.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "size"))
	recherche.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "time"))
	recherche.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	recherche.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "present"))
	recherche.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs"))

	controle := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	controle.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oid, "type"))
	if critique != nil {
		controle.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, *critique, "crit"))
	}
	if valeur != nil {
		controle.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(valeur), "value"))
	}
	controles := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	controles.AppendChild(controle)

	message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 5, "id"))
	message.AppendChild(recherche)
	message.AppendChild(controles)
	return message.Bytes()
}

// La criticité a une valeur par défaut : un client qui envoie FALSE l'OMET. La
// séquence n'a alors que deux éléments, et le second est la valeur.
//
// L'analyseur lisait par position — deuxième élément = booléen, troisième =
// valeur — et rendait donc un contrôle non critique SANS valeur. La pagination,
// que la plupart des clients demandent sans la marquer critique, aurait été
// illisible pour eux et lisible seulement pour ceux qui la marquent.
func TestLaValeurDUnControleNonCritiqueEstLue(t *testing.T) {
	vrai, faux := true, false
	valeur := valeurPagination(100, "")

	for _, c := range []struct {
		titre    string
		critique *bool
		attendu  bool
	}{
		{"criticité omise", nil, false},
		{"criticité FALSE explicite", &faux, false},
		{"criticité TRUE", &vrai, true},
	} {
		message, err := ParseLDAPMessage(messageAvecControle(ldapstorage.OIDPagedResults, c.critique, valeur))
		if err != nil {
			t.Fatalf("%s : %v", c.titre, err)
		}
		if len(message.Controls) != 1 {
			t.Fatalf("%s : %d contrôle(s) lus", c.titre, len(message.Controls))
		}
		ctrl := message.Controls[0]
		if ctrl.ControlType != ldapstorage.OIDPagedResults || ctrl.Criticality != c.attendu {
			t.Errorf("%s : type=%q critique=%v", c.titre, ctrl.ControlType, ctrl.Criticality)
		}
		page, err := extrairePagination(message.Controls)
		if err != nil || page == nil || page.Size != 100 || len(page.Cookie) != 0 {
			t.Errorf("%s : la valeur du contrôle est perdue (page=%+v, err=%v)", c.titre, page, err)
		}
	}
}

func TestDecoderPagedResults(t *testing.T) {
	page, err := decoderPagedResults(valeurPagination(500, "\x01\x02\x00\xff"))
	if err != nil || page.Size != 500 || string(page.Cookie) != "\x01\x02\x00\xff" {
		t.Fatalf("page=%+v err=%v", page, err)
	}

	// Un cookie est une chaîne d'OCTETS : un zéro au milieu ne le termine pas.
	if len(page.Cookie) != 4 {
		t.Fatalf("cookie de %d octets, 4 envoyés", len(page.Cookie))
	}

	pasUneSequence := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "x", "").Bytes()
	unSeulChamp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	unSeulChamp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 10, ""))
	inverses := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	inverses.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	inverses.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 10, ""))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIQUE sur une valeur de contrôle forgée : %v\n%s", r, debug.Stack())
		}
	}()
	for titre, valeur := range map[string][]byte{
		"vide":                 nil,
		"octets quelconques":   {0xff, 0xff, 0xff, 0xff},
		"longueur mensongère":  {0x30, 0x7f, 0x02, 0x01},
		"pas une séquence":     pasUneSequence,
		"un seul champ":        unSeulChamp.Bytes(),
		"champs inversés":      inverses.Bytes(),
		"taille négative":      valeurPagination(-1, ""),
		"taille au-delà d'int": valeurPagination(1<<40, ""),
	} {
		if _, err := decoderPagedResults(valeur); err == nil {
			t.Errorf("%s : accepté", titre)
		}
	}
}

func TestDeuxControlesDePaginationSontRefuses(t *testing.T) {
	c := ldapstorage.LDAPControl{ControlType: ldapstorage.OIDPagedResults, ControlValue: valeurPagination(10, "")}
	if _, err := extrairePagination([]ldapstorage.LDAPControl{c, c}); err == nil {
		t.Error("deux contrôles de pagination acceptés : lequel suivre ?")
	}
	autre := ldapstorage.LDAPControl{ControlType: "1.2.3.4", ControlValue: []byte("x")}
	if page, err := extrairePagination([]ldapstorage.LDAPControl{autre}); page != nil || err != nil {
		t.Errorf("un contrôle étranger est pris pour de la pagination : %+v, %v", page, err)
	}
}

// Un contrôle n'est admis que là où il s'applique. Marquée critique sur un
// bind, la pagination doit le faire échouer comme tout contrôle critique que le
// serveur ne sait pas honorer là (RFC 4511 §4.1.11).
func TestLaPaginationNEstAdmiseQueSurUneRecherche(t *testing.T) {
	if !controleAdmis(ldapstorage.OIDPagedResults, "SearchRequest") {
		t.Error("la pagination est refusée sur une recherche")
	}
	for _, op := range []string{"BindRequest", "UnbindRequest", "ExtendedRequest"} {
		if controleAdmis(ldapstorage.OIDPagedResults, op) {
			t.Errorf("la pagination est admise sur %s", op)
		}
	}
	if controleAdmis("1.3.6.1.4.1.42.2.27.8.5.1", "SearchRequest") {
		t.Error("un contrôle que le serveur ne traite pas est admis")
	}
	// Tout ce qui est annoncé doit être admis quelque part : sinon le RootDSE
	// promet un contrôle que le dispatcheur refuse.
	for _, oid := range ldapstorage.ControlesGeres {
		if !controleAdmis(oid, "SearchRequest") {
			t.Errorf("%s est annoncé (ControlesGeres) mais n'est admis sur aucune recherche", oid)
		}
	}
}
