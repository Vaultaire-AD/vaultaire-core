package ldapparser

import (
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Tests du décodage des filtres de sous-chaîne — RFC 4511 §4.5.1.
//
// # Pourquoi ce test existe séparément de celui de l'évaluateur
//
// L'évaluateur est testé sur des filtres construits à la main, avec SubInitial,
// SubAny et SubFinal déjà remplis. Il peut donc être parfaitement juste alors
// que le PARSEUR range les morceaux dans les mauvais champs : le filtre est
// évalué correctement, mais ce n'est pas le filtre que le client a envoyé.
//
// C'est précisément ce qui se passait. Le parseur concaténait les morceaux en
// jetant leurs balises de position : « jo*n*doe » devenait « jondoe », comparé
// ensuite par égalité stricte. Aucun test de l'évaluateur ne pouvait le voir.

// buildSubstringPacket fabrique le paquet BER qu'un client émet pour un filtre
// de sous-chaîne, avec les balises de contexte 0 (initial), 1 (any) et 2 (final).
func buildSubstringPacket(attr string, morceaux []struct {
	tag ber.Tag
	val string
}) *ber.Packet {
	sub := ber.Encode(ber.ClassContext, ber.TypeConstructed, 4, nil, "substrings")
	sub.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "type"))

	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "substrings")
	for _, m := range morceaux {
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, m.tag, m.val, "part"))
	}
	sub.AppendChild(seq)

	// Aller-retour par les octets : c'est ce que le serveur reçoit réellement.
	// Analyser l'arbre construit en mémoire testerait le constructeur, pas le
	// décodeur — et les balises de contexte pourraient survivre à l'un sans
	// survivre à l'autre.
	return ber.DecodePacket(sub.Bytes())
}

type morceau = struct {
	tag ber.Tag
	val string
}

// TestSubstringConserveLesPositions : chaque morceau doit atterrir dans le champ
// que sa balise désigne.
//
// Les intervertir ne casse RIEN à la compilation — les trois champs sont des
// chaînes — et produit une recherche qui répond parfaitement, à côté.
func TestSubstringConserveLesPositions(t *testing.T) {
	p := buildSubstringPacket("cn", []morceau{
		{0, "jo"}, {1, "n"}, {2, "doe"},
	})

	f, err := decodeSubstringFilter(p)
	if err != nil {
		t.Fatalf("décodage impossible : %v", err)
	}

	if f.Type != ldapstorage.FilterSubstring {
		t.Errorf("type %v, attendu FilterSubstring", f.Type)
	}
	if f.Attribute != "cn" {
		t.Errorf("attribut %q, attendu cn", f.Attribute)
	}
	if f.SubInitial != "jo" {
		t.Errorf("SubInitial = %q, attendu jo", f.SubInitial)
	}
	if len(f.SubAny) != 1 || f.SubAny[0] != "n" {
		t.Errorf("SubAny = %v, attendu [n]", f.SubAny)
	}
	if f.SubFinal != "doe" {
		t.Errorf("SubFinal = %q, attendu doe", f.SubFinal)
	}
}

// TestSubstringPrefixeSeul : (cn=jo*) n'a qu'un initial.
//
// Un final vide n'est pas la même chose qu'un final absent : le remplir avec le
// dernier morceau rencontré ferait exiger un suffixe que le client n'a pas
// demandé, et la recherche par préfixe ne rendrait plus rien.
func TestSubstringPrefixeSeul(t *testing.T) {
	f, err := decodeSubstringFilter(buildSubstringPacket("uid", []morceau{{0, "jo"}}))
	if err != nil {
		t.Fatalf("décodage impossible : %v", err)
	}
	if f.SubInitial != "jo" || f.SubFinal != "" || len(f.SubAny) != 0 {
		t.Errorf("initial=%q any=%v final=%q, attendu initial seul",
			f.SubInitial, f.SubAny, f.SubFinal)
	}
}

// TestSubstringSuffixeSeul : (cn=*doe) n'a qu'un final.
func TestSubstringSuffixeSeul(t *testing.T) {
	f, err := decodeSubstringFilter(buildSubstringPacket("uid", []morceau{{2, "doe"}}))
	if err != nil {
		t.Fatalf("décodage impossible : %v", err)
	}
	if f.SubFinal != "doe" || f.SubInitial != "" || len(f.SubAny) != 0 {
		t.Errorf("initial=%q any=%v final=%q, attendu final seul",
			f.SubInitial, f.SubAny, f.SubFinal)
	}
}

// TestSubstringPlusieursAny : les morceaux intermédiaires gardent leur ORDRE.
//
// L'ordre est porteur de sens : « a*b*c » ne veut pas dire « b*a*c ». Un
// décodage qui les rangerait dans une map ou les trierait produirait un filtre
// qui répond à des entrées que le client n'a pas demandées.
func TestSubstringPlusieursAny(t *testing.T) {
	f, err := decodeSubstringFilter(buildSubstringPacket("cn", []morceau{
		{1, "un"}, {1, "deux"}, {1, "trois"},
	}))
	if err != nil {
		t.Fatalf("décodage impossible : %v", err)
	}
	attendu := []string{"un", "deux", "trois"}
	if len(f.SubAny) != len(attendu) {
		t.Fatalf("SubAny = %v, attendu %v", f.SubAny, attendu)
	}
	for i := range attendu {
		if f.SubAny[i] != attendu[i] {
			t.Fatalf("SubAny = %v, l'ordre n'est pas conservé (attendu %v)", f.SubAny, attendu)
		}
	}
}

// TestSubstringFiltreTronqueNePaniquePas : un filtre auquel il manque la
// séquence des morceaux doit être refusé, pas déréférencé.
//
// Le contenu vient du réseau, avant toute authentification pour certaines
// opérations : une panique ici est un déni de service à un paquet.
func TestSubstringFiltreTronqueNePaniquePas(t *testing.T) {
	tronque := ber.Encode(ber.ClassContext, ber.TypeConstructed, 4, nil, "substrings")
	tronque.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "type"))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panique sur un filtre tronqué : %v", r)
		}
	}()

	if _, err := decodeSubstringFilter(ber.DecodePacket(tronque.Bytes())); err == nil {
		t.Error("un filtre sans séquence de morceaux doit être refusé")
	}
}
