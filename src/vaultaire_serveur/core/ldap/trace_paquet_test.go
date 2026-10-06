package ldap

import (
	"strings"
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Le point 121 tient à une ligne : le vidage hexadécimal du paquet reçu, écrit
// AVANT toute analyse, portait le mot de passe du bind en clair dans le journal.

const motDePasseDuTest = "MotDePasseTresReconnaissable42"

// message construit un LDAPMessage complet autour d'une opération.
func message(messageID int, op *ber.Packet) []byte {
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger,
		uint64(messageID), "Message ID"))
	m.AppendChild(op)
	return m.Bytes()
}

// bindSimple forge un BindRequest tel qu'un client l'envoie.
func bindSimple(dn, motDePasse string) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapstorage.AppBindRequest, nil, "BindRequest")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Name"))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, motDePasse, "Password"))
	return message(1, op)
}

// rechercheSimple forge un SearchRequest, qui lui doit rester lisible.
func rechercheSimple(baseObject string) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapstorage.AppSearchRequest, nil, "SearchRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseObject, "BaseObject"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "Scope"))
	return message(2, op)
}

// LE test du point : le mot de passe ne part pas au journal.
//
// Il est cherché sous sa forme HEXADÉCIMALE, parce que c'est ainsi que la ligne
// l'écrivait — chercher le texte en clair ne prouverait rien.
func TestLeMotDePasseDuBindNeVaPasAuJournal(t *testing.T) {
	paquet := bindSimple("uid=jdupont,ou=users,dc=vaultaire,dc=local", motDePasseDuTest)

	trace := traceDuPaquet(paquet)

	if strings.Contains(hexSansEspaces(trace), hexDe(motDePasseDuTest)) {
		t.Fatalf("le mot de passe est dans la trace de mise au point : %s", trace)
	}
	if strings.Contains(trace, motDePasseDuTest) {
		t.Fatalf("le mot de passe est en clair dans la trace : %s", trace)
	}
}

// Le masquage ne doit pas effacer l'événement : il faut encore voir qu'un bind
// est arrivé, et de quelle taille. Sans cela, on aurait corrigé la fuite en
// supprimant le moyen de diagnostiquer.
//
// L'adresse du client n'est plus dans cette ligne (TO-DO 145) : elle s'écrit
// sous l'identifiant de sa connexion, et l'adresse est sur la ligne d'ouverture.
func TestLaTraceDuBindDitQuandMemeCeQuiEstArrive(t *testing.T) {
	paquet := bindSimple("uid=jdupont,ou=users,dc=vaultaire,dc=local", motDePasseDuTest)

	trace := traceDuPaquet(paquet)

	for _, attendu := range []string{"BindRequest", "octets", "masqué"} {
		if !strings.Contains(trace, attendu) {
			t.Errorf("la trace ne porte pas %q : %s", attendu, trace)
		}
	}
}

// Les AUTRES opérations gardent leur vidage complet : c'est la raison d'être de
// cette ligne, et elle sert à comprendre une trame mal découpée.
func TestUneRechercheGardeSonVidageComplet(t *testing.T) {
	paquet := rechercheSimple("ou=users,dc=vaultaire,dc=local")

	trace := traceDuPaquet(paquet)

	if strings.Contains(trace, "masqué") {
		t.Fatalf("un SearchRequest est masqué alors qu'il ne porte aucun secret : %s", trace)
	}
	if !strings.Contains(hexSansEspaces(trace), hexDe("ou=users")) {
		t.Errorf("le vidage ne contient pas le contenu de la trame : %s", trace)
	}
}

// UNE TRAME ILLISIBLE EST MASQUÉE, elle aussi.
//
// C'est le choix qui demande d'être justifié, parce qu'il coûte quelque chose :
// un paquet qu'on n'arrive pas à découper est justement celui qu'on aimerait
// voir en entier. Mais rien ne permet d'affirmer que ce n'est pas un bind sans
// lire le corps — ce qu'il s'agit précisément d'éviter. Le motif de l'échec
// d'analyse est journalisé à côté, lui.
func TestUneTrameIllisibleEstMasquee(t *testing.T) {
	for nom, paquet := range map[string][]byte{
		"vide":               {},
		"tronquée":           {0x30, 0x84, 0xff, 0xff},
		"pas une séquence":   {0x02, 0x01, 0x05},
		"séquence à un fils": {0x30, 0x03, 0x02, 0x01, 0x01},
	} {
		if !peutEtreUnBind(paquet) {
			t.Errorf("%s : traitée comme sûrement pas un bind, donc vidée en entier", nom)
		}
	}
}

// Et le décodage ne doit pas faire tomber le serveur sur une trame forgée : ce
// code s'exécute sur des octets venus d'inconnus, avant toute authentification.
func TestUneTrameForgeeNeFaitPasPaniquer(t *testing.T) {
	forgées := [][]byte{
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
		{0x30, 0x80, 0x30, 0x80, 0x30, 0x80},
		{0xff, 0xff, 0xff, 0xff},
		{0x30, 0x02, 0x01},
	}
	for _, p := range forgées {
		// Le test est l'appel lui-même : s'il panique, le test échoue. Rien d'autre
		// à vérifier — la valeur rendue est éprouvée par les tests précédents.
		trace := traceDuPaquet(p)
		if trace == "" {
			t.Errorf("trace vide pour % X", p)
		}
	}
}

func hexDe(s string) string {
	const chiffres = "0123456789ABCDEF"
	var b strings.Builder
	for _, o := range []byte(s) {
		b.WriteByte(chiffres[o>>4])
		b.WriteByte(chiffres[o&0x0f])
	}
	return b.String()
}

func hexSansEspaces(trace string) string {
	return strings.ToUpper(strings.ReplaceAll(trace, " ", ""))
}
