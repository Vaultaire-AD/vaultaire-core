package filter

import (
	"errors"
	"strings"
	"testing"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// Le point 119 : trois types de filtres sur dix rendaient zéro entrée, en
// silence. Le parseur les décodait correctement ; c'est l'évaluation qui les
// laissait tomber dans un `default: return false` dont la ligne d'avertissement
// était commentée.

// entrée réduite à ce qu'un filtre regarde.
type entrée struct {
	dn     string
	attrs  map[string][]string
	classe []string
}

func (e entrée) DN() string         { return e.dn }
func (e entrée) Domaines() []string { return []string{"enov.local"} }
func (e entrée) Restreinte(func(string) bool) ldapinterface.LDAPEntry {
	return e
}
func (e entrée) ObjectClasses() []string {
	if e.classe == nil {
		return []string{"inetOrgPerson"}
	}
	return e.classe
}
func (e entrée) GetAttribute(attr string) []string {
	return e.attrs[strings.ToLower(strings.TrimSpace(attr))]
}
func (e entrée) GetAttributes(attrs []string, typesOnly bool) map[string][]string {
	out := map[string][]string{}
	for _, a := range attrs {
		a = strings.ToLower(a)
		if v, ok := e.attrs[a]; ok {
			out[a] = v
		}
	}
	return out
}

func compte(uid string, attrs map[string][]string) entrée {
	if attrs == nil {
		attrs = map[string][]string{}
	}
	attrs["uid"] = []string{uid}
	return entrée{dn: "uid=" + uid + ",ou=users,dc=enov,dc=local", attrs: attrs}
}

func ordre(t ldapstorage.LDAPFilterType, attr, val string) *ldapstorage.LDAPFilter {
	return &ldapstorage.LDAPFilter{Type: t, Attribute: attr, Value: val}
}

// LE test du point : `>=` rend enfin quelque chose.
//
// Avant, il rendait zéro entrée avec un code de SUCCÈS, sans aucune trace côté
// serveur. C'est le pire mode de panne : rien n'a l'air cassé d'aucun des deux
// côtés, et le diagnostic prend des heures.
func TestLeSuperieurOuEgalRendEnfinQuelqueChose(t *testing.T) {
	e := compte("alice", map[string][]string{"uidnumber": {"1500"}})

	if !Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "uidNumber", "1000"), "", 2) {
		t.Error("(uidNumber>=1000) ne retient pas une entrée à 1500")
	}
	if Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "uidNumber", "2000"), "", 2) {
		t.Error("(uidNumber>=2000) retient une entrée à 1500")
	}
	if !Evaluate(e, ordre(ldapstorage.FilterLessOrEqual, "uidNumber", "1500"), "", 2) {
		t.Error("(uidNumber<=1500) ne retient pas une entrée à 1500 — la borne est INCLUSE")
	}
	if Evaluate(e, ordre(ldapstorage.FilterLessOrEqual, "uidNumber", "1000"), "", 2) {
		t.Error("(uidNumber<=1000) retient une entrée à 1500")
	}
}

// LA COMPARAISON EST NUMÉRIQUE quand les deux côtés le sont.
//
// Sinon `(uidNumber>=1000)` retiendrait 999 : dans l'ordre du texte, « 999 »
// vient après « 1000 ». C'est la comparaison la plus employée des deux, et
// l'erreur ne se voit pas — elle rend des résultats, simplement les mauvais.
func TestLesNombresSeComparentCommeDesNombres(t *testing.T) {
	petit := compte("bob", map[string][]string{"uidnumber": {"999"}})

	if Evaluate(petit, ordre(ldapstorage.FilterGreaterOrEqual, "uidNumber", "1000"), "", 2) {
		t.Error("999 passe pour supérieur à 1000 : la comparaison est lexicographique")
	}
	if !Evaluate(petit, ordre(ldapstorage.FilterLessOrEqual, "uidNumber", "1000"), "", 2) {
		t.Error("999 ne passe pas pour inférieur à 1000")
	}
}

// Les dates se comparent dans l'ordre du texte, et c'est correct : le format
// GeneralizedTime est fait pour cela. C'est le filtre qu'emploie un outil de
// synchronisation incrémentale, donc celui qui rendait zéro au pire endroit.
func TestLesDatesSOrdonnentCommeDuTexte(t *testing.T) {
	e := compte("carol", map[string][]string{"modifytimestamp": {"20260315120000Z"}})

	if !Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "modifyTimestamp", "20260101000000Z"), "", 2) {
		t.Error("une entrée modifiée en mars n'est pas rendue pour « depuis janvier »")
	}
	if Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "modifyTimestamp", "20260401000000Z"), "", 2) {
		t.Error("une entrée modifiée en mars est rendue pour « depuis avril »")
	}
}

// Un attribut est MULTIVALUÉ : une seule valeur satisfaisante suffit.
//
// Exiger que toutes le soient rendrait `(memberOf>=x)` faux dès qu'un groupe ne
// convient pas — ce n'est pas ce que dit la RFC, et ce n'est pas ce qu'un client
// attend.
func TestUneSeuleValeurSatisfaisanteSuffit(t *testing.T) {
	e := compte("dave", map[string][]string{"employeenumber": {"10", "900"}})

	if !Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "employeeNumber", "500"), "", 2) {
		t.Error("aucune des deux valeurs n'est retenue alors que 900 >= 500")
	}
}

// UNE ASSERTION VIDE N'ORDONNE RIEN.
//
// La comparer ferait passer toute valeur pour supérieure, donc `(cn>=)` rendrait
// l'annuaire entier — un filtre vide qui vide l'annuaire, c'est-à-dire le
// contraire de ce que l'on veut d'un filtre.
func TestUneAssertionVideNeRendRien(t *testing.T) {
	e := compte("erin", map[string][]string{"cn": {"Erin"}})

	for _, typ := range []ldapstorage.LDAPFilterType{
		ldapstorage.FilterGreaterOrEqual, ldapstorage.FilterLessOrEqual,
	} {
		if Evaluate(e, ordre(typ, "cn", ""), "", 2) {
			t.Errorf("le filtre de type %d avec une assertion vide retient une entrée", typ)
		}
	}
}

// `~=` rend une égalité insensible à la casse, et c'est assumé.
//
// Ce n'est pas une vraie correspondance approchée. Rendre un SOUS-ENSEMBLE de ce
// qu'elle rendrait est sans danger — on ne montre rien de plus qu'une égalité —
// alors que l'inverse divulguerait des entrées que le client n'a pas demandées.
// Ce qui compte, c'est que ce ne soit plus zéro.
func TestLApproximationVautUneEgalite(t *testing.T) {
	e := compte("frank", map[string][]string{"cn": {"Frank Dupont"}})

	if !Evaluate(e, ordre(ldapstorage.FilterApprox, "cn", "frank dupont"), "", 2) {
		t.Error("(cn~=frank dupont) ne retient pas « Frank Dupont »")
	}
	if Evaluate(e, ordre(ldapstorage.FilterApprox, "cn", "franck dupond"), "", 2) {
		t.Error("(cn~=franck dupond) retient « Frank Dupont » : l'approximation est " +
			"volontairement une égalité, pas une distance d'édition")
	}
}

// L'EXTENSIBLE MATCH EST REFUSÉ, et non répondu à côté.
//
// Il était évalué comme une simple égalité : la règle de correspondance et le
// marqueur `dn:` étaient ignorés. La chaîne AD d'appartenance TRANSITIVE
// `(memberOf:1.2.840.113556.1.4.1941:=…)` recevait donc une liste de membres
// FAUSSE — et une liste de membres fausse peut accorder ou refuser un accès dans
// l'application qui la lit. Un résultat faux est pire que pas de résultat.
func TestLExtensibleMatchEstRefuse(t *testing.T) {
	f := &ldapstorage.LDAPFilter{
		Type: ldapstorage.FilterExtensible, Attribute: "memberOf", Value: "cn=admins",
	}

	err := Verifier(f)
	if err == nil {
		t.Fatal("un extensible match est accepté : il sera évalué comme une égalité, " +
			"donc répondu à côté")
	}

	var ef *ErreurFiltre
	if !errors.As(err, &ef) {
		t.Fatalf("erreur de type %T : l'appelant ne peut pas en tirer un code LDAP", err)
	}
	if ef.Code != ldapstorage.ResultInappropriateMatching {
		t.Errorf("code %d, attendu %d (inappropriateMatching)",
			ef.Code, ldapstorage.ResultInappropriateMatching)
	}
	if !strings.Contains(err.Error(), "memberOf") {
		t.Errorf("le motif ne nomme pas l'attribut en cause : %q", err.Error())
	}
}

// L'INVARIANT DU POINT : tout type que Verifier ACCEPTE, Evaluate sait
// l'évaluer.
//
// C'est cet invariant qui fait que le `default` d'Evaluate n'est atteint que par
// un défaut de programmation — donc que le silence d'origine ne peut pas revenir.
//
// # Comment il est éprouvé, et pourquoi pas autrement
//
// En BALAYANT les valeurs de type, et non en recopiant la liste des cas. Une
// première version comparait deux listes tenues à la main : ajouter un type au
// parseur et à Verifier en oubliant Evaluate ET la liste du test serait passé
// inaperçu — précisément la régression que ce test existe pour interdire.
//
// Ici, tout type que Verifier accepte doit retenir une entrée faite pour le
// satisfaire. Un type neuf pour lequel personne n'a écrit de cas d'essai tombe
// sur le filtre générique, qu'Evaluate ne saura pas évaluer : le test échoue, et
// c'est ce qu'on veut.
//
// La réciproque n'est PAS testée, parce qu'elle est fausse et doit l'être :
// `FilterExtensible` est refusé par Verifier et n'a aucun cas dans Evaluate.
func TestToutTypeAccepteEstEvaluable(t *testing.T) {
	e := compte("grace", map[string][]string{"cn": {"Grace"}})

	// Au-delà des types qui existent aujourd'hui : un type ajouté demain tombe
	// dans ce balayage sans que personne ait à l'inscrire ici.
	for brut := 0; brut < 16; brut++ {
		typ := ldapstorage.LDAPFilterType(brut)
		f := filtreSatisfaisant(typ)

		if Verifier(f) != nil {
			continue // refusé : rien à évaluer, c'est cohérent
		}
		if !Evaluate(e, f, "", 2) {
			t.Errorf("type %d : accepté par Verifier, mais Evaluate ne retient pas "+
				"une entrée faite pour le satisfaire — le client recevra « success » "+
				"et zéro entrée, en silence", brut)
		}
	}
}

// filtreSatisfaisant fabrique, pour un type donné, un filtre que l'entrée
// d'essai satisfait. Un type inconnu reçoit un filtre générique, qu'Evaluate ne
// saura pas évaluer : c'est le piège tendu aux types ajoutés sans cas.
func filtreSatisfaisant(typ ldapstorage.LDAPFilterType) *ldapstorage.LDAPFilter {
	f := &ldapstorage.LDAPFilter{Type: typ, Attribute: "cn", Value: "Grace"}
	switch typ {
	case ldapstorage.FilterAnd, ldapstorage.FilterOr:
		f.SubFilters = []*ldapstorage.LDAPFilter{
			{Type: ldapstorage.FilterPresent, Attribute: "cn"},
		}
	case ldapstorage.FilterNot:
		// Un sous-filtre FAUX, pour que la négation soit vraie.
		f.SubFilters = []*ldapstorage.LDAPFilter{
			{Type: ldapstorage.FilterPresent, Attribute: "attribut-absent"},
		}
	case ldapstorage.FilterSubstring:
		f.SubInitial = "gra"
	}
	return f
}

// UN AND OU UN OR VIDE EST REFUSÉ.
//
// La RFC 4511 §4.5.1 impose au moins un élément, et l'évaluation en fait quelque
// chose de dangereux : un AND vide est VRAI, donc retient toutes les entrées. Un
// filtre qui ne demande rien rendrait l'annuaire.
func TestUnAndOuUnOrVideEstRefuse(t *testing.T) {
	for _, typ := range []ldapstorage.LDAPFilterType{
		ldapstorage.FilterAnd, ldapstorage.FilterOr,
	} {
		if Verifier(&ldapstorage.LDAPFilter{Type: typ}) == nil {
			t.Errorf("type %d vide : accepté", typ)
		}
	}

	// Et le rappel de ce qu'un AND vide vaudrait s'il passait.
	e := compte("hugo", nil)
	if !Evaluate(e, &ldapstorage.LDAPFilter{Type: ldapstorage.FilterAnd}, "", 2) {
		t.Skip("un AND vide ne retient plus tout : ce test peut être simplifié")
	}
}

// UN SOUS-FILTRE ABSENT EST REFUSÉ, et pas traité comme « pas de filtre ».
//
// Evaluate rend VRAI pour un filtre nil — c'est le sens d'une recherche sans
// filtre. Un nil glissé dans un OR retiendrait donc l'annuaire entier.
func TestUnSousFiltreAbsentEstRefuse(t *testing.T) {
	f := &ldapstorage.LDAPFilter{
		Type:       ldapstorage.FilterOr,
		SubFilters: []*ldapstorage.LDAPFilter{nil},
	}
	if Verifier(f) == nil {
		t.Error("un sous-filtre absent est accepté : il retiendrait toutes les entrées")
	}
}

// Un NOT malformé est refusé, au lieu de rendre une réponse vide et valide.
func TestUnNotMalformeEstRefuse(t *testing.T) {
	for nom, sous := range map[string][]*ldapstorage.LDAPFilter{
		"aucun sous-filtre": nil,
		"deux sous-filtres": {
			{Type: ldapstorage.FilterPresent, Attribute: "cn"},
			{Type: ldapstorage.FilterPresent, Attribute: "uid"},
		},
	} {
		err := Verifier(&ldapstorage.LDAPFilter{Type: ldapstorage.FilterNot, SubFilters: sous})
		if err == nil {
			t.Errorf("NOT avec %s : accepté", nom)
		}
	}
}

// Un filtre non géré NICHÉ dans un AND ou un OR est refusé lui aussi.
//
// C'est le cas qui compte en pratique : personne n'envoie un extensible match
// tout seul, il arrive dans une conjonction. Ne vérifier que la racine aurait
// laissé passer exactement ce qu'on veut attraper.
func TestUnFiltreNonGereEstRefuseMemeEnProfondeur(t *testing.T) {
	f := &ldapstorage.LDAPFilter{
		Type: ldapstorage.FilterAnd,
		SubFilters: []*ldapstorage.LDAPFilter{
			{Type: ldapstorage.FilterPresent, Attribute: "objectClass"},
			{Type: ldapstorage.FilterOr, SubFilters: []*ldapstorage.LDAPFilter{
				{Type: ldapstorage.FilterEquality, Attribute: "uid", Value: "alice"},
				{Type: ldapstorage.FilterExtensible, Attribute: "memberOf", Value: "cn=x"},
			}},
		},
	}
	if Verifier(f) == nil {
		t.Error("un extensible match niché dans un OR dans un AND est accepté")
	}
}

// Un filtre nil est accepté : c'est une recherche sans filtre, pas une erreur.
func TestUnFiltreAbsentEstAccepte(t *testing.T) {
	if err := Verifier(nil); err != nil {
		t.Errorf("un filtre absent est refusé : %v", err)
	}
}

// UN GRAND NOMBRE RESTE UN NOMBRE.
//
// Le mode de comparaison est choisi par VALEUR. Avec un entier 64 bits, une
// valeur qui déborde ne se lisait plus comme un nombre et basculait en
// comparaison de texte face à une assertion numérique : « 1 » vient avant « 9 »,
// donc dix milliards de milliards passaient pour inférieurs à 999.
//
// Le résultat était FAUX, pas absent. C'est le mode de panne que tout ce point
// corrige, reproduit à l'intérieur du correctif.
func TestUnGrandNombreResteUnNombre(t *testing.T) {
	énorme := compte("hugo", map[string][]string{
		"employeenumber": {"10000000000000000000"}, // au-delà d'un entier 64 bits
	})

	if !Evaluate(énorme, ordre(ldapstorage.FilterGreaterOrEqual, "employeeNumber", "999"), "", 2) {
		t.Error("une valeur de vingt chiffres passe pour inférieure à 999")
	}
	if Evaluate(énorme, ordre(ldapstorage.FilterLessOrEqual, "employeeNumber", "999"), "", 2) {
		t.Error("une valeur de vingt chiffres passe pour inférieure ou égale à 999")
	}
}

// Les nombres négatifs s'ordonnent comme des nombres.
func TestLesNegatifsSOrdonnentCommeDesNombres(t *testing.T) {
	e := compte("iris", map[string][]string{"solde": {"-5"}})

	if Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "solde", "0"), "", 2) {
		t.Error("-5 passe pour supérieur ou égal à 0")
	}
	if !Evaluate(e, ordre(ldapstorage.FilterLessOrEqual, "solde", "0"), "", 2) {
		t.Error("-5 ne passe pas pour inférieur ou égal à 0")
	}
}

// Un côté numérique et l'autre non : comparaison de texte, faute de mieux — mais
// au moins les deux côtés sont traités de la même façon.
func TestUnSeulCoteNumeriqueCompareDuTexte(t *testing.T) {
	e := compte("jean", map[string][]string{"cn": {"Jean"}})

	// Ne doit ni paniquer ni prétendre à un ordre numérique.
	_ = Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "cn", "42"), "", 2)
	if !Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "cn", "Alice"), "", 2) {
		t.Error("« Jean » ne passe pas pour après « Alice » dans l'ordre du texte")
	}
}

// Le message envoyé au CLIENT ne porte pas le numéro interne du type.
//
// La numérotation de LDAPFilterType n'est pas celle des étiquettes de la RFC :
// l'y mettre enverrait l'administrateur lire la mauvaise ligne de la norme.
func TestLeMotifEnvoyeAuClientNePorteAucunNumero(t *testing.T) {
	err := Verifier(&ldapstorage.LDAPFilter{Type: ldapstorage.LDAPFilterType(99)})
	if err == nil {
		t.Fatal("un type inconnu est accepté")
	}
	if strings.ContainsAny(err.Error(), "0123456789") {
		t.Errorf("le motif porte un numéro : %q", err.Error())
	}
}

// UN HORODATAGE AVEC DÉCALAGE S'ORDONNE COMME UN INSTANT, pas comme du texte.
//
// « 20260315120000+0200 » comparé à « 20260315120000Z » en comparaison de texte
// donne « + » (0x2B) avant « Z » : l'instant est déclaré antérieur à un instant
// qu'il suit. Faux, et faux en silence — le mode de panne que ce point corrige,
// reproduit à l'intérieur du correctif.
func TestUnHorodatageAvecDecalageSOrdonneCommeUnInstant(t *testing.T) {
	// 12h00 à UTC+2 vaut 10h00 UTC : l'entrée est ANTÉRIEURE à 11h00 UTC.
	e := compte("karl", map[string][]string{"modifytimestamp": {"20260315120000+0200"}})

	if Evaluate(e, ordre(ldapstorage.FilterGreaterOrEqual, "modifyTimestamp", "20260315110000Z"), "", 2) {
		t.Error("12h00 à UTC+2 (soit 10h00 UTC) passe pour postérieur à 11h00 UTC")
	}
	if !Evaluate(e, ordre(ldapstorage.FilterLessOrEqual, "modifyTimestamp", "20260315110000Z"), "", 2) {
		t.Error("12h00 à UTC+2 ne passe pas pour antérieur à 11h00 UTC")
	}
}

// UNE VALEUR INCOMPARABLE EST PASSÉE, pas comparée de travers.
//
// Le mode est choisi par l'ASSERTION : c'est le client qui dit ce qu'il compare.
// Une valeur qui n'entre pas dans ce moule — « 10 bis » face à un nombre — était
// comparée comme du texte, où « 1 » vient avant « 9 » : deux entrées du même
// ordre de grandeur recevaient des verdicts opposés dans la même recherche.
func TestUneValeurIncomparableEstPassee(t *testing.T) {
	texte := compte("lena", map[string][]string{"employeenumber": {"10 bis"}})
	nombre := compte("marc", map[string][]string{"employeenumber": {"10"}})

	f := ordre(ldapstorage.FilterGreaterOrEqual, "employeeNumber", "9")
	if !Evaluate(nombre, f, "", 2) {
		t.Error("10 ne passe pas pour supérieur à 9")
	}
	if Evaluate(texte, f, "", 2) {
		t.Error("« 10 bis » est retenu : il a été comparé comme du texte")
	}

	// Et une entrée qui porte les DEUX formes sort quand même, grâce à la bonne.
	mixte := compte("nora", map[string][]string{"employeenumber": {"10 bis", "10"}})
	if !Evaluate(mixte, f, "", 2) {
		t.Error("une valeur incomparable masque une valeur comparable du même attribut")
	}
}
