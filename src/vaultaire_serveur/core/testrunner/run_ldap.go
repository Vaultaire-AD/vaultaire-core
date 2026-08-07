package testrunner

import (
	"fmt"
	"strings"

	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapfilter "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/filter"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// Tests de conformité au protocole LDAP (RFC 4511 / 4512 / 4514).
//
// # Ce que ces tests cherchent
//
// LDAP échoue rarement bruyamment. Un filtre mal évalué, un attribut de trop
// dans une réponse ou une portée trop large ne produisent aucune erreur : ils
// produisent un résultat VALIDE et faux. Le client l'accepte, l'annuaire a
// l'air de fonctionner, et l'écart ne se voit qu'au moment où quelqu'un compare
// à la main.
//
// Les cas ci-dessous portent donc surtout sur ce qui ne doit PAS sortir, et sur
// ce qui doit sortir alors que rien ne le réclame bruyamment.
//
// # Ce que ces tests ne couvrent pas
//
// Tout ce qui exige une connexion ou une base : le contrôle de flux de la
// session, la limitation de débit du bind, la pagination. Ces parties ont leurs
// propres tests `go test` dans leurs paquets, où l'on peut fabriquer une
// connexion factice.
func testLDAP() []Result {
	var out []Result

	out = append(out, testLDAPFiltresLogiques()...)
	out = append(out, testLDAPSubstring()...)
	out = append(out, testLDAPAttributs()...)
	out = append(out, testLDAPResultCodes()...)
	out = append(out, testLDAPRootDSE()...)
	out = append(out, testLDAPDN()...)

	return out
}

// ---------------------------------------------------------------------------
// Entrée factice
// ---------------------------------------------------------------------------

// entreeTest implémente LDAPEntry sans base ni connexion.
type entreeTest struct {
	dn    string
	attrs map[string][]string
}

func (e entreeTest) DN() string { return e.dn }

func (e entreeTest) GetAttribute(attr string) []string {
	return e.attrs[strings.ToLower(strings.TrimSpace(attr))]
}

func (e entreeTest) GetAttributes(attrs []string, typesOnly bool) map[string][]string {
	out := map[string][]string{}
	for _, a := range attrs {
		a = strings.ToLower(a)
		if v, ok := e.attrs[a]; ok {
			if typesOnly {
				out[a] = []string{}
			} else {
				out[a] = v
			}
		}
	}
	return out
}

func (e entreeTest) ObjectClasses() []string { return []string{"inetOrgPerson"} }

func utilisateurTest() entreeTest {
	return entreeTest{
		dn: "uid=jdupont,ou=users,dc=vaultaire,dc=local",
		attrs: map[string][]string{
			"uid":         {"jdupont"},
			"cn":          {"Jean Dupont"},
			"mail":        {"jean.dupont@vaultaire.local"},
			"displayname": {"Jean Dupont"},
			"memberof":    {"cn=admins,ou=groups,dc=vaultaire,dc=local"},
		},
	}
}

func eq(attr, val string) *ldapstorage.LDAPFilter {
	return &ldapstorage.LDAPFilter{Type: ldapstorage.FilterEquality, Attribute: attr, Value: val}
}

func present(attr string) *ldapstorage.LDAPFilter {
	return &ldapstorage.LDAPFilter{Type: ldapstorage.FilterPresent, Attribute: attr}
}

func sub(attr, initial string, any []string, final string) *ldapstorage.LDAPFilter {
	return &ldapstorage.LDAPFilter{
		Type: ldapstorage.FilterSubstring, Attribute: attr,
		SubInitial: initial, SubAny: any, SubFinal: final,
	}
}

// ---------------------------------------------------------------------------
// Filtres logiques — RFC 4511 §4.5.1, RFC 4526
// ---------------------------------------------------------------------------

func testLDAPFiltresLogiques() []Result {
	var out []Result
	e := utilisateurTest()
	ev := func(f *ldapstorage.LDAPFilter) bool {
		return ldapfilter.Evaluate(e, f, "dc=vaultaire,dc=local", 2)
	}

	cas := []struct {
		nom      string
		filtre   *ldapstorage.LDAPFilter
		attendu  bool
		pourquoi string
	}{
		{"egalite exacte", eq("uid", "jdupont"), true, ""},
		{"egalite insensible a la casse", eq("uid", "JDUPONT"), true,
			"caseIgnoreMatch est la regle par defaut de uid"},
		{"egalite sur une valeur absente", eq("uid", "autre"), false, ""},
		{"egalite sur un attribut inconnu", eq("nexistepas", "x"), false, ""},

		{"presence d'un attribut porte", present("mail"), true, ""},
		{"presence d'un attribut absent", present("telephonenumber"), false, ""},

		{"ET de deux vrais", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterAnd,
			SubFilters: []*ldapstorage.LDAPFilter{eq("uid", "jdupont"), present("mail")}}, true, ""},
		{"ET dont un faux", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterAnd,
			SubFilters: []*ldapstorage.LDAPFilter{eq("uid", "jdupont"), eq("uid", "autre")}}, false, ""},

		{"OU dont un vrai", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterOr,
			SubFilters: []*ldapstorage.LDAPFilter{eq("uid", "autre"), present("mail")}}, true, ""},
		{"OU tout faux", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterOr,
			SubFilters: []*ldapstorage.LDAPFilter{eq("uid", "autre"), present("fax")}}, false, ""},

		{"NON inverse", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterNot,
			SubFilters: []*ldapstorage.LDAPFilter{eq("uid", "autre")}}, true, ""},

		// RFC 4526 : « (&) » est le filtre VRAI absolu, « (|) » le filtre FAUX
		// absolu. Ce n'est pas une curiosité : les clients Microsoft envoient
		// « (&) » comme filtre neutre, et l'évaluer à faux rend l'annuaire
		// entièrement vide pour eux — sans la moindre erreur.
		{"ET vide = vrai absolu (RFC 4526)", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterAnd}, true,
			"un ET sans sous-filtre doit valoir vrai"},
		{"OU vide = faux absolu (RFC 4526)", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterOr}, false,
			"un OU sans sous-filtre doit valoir faux"},

		// Un NON doit porter sur EXACTEMENT un sous-filtre. Zéro ou plusieurs est
		// un filtre malformé : le refuser vaut mieux que d'en deviner le sens.
		{"NON sans sous-filtre est refuse", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterNot}, false, ""},
		{"NON a deux sous-filtres est refuse", &ldapstorage.LDAPFilter{Type: ldapstorage.FilterNot,
			SubFilters: []*ldapstorage.LDAPFilter{eq("uid", "a"), eq("uid", "b")}}, false, ""},
	}

	for _, c := range cas {
		got := ev(c.filtre)
		msg := c.pourquoi
		if msg == "" {
			msg = fmt.Sprintf("obtenu %v, attendu %v", got, c.attendu)
		}
		out = append(out, Result{"LDAP/filtre: " + c.nom, got == c.attendu, msg})
	}

	// Un filtre nil signifie « pas de filtre » : tout passe. C'est ce que fait le
	// code, et le contraire viderait toute recherche dont le filtre n'a pas pu
	// être analysé — un échec d'analyse se présenterait alors comme un annuaire
	// vide.
	out = append(out, Result{"LDAP/filtre: un filtre absent laisse tout passer",
		ldapfilter.Evaluate(e, nil, "dc=vaultaire,dc=local", 2), "un filtre nil doit valoir vrai"})

	// (attr=*) est très souvent envoyé comme une ÉGALITÉ à l'étoile plutôt que
	// comme une assertion de présence. Les deux formes doivent se comporter
	// pareil, sinon la moitié des clients ne voit rien.
	out = append(out, Result{"LDAP/filtre: (attr=*) en egalite vaut presence",
		ev(eq("mail", "*")) && !ev(eq("fax", "*")),
		"l'etoile en valeur d'egalite doit tester la presence"})

	return out
}

// ---------------------------------------------------------------------------
// Filtres de sous-chaîne — RFC 4511 §4.5.1
// ---------------------------------------------------------------------------

// testLDAPSubstring est la partie qui a motivé cet audit.
//
// Le filtre de sous-chaîne était évalué comme une ÉGALITÉ sur la concaténation
// de ses morceaux : `(cn=jo*)` cherchait une entrée dont le cn vaut exactement
// « jo ». Aucune recherche par préfixe ne rendait quoi que ce soit, et la
// réponse vide était parfaitement valide — donc indiagnosticable côté client.
func testLDAPSubstring() []Result {
	var out []Result
	e := utilisateurTest()
	ev := func(f *ldapstorage.LDAPFilter) bool {
		return ldapfilter.Evaluate(e, f, "dc=vaultaire,dc=local", 2)
	}

	cas := []struct {
		nom     string
		filtre  *ldapstorage.LDAPFilter
		attendu bool
	}{
		// cn = "Jean Dupont"
		{"prefixe (cn=Jean*)", sub("cn", "Jean", nil, ""), true},
		{"prefixe qui ne colle pas (cn=Paul*)", sub("cn", "Paul", nil, ""), false},
		{"suffixe (cn=*Dupont)", sub("cn", "", nil, "Dupont"), true},
		{"suffixe qui ne colle pas (cn=*Martin)", sub("cn", "", nil, "Martin"), false},
		{"contient (cn=*an Du*)", sub("cn", "", []string{"an Du"}, ""), true},
		{"prefixe et suffixe (cn=Jean*Dupont)", sub("cn", "Jean", nil, "Dupont"), true},
		{"morceaux multiples dans l'ordre (cn=J*an*pont)",
			sub("cn", "J", []string{"an"}, "pont"), true},

		// L'ORDRE compte. « Dupont » précède « Jean » dans le filtre mais pas
		// dans la valeur : un Contains par morceau, sans curseur, accepterait.
		{"morceaux dans le desordre refuses (cn=*Dupont*Jean*)",
			sub("cn", "", []string{"Dupont", "Jean"}, ""), false},

		// Pas de chevauchement : « ean » ne peut pas servir deux fois.
		{"un morceau ne sert pas deux fois", sub("cn", "", []string{"ean", "ean"}, ""), false},

		// Le suffixe est consommé avant les morceaux intermédiaires.
		{"final et any ne se recouvrent pas", sub("cn", "", []string{"Dupont"}, "Dupont"), false},

		// Insensible à la casse, comme l'égalité.
		{"insensible a la casse (cn=jEaN*)", sub("cn", "jEaN", nil, ""), true},

		// Sans aucun morceau, c'est une présence.
		{"aucun morceau = presence, attribut porte", sub("mail", "", nil, ""), true},
		{"aucun morceau = presence, attribut absent", sub("fax", "", nil, ""), false},

		{"sur un attribut inconnu", sub("nexistepas", "x", nil, ""), false},

		// La valeur entière comme préfixe ET suffixe : doit rester vrai.
		{"valeur entiere en prefixe", sub("uid", "jdupont", nil, ""), true},
		{"valeur entiere en suffixe", sub("uid", "", nil, "jdupont"), true},

		// Un préfixe plus long que la valeur ne doit pas déborder.
		{"prefixe plus long que la valeur", sub("uid", "jdupontXXXX", nil, ""), false},
		{"suffixe plus long que la valeur", sub("uid", "", nil, "XXXXjdupont"), false},
	}

	for _, c := range cas {
		got := ev(c.filtre)
		out = append(out, Result{"LDAP/sous-chaine: " + c.nom, got == c.attendu,
			fmt.Sprintf("obtenu %v, attendu %v", got, c.attendu)})
	}

	// Le piège de l'ancienne implémentation, épinglé explicitement : la
	// concaténation des morceaux ne doit PAS être comparée par égalité, sinon
	// une entrée nommée « JeanDupont » répondrait à `(cn=Jean*Dupont)` alors que
	// « Jean Dupont » — la vraie — ne répondrait pas.
	concat := entreeTest{dn: "uid=x", attrs: map[string][]string{"cn": {"JeanDupont"}}}
	out = append(out, Result{
		"LDAP/sous-chaine: la concatenation n'est pas comparee par egalite",
		ldapfilter.Evaluate(e, sub("cn", "Jean", nil, "Dupont"), "", 2) &&
			ldapfilter.Evaluate(concat, sub("cn", "Jean", nil, "Dupont"), "", 2),
		"les deux formes doivent repondre au meme filtre de sous-chaine",
	})

	return out
}

// ---------------------------------------------------------------------------
// Sélection d'attributs — RFC 4511 §4.5.1
// ---------------------------------------------------------------------------

// testLDAPAttributs vérifie la discipline des attributs opérationnels.
//
// Un attribut opérationnel ne sort que s'il est demandé, nommément ou par « + ».
// « * » désigne les attributs UTILISATEUR et rien d'autre.
//
// Le code entrait dans la branche « non demandé » puis ajoutait quand même
// l'attribut dès qu'il portait une valeur. Comme `entryuuid`, `nsuniqueid`,
// `objectguid`, `guid` et `ipauniqueid` en portent toujours une, ils partaient à
// CHAQUE recherche — y compris sur « 1.1 », qui veut dire « aucun attribut ».
func testLDAPAttributs() []Result {
	var out []Result

	operationnels := []string{"entryuuid", "nsuniqueid", "objectguid", "guid", "ipauniqueid"}
	u := utilisateurAvecOperationnels()

	// --- « 1.1 » : aucun attribut ------------------------------------------
	attrs := u.GetAttributes([]string{"1.1"}, false)
	out = append(out, Result{
		"LDAP/attributs: 1.1 ne rend aucun attribut",
		len(attrs) == 0,
		fmt.Sprintf("1.1 a rendu %d attribut(s) : %v", len(attrs), clesTriees(attrs)),
	})

	// --- Un attribut nommé, et lui seul ------------------------------------
	attrs = u.GetAttributes([]string{"uid"}, false)
	seulementUID := len(attrs) == 1 && len(attrs["uid"]) > 0
	out = append(out, Result{
		"LDAP/attributs: demander uid ne rend que uid",
		seulementUID,
		fmt.Sprintf("obtenu %v", clesTriees(attrs)),
	})

	// --- « * » : attributs utilisateur, pas les opérationnels --------------
	attrs = u.GetAttributes([]string{"*"}, false)
	var fuites []string
	for _, op := range operationnels {
		if _, present := attrs[op]; present {
			fuites = append(fuites, op)
		}
	}
	out = append(out, Result{
		"LDAP/attributs: l'etoile n'entraine pas les attributs operationnels",
		len(fuites) == 0,
		fmt.Sprintf("attributs operationnels rendus sans avoir ete demandes : %v", fuites),
	})
	out = append(out, Result{
		"LDAP/attributs: l'etoile rend bien les attributs utilisateur",
		len(attrs["uid"]) > 0 && len(attrs["mail"]) > 0,
		"uid ou mail manquant sur une demande *",
	})

	// --- « + » : les opérationnels sortent ---------------------------------
	attrs = u.GetAttributes([]string{"+"}, false)
	var manquants []string
	for _, op := range operationnels {
		if _, present := attrs[op]; !present {
			manquants = append(manquants, op)
		}
	}
	out = append(out, Result{
		"LDAP/attributs: le plus rend les attributs operationnels",
		len(manquants) == 0,
		fmt.Sprintf("operationnels absents malgre + : %v", manquants),
	})

	// --- Un opérationnel nommé explicitement reste accessible --------------
	//
	// Sinon l'évaluation d'un filtre sur entryuuid cesserait de fonctionner :
	// GetAttribute passe par GetAttributes avec le nom seul.
	attrs = u.GetAttributes([]string{"entryuuid"}, false)
	out = append(out, Result{
		"LDAP/attributs: un operationnel nomme reste accessible",
		len(attrs["entryuuid"]) > 0,
		"demander entryuuid nommement doit le rendre",
	})

	// --- typesOnly : les noms sans les valeurs -----------------------------
	attrs = u.GetAttributes([]string{"uid"}, true)
	out = append(out, Result{
		"LDAP/attributs: typesOnly rend le nom sans la valeur",
		len(attrs) == 1 && len(attrs["uid"]) == 0,
		fmt.Sprintf("obtenu %v", attrs),
	})

	return out
}

func clesTriees(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Tri par insertion : la liste est courte et n'importer sort ici n'apporte
	// rien qu'on ne puisse écrire en quatre lignes.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Codes de résultat — RFC 4511 §4.1.9 et Annexe A
// ---------------------------------------------------------------------------

func testLDAPResultCodes() []Result {
	var out []Result

	// Les valeurs sont normatives : un client les interprète directement, et
	// une erreur de constante donne un refus que personne ne sait traduire.
	attendus := map[string]int{
		"success":                      ldapstorage.ResultSuccess,
		"protocolError":                ldapstorage.ResultProtocolError,
		"timeLimitExceeded":            ldapstorage.ResultTimeLimitExceeded,
		"sizeLimitExceeded":            ldapstorage.ResultSizeLimitExceeded,
		"authMethodNotSupported":       ldapstorage.ResultAuthMethodNotSupported,
		"strongerAuthRequired":         ldapstorage.ResultStrongerAuthRequired,
		"unavailableCriticalExtension": ldapstorage.ResultUnavailableCriticalExtension,
		"invalidCredentials":           ldapstorage.ResultInvalidCredentials,
		"insufficientAccessRights":     ldapstorage.ResultInsufficientAccessRights,
		"unwillingToPerform":           ldapstorage.ResultUnwillingToPerform,
	}
	valeursRFC := map[string]int{
		"success": 0, "protocolError": 2, "timeLimitExceeded": 3, "sizeLimitExceeded": 4,
		"authMethodNotSupported": 7, "strongerAuthRequired": 8,
		"unavailableCriticalExtension": 12, "invalidCredentials": 49,
		"insufficientAccessRights": 50, "unwillingToPerform": 53,
	}
	for nom, attendu := range valeursRFC {
		out = append(out, Result{
			fmt.Sprintf("LDAP/codes: %s vaut %d", nom, attendu),
			attendus[nom] == attendu,
			fmt.Sprintf("obtenu %d", attendus[nom]),
		})
	}

	// Chaque requête a UNE réponse, avec le bon tag applicatif. Se tromper de
	// tag produit un paquet valide que le client range dans la mauvaise
	// catégorie — il attend alors indéfiniment la réponse qu'il a déjà reçue.
	couples := []struct {
		requete, reponse int
		nom              string
	}{
		{ldapstorage.AppBindRequest, ldapstorage.AppBindResponse, "bind"},
		{ldapstorage.AppSearchRequest, ldapstorage.AppSearchResultDone, "search"},
		{ldapstorage.AppModifyRequest, ldapstorage.AppModifyResponse, "modify"},
		{ldapstorage.AppAddRequest, ldapstorage.AppAddResponse, "add"},
		{ldapstorage.AppDelRequest, ldapstorage.AppDelResponse, "del"},
		{ldapstorage.AppModifyDNRequest, ldapstorage.AppModifyDNResponse, "modifyDN"},
		{ldapstorage.AppCompareRequest, ldapstorage.AppCompareResponse, "compare"},
		{ldapstorage.AppExtendedRequest, ldapstorage.AppExtendedResponse, "extended"},
	}
	for _, c := range couples {
		got, ok := ldapstorage.ResponseTagFor(c.requete)
		out = append(out, Result{
			"LDAP/codes: la reponse a " + c.nom + " porte le bon tag",
			ok && got == c.reponse,
			fmt.Sprintf("obtenu tag=%d ok=%v, attendu %d", got, ok, c.reponse),
		})
	}

	// Unbind (§4.3) et Abandon (§4.11) n'ont PAS de réponse. Leur en fabriquer
	// une envoie au client un paquet qu'il n'attend pas ; certains ferment la
	// connexion en signalant une erreur de protocole.
	for _, c := range []struct {
		tag int
		nom string
	}{
		{ldapstorage.AppUnbindRequest, "unbind"},
		{ldapstorage.AppAbandonRequest, "abandon"},
	} {
		_, ok := ldapstorage.ResponseTagFor(c.tag)
		out = append(out, Result{
			"LDAP/codes: " + c.nom + " n'a pas de reponse",
			!ok,
			"une reponse est definie alors que la RFC n'en prevoit aucune",
		})
	}

	return out
}

// ---------------------------------------------------------------------------
// RootDSE — RFC 4512 §5.1
// ---------------------------------------------------------------------------

func testLDAPRootDSE() []Result {
	var out []Result

	// Le DN vide désigne la RootDSE. C'est la première chose que fait tout
	// client en se connectant : ne pas la reconnaître fait échouer la découverte
	// avant même le bind.
	for _, base := range []string{"", "   "} {
		out = append(out, Result{
			fmt.Sprintf("LDAP/RootDSE: le DN %q designe la RootDSE", base),
			ldaptools.IsRootDSEBase(base),
			"un DN vide doit designer la RootDSE",
		})
	}

	// Le sous-schéma est une entrée distincte de la RootDSE, mais s'atteint par
	// le même chemin de détection.
	for _, base := range []string{"cn=subschema", "CN=Subschema", "cn=schema", "CN=SCHEMA"} {
		out = append(out, Result{
			fmt.Sprintf("LDAP/RootDSE: %q est reconnu (insensible a la casse)", base),
			ldaptools.IsRootDSEBase(base),
			"le DN de schema doit etre reconnu quelle que soit la casse",
		})
	}

	// Et surtout : un DN ordinaire ne doit PAS être pris pour la RootDSE. Le
	// confondre servirait le contenu du schéma à la place d'une branche de
	// l'annuaire, ou l'inverse.
	for _, base := range []string{
		"dc=vaultaire,dc=local",
		"ou=users,dc=vaultaire,dc=local",
		"uid=jdupont,ou=users,dc=vaultaire,dc=local",
		"cn=admins,ou=groups,dc=vaultaire,dc=local",
	} {
		out = append(out, Result{
			fmt.Sprintf("LDAP/RootDSE: %q n'est PAS la RootDSE", base),
			!ldaptools.IsRootDSEBase(base),
			"un DN ordinaire pris pour la RootDSE",
		})
	}

	return out
}

// ---------------------------------------------------------------------------
// Analyse des DN — RFC 4514
// ---------------------------------------------------------------------------

func testLDAPDN() []Result {
	var out []Result

	cas := []struct {
		entree            string
		user, domaine, ou string
	}{
		{"uid=jdupont,ou=IT,dc=example,dc=com", "jdupont", "example.com", "IT"},
		{"cn=Admin,dc=vaultaire,dc=local", "Admin", "vaultaire.local", ""},
		{"jdupont@ldap.domain.com", "jdupont", "ldap.domain.com", ""},
		{"jdupont", "jdupont", "", ""},
		// La casse des types d'attribut n'est pas significative (RFC 4514 §3) :
		// un client qui écrit UID= doit être compris comme un qui écrit uid=.
		{"UID=jdupont,OU=IT,DC=example,DC=com", "jdupont", "example.com", "IT"},
		// Les espaces autour des composants sont tolérés.
		{"uid=jdupont, ou=IT, dc=example, dc=com", "jdupont", "example.com", "IT"},
		// Plusieurs dc doivent se recomposer dans l'ORDRE : les inverser
		// donnerait com.example, donc un domaine qui n'existe pas.
		{"uid=x,dc=a,dc=b,dc=c", "x", "a.b.c", ""},
	}

	for _, c := range cas {
		user, domaine, ou := ldaptools.ExtractUsernameAndDomain(c.entree)
		ok := user == c.user && domaine == c.domaine && ou == c.ou
		out = append(out, Result{
			"LDAP/DN: " + c.entree,
			ok,
			fmt.Sprintf("obtenu user=%q domaine=%q ou=%q, attendu user=%q domaine=%q ou=%q",
				user, domaine, ou, c.user, c.domaine, c.ou),
		})
	}

	// Une chaîne vide ne doit rien produire d'exploitable — surtout pas un
	// utilisateur vide qu'un appelant prendrait pour un identifiant valide.
	user, domaine, ou := ldaptools.ExtractUsernameAndDomain("")
	out = append(out, Result{
		"LDAP/DN: une entree vide ne fabrique pas d'identite",
		user == "" && domaine == "" && ou == "",
		fmt.Sprintf("obtenu user=%q domaine=%q ou=%q", user, domaine, ou),
	})

	return out
}

// utilisateurAvecOperationnels construit une VRAIE UserEntry.
//
// Le test des attributs opérationnels ne peut pas se contenter de l'entrée
// factice : c'est la logique de sélection de `candidate.UserEntry` qui est en
// cause, pas l'interface.
func utilisateurAvecOperationnels() candidate.UserEntry {
	return candidate.UserEntry{
		User: ldapstorage.User{
			Username:  "jdupont",
			Firstname: "Jean",
			Lastname:  "Dupont",
			Email:     "jean.dupont@vaultaire.local",
		},
		BaseDN: "dc=vaultaire,dc=local",
		Groups: []string{"cn=admins,ou=groups,dc=vaultaire,dc=local"},
	}
}
