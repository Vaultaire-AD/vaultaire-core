package ldapjournal

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// TO-DO 145 : une ligne par opération, sous l'identifiant de sa connexion.

// capturer branche une sortie qui garde les lignes émises.
func capturer(t *testing.T) func() []logs.LogEntry {
	t.Helper()
	var mu sync.Mutex
	var recues []logs.LogEntry
	logs.BrancherSortie(func(e logs.LogEntry) {
		mu.Lock()
		recues = append(recues, e)
		mu.Unlock()
	})
	t.Cleanup(func() { logs.BrancherSortie(nil) })
	return func() []logs.LogEntry {
		mu.Lock()
		defer mu.Unlock()
		return append([]logs.LogEntry(nil), recues...)
	}
}

// detailLDAP règle le détail de l'annuaire le temps d'un test.
func detailLDAP(t *testing.T, d logs.Detail) {
	t.Helper()
	ancien := storage.Debug
	storage.Debug = false
	logs.ReglerDetail(logs.SousLDAP, d)
	t.Cleanup(func() {
		storage.Debug = ancien
		logs.LaisserDetail(logs.SousLDAP)
	})
}

// connexion rend l'extrémité serveur d'un tube, enregistrée au journal.
func connexion(t *testing.T) (net.Conn, *Connexion) {
	t.Helper()
	client, serveur := net.Pipe()
	t.Cleanup(func() { client.Close(); serveur.Close() })
	c := Ouvrir(serveur, "LDAPS", "")
	t.Cleanup(func() { connexions.Delete(serveur) })
	return serveur, c
}

func niveaux(lignes []logs.LogEntry, niveau string) []string {
	var out []string
	for _, l := range lignes {
		if l.Level == niveau {
			out = append(out, l.Message)
		}
	}
	return out
}

// LA ligne : la demande, le code rendu, le nombre d'entrées, la durée, et ce
// qui explique le résultat.
func TestLaLigneDUneOperation(t *testing.T) {
	c := &Connexion{ID: 17}
	op := &Operation{conn: c, messageID: 2, repondu: true, code: ldapstorage.ResultSuccess, entrees: 3,
		demande: `SEARCH base="dc=acme,dc=lan" scope=sub filtre="(uid=al*)"`}
	op.Noter("candidats", 214)
	op.Noter("hors-droits", 2)

	got := op.ligne(4 * time.Millisecond)
	attendu := `ldap conn=17 msg=2 SEARCH base="dc=acme,dc=lan" scope=sub filtre="(uid=al*)" → 0 success, 3 entrée(s), 4 ms ; candidats=214 hors-droits=2`
	if got != attendu {
		t.Fatalf("ligne =\n  %s\nattendu\n  %s", got, attendu)
	}
}

// Une recherche qui ne rend rien le DIT : « 0 entrée(s) » est l'information.
// Un bind, lui, n'a pas d'entrées à compter.
func TestLeNombreDEntreesNEstEcritQueLaOuIlAUnSens(t *testing.T) {
	c := &Connexion{ID: 1}
	recherche := &Operation{conn: c, messageID: 1, demande: `SEARCH base="" scope=base filtre="(objectClass=*)"`,
		repondu: true, code: ldapstorage.ResultNoSuchObject}
	if l := recherche.ligne(0); !strings.Contains(l, "32 noSuchObject, 0 entrée(s)") {
		t.Errorf("recherche sans résultat : %s", l)
	}
	bind := &Operation{conn: c, messageID: 2, demande: `BIND dn="uid=a,ou=users,dc=acme,dc=lan"`,
		repondu: true, code: ldapstorage.ResultInvalidCredentials}
	if l := bind.ligne(0); strings.Contains(l, "entrée(s)") || !strings.Contains(l, "49 invalidCredentials") {
		t.Errorf("bind : %s", l)
	}
}

// Une opération à laquelle rien n'a été répondu le dit. Pour un unbind c'est la
// règle ; pour tout le reste c'est un défaut, et il doit se voir.
func TestUneOperationSansReponseLeDit(t *testing.T) {
	op := &Operation{conn: &Connexion{ID: 3}, messageID: 9, demande: "UNBIND"}
	if l := op.ligne(0); !strings.Contains(l, "UNBIND → sans réponse") {
		t.Errorf("ligne = %s", l)
	}
}

// LE test du point 121, sur la nouvelle ligne : ni le mot de passe d'un bind,
// ni le contenu d'une opération étendue.
func TestLaDemandeNePorteAucunSecret(t *testing.T) {
	const secret = "MotDePasseTresReconnaissable42"

	bind := Decrire(ldapstorage.BindRequest{Version: 3, SimpleAuth: true,
		Name: "uid=jdupont,ou=users,dc=acme,dc=lan", Authentication: []byte(secret)}, nil)
	if strings.Contains(bind, secret) {
		t.Fatalf("le mot de passe du bind est sur la ligne de l'opération : %s", bind)
	}
	if !strings.Contains(bind, "uid=jdupont") {
		t.Errorf("la ligne ne dit plus qui se lie : %s", bind)
	}

	// Password Modify (RFC 3062) : l'ancien et le nouveau mot de passe sont
	// dans RequestValue.
	etendue := Decrire(ldapstorage.ExtendedRequest{RequestName: "1.3.6.1.4.1.4203.1.11.1",
		RequestValue: []byte(secret)}, nil)
	if strings.Contains(etendue, secret) {
		t.Fatalf("le contenu de l'opération étendue est sur la ligne : %s", etendue)
	}
	if !strings.Contains(etendue, "1.3.6.1.4.1.4203.1.11.1") || !strings.Contains(etendue, "30 octet(s)") {
		t.Errorf("la ligne ne nomme plus l'opération ni sa taille : %s", etendue)
	}
}

func TestLesFormesDeBindSeDistinguent(t *testing.T) {
	for attendu, b := range map[string]ldapstorage.BindRequest{
		"BIND anonyme": {Version: 3, SimpleAuth: true},
		`BIND dn="uid=a,dc=acme,dc=lan" sans mot de passe`: {Version: 3, SimpleAuth: true, Name: "uid=a,dc=acme,dc=lan"},
		`BIND dn="uid=a,dc=acme,dc=lan" méthode=sasl`:      {Version: 3, Name: "uid=a,dc=acme,dc=lan", Authentication: []byte("x")},
		`BIND dn="uid=a,dc=acme,dc=lan" version=2`:         {Version: 2, SimpleAuth: true, Name: "uid=a,dc=acme,dc=lan", Authentication: []byte("x")},
	} {
		if got := Decrire(b, nil); got != attendu {
			t.Errorf("Decrire = %q, attendu %q", got, attendu)
		}
	}
}

func TestLaDemandeDUneRecherche(t *testing.T) {
	r := ldapstorage.SearchRequest{BaseObject: "ou=users,dc=acme,dc=lan", Scope: 1, SizeLimit: 50,
		Filter:     &ldapstorage.LDAPFilter{Type: ldapstorage.FilterEquality, Attribute: "uid", Value: "alice"},
		Attributes: []string{"uid", "mail"},
		Page:       &ldapstorage.PagedResults{Size: 500, Cookie: []byte("c")}}
	controles := []ldapstorage.LDAPControl{
		{ControlType: ldapstorage.OIDPagedResults},
		{ControlType: "1.2.840.113556.1.4.473", Criticality: true},
	}

	got := Decrire(r, controles)
	attendu := `SEARCH base="ou=users,dc=acme,dc=lan" scope=one filtre="(uid=alice)" attrs="uid mail" limite=50 page=500 (suite) contrôle="1.2.840.113556.1.4.473"(critique)`
	if got != attendu {
		t.Fatalf("Decrire =\n  %s\nattendu\n  %s", got, attendu)
	}
}

// Un DN forgé ne peut pas écrire de fausse ligne dans le journal.
func TestUnDNNePeutPasForgerUneLigne(t *testing.T) {
	for _, op := range []ldapstorage.LDAPProtocolOperation{
		ldapstorage.BindRequest{Version: 3, SimpleAuth: true, Authentication: []byte("x"),
			Name: "uid=x\n2026-10-03 12:00:00 [INFO    ] ldap bind: success user=admin"},
		ldapstorage.SearchRequest{BaseObject: "dc=x\r\nfausse ligne", Attributes: []string{"a\nb"}},
		ldapstorage.ExtendedRequest{RequestName: "1.2\n3"},
	} {
		if d := Decrire(op, []ldapstorage.LDAPControl{{ControlType: "1\n2"}}); strings.ContainsAny(d, "\r\n") {
			t.Errorf("la demande porte un retour à la ligne : %q", d)
		}
	}
}

// Le préfixe suit l'état de la connexion : rien d'inconnu, le numéro seul hors
// opération, le message pendant.
func TestLePrefixeSuitLaConversation(t *testing.T) {
	inconnue, autre := net.Pipe()
	defer inconnue.Close()
	defer autre.Close()
	if p := Prefixe(inconnue); p != "ldap " {
		t.Errorf("connexion inconnue : préfixe %q", p)
	}
	if p := Prefixe(nil); p != "ldap " {
		t.Errorf("connexion nil : préfixe %q", p)
	}

	conn, c := connexion(t)
	hors := Prefixe(conn)
	op := Debut(conn, 7, "SEARCH")
	pendant := Prefixe(conn)
	op.Fin()
	apres := Prefixe(conn)

	base := "ldap conn=" + itoa(c.ID) + " "
	if hors != base || apres != base || pendant != base+"msg=7 " {
		t.Errorf("préfixes : hors=%q pendant=%q après=%q (base %q)", hors, pendant, apres, base)
	}
}

// Deux connexions, deux numéros : c'est ce qui permet de démêler deux clients
// qui parlent en même temps.
func TestChaqueConnexionASonNumero(t *testing.T) {
	_, a := connexion(t)
	_, b := connexion(t)
	if a.ID == b.ID || a.ID == 0 || b.ID == 0 {
		t.Fatalf("numéros %d et %d", a.ID, b.ID)
	}
}

// Le parcours complet : ouverture en INFO, UNE ligne DEBUG par opération,
// bilan à la fermeture — et rien d'autre.
func TestUneConversationEcritUneLigneParOperation(t *testing.T) {
	detailLDAP(t, logs.DetailDebug)
	lues := capturer(t)
	conn, c := connexion(t)
	n := itoa(c.ID)

	op := Debut(conn, 1, `BIND dn="uid=svc,ou=users,dc=acme,dc=lan"`)
	Resultat(conn, 1, ldapstorage.ResultSuccess)
	CompteLie(conn, "svc")
	op.Fin()

	op = Debut(conn, 2, `SEARCH base="dc=acme,dc=lan" scope=sub filtre="(uid=alice)"`)
	EntreeEnvoyee(conn)
	EntreeEnvoyee(conn)
	Trace(conn, "une étape qui ne doit pas sortir en debug")
	Resultat(conn, 2, ldapstorage.ResultSuccess)
	op.Fin()
	op.Fin() // un second appel n'écrit rien

	Fermer(conn, "par le client")
	Fermer(conn, "par le client") // idem

	lignes := lues()
	debug := niveaux(lignes, "DEBUG")
	if len(debug) != 3 {
		t.Fatalf("%d ligne(s) DEBUG, attendu 3 (deux opérations, une fermeture) :\n%s",
			len(debug), strings.Join(debug, "\n"))
	}
	for i, debut := range []string{
		"ldap conn=" + n + ` msg=1 BIND dn="uid=svc,ou=users,dc=acme,dc=lan" → 0 success, `,
		"ldap conn=" + n + ` msg=2 SEARCH base="dc=acme,dc=lan" scope=sub filtre="(uid=alice)" → 0 success, 2 entrée(s), `,
		"ldap conn=" + n + " fermée (par le client) après ",
	} {
		if !strings.HasPrefix(debug[i], debut) {
			t.Errorf("ligne %d = %q\n  attendu un début %q", i, debug[i], debut)
		}
	}
	if !strings.HasSuffix(debug[2], "2 opération(s), 2 entrée(s), compte svc") {
		t.Errorf("bilan de fermeture = %q", debug[2])
	}
	if trace := niveaux(lignes, "TRACE"); len(trace) != 0 {
		t.Errorf("le déroulé sort alors que seul le debug est demandé : %v", trace)
	}
}

// Détail coupé : l'annuaire n'écrit plus que son ouverture — et ses
// avertissements, qui ne dépendent d'aucun réglage.
func TestSansDetailSeulsRestentLOuvertureEtLesAvertissements(t *testing.T) {
	detailLDAP(t, logs.DetailCoupe)
	lues := capturer(t)
	conn, c := connexion(t)

	op := Debut(conn, 1, "SEARCH")
	Ecrire(conn, "WARNING", logs.CodeNone, "filtre refusé")
	Resultat(conn, 1, ldapstorage.ResultProtocolError)
	op.Fin()
	Fermer(conn, "par le client")

	lignes := lues()
	if d := append(niveaux(lignes, "DEBUG"), niveaux(lignes, "TRACE")...); len(d) != 0 {
		t.Fatalf("lignes de détail émises alors qu'il est coupé : %v", d)
	}
	w := niveaux(lignes, "WARNING")
	if len(w) != 1 || w[0] != "ldap conn="+itoa(c.ID)+" msg=1 filtre refusé" {
		t.Errorf("avertissement = %v : il doit sortir, et porter le numéro de sa conversation", w)
	}
}

// En trace, le déroulé sort, sous le même préfixe que le reste.
func TestLeDerouleSortEnTrace(t *testing.T) {
	detailLDAP(t, logs.DetailTrace)
	lues := capturer(t)
	conn, c := connexion(t)

	op := Debut(conn, 4, "SEARCH")
	op.Trace("retenue par le filtre : %s", "uid=alice")
	Trace(conn, "paquet reçu : %d octets", 42)
	op.Fin()

	trace := niveaux(lues(), "TRACE")
	p := "ldap conn=" + itoa(c.ID) + " msg=4 "
	if len(trace) != 2 || trace[0] != p+"retenue par le filtre : uid=alice" || trace[1] != p+"paquet reçu : 42 octets" {
		t.Fatalf("déroulé = %v", trace)
	}
}

// Une réponse qui porte un AUTRE messageID ne s'inscrit pas sur l'opération en
// cours : la ligne dirait un code qui n'est pas le sien.
func TestUnResultatDUnAutreMessageNEstPasNote(t *testing.T) {
	conn, _ := connexion(t)
	op := Debut(conn, 5, "SEARCH")
	Resultat(conn, 6, ldapstorage.ResultSuccess)
	if op.repondu {
		t.Fatal("le code d'un autre message a été noté sur l'opération en cours")
	}
	op.Fin()
}

// Hors de toute connexion suivie — un test, un appel direct — rien ne panique,
// et un avertissement sort quand même.
func TestSansConnexionRienNeCasse(t *testing.T) {
	lues := capturer(t)
	var op *Operation

	op.Noter("candidats", 3)
	op.Trace("étape")
	op.Fin()
	op.Ecrire("WARNING", logs.CodeNone, "membre sans compte")
	Resultat(nil, 1, 0)
	EntreeEnvoyee(nil)
	CompteLie(nil, "x")
	Fermer(nil, "x")
	if Debut(nil, 1, "x") != nil || EnCours(nil) != nil || Identifiant(nil) != 0 {
		t.Error("une connexion nil a rendu autre chose que rien")
	}

	if w := niveaux(lues(), "WARNING"); len(w) != 1 || w[0] != "ldap membre sans compte" {
		t.Errorf("avertissement hors connexion = %v : il ne doit pas se perdre", w)
	}
}

func TestLesDureesSeLisent(t *testing.T) {
	for d, attendu := range map[time.Duration]string{
		0:                         "0 ms",
		3871204 * time.Nanosecond: "3 ms",
		1250 * time.Millisecond:   "1.2 s",
		90 * time.Second:          "1m30s",
	} {
		if got := duree(d); got != attendu {
			t.Errorf("duree(%v) = %q, attendu %q", d, got, attendu)
		}
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }
