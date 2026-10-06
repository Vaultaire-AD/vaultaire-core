package ldap

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// TO-DO 145, de bout en bout : une vraie session, sur un tube, à travers la
// boucle de lecture, le décodeur, le répartiteur et les fonctions de réponse.
//
// Les tests de ldapjournal éprouvent la mise en forme. Celui-ci éprouve le
// CÂBLAGE : que la boucle ouvre bien le journal, que les réponses y notent leur
// code, que l'unbind ferme sans laisser d'erreur — ce qu'aucun des morceaux ne
// montre seul.

// rechercheRootDSE forge la recherche que tout client envoie en premier :
// base vide, portée base, (objectClass=*). Elle ne touche pas la base.
func rechercheRootDSE(messageID int) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapstorage.AppSearchRequest, nil, "SearchRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "BaseObject"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "DerefAliases"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "SizeLimit"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "TimeLimit"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "TypesOnly"))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "Present"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "namingContexts", "attr"))
	op.AppendChild(attrs)
	return message(messageID, op)
}

// avecPage ajoute à un message le contrôle de pagination (RFC 2696).
func avecPage(paquet []byte, taille int) []byte {
	m := ber.DecodePacket(paquet)
	valeur := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "realSearchControlValue")
	valeur.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(taille), "size"))
	valeur.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "cookie"))
	controle := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	controle.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		ldapstorage.OIDPagedResults, "controlType"))
	controle.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		string(valeur.Bytes()), "controlValue"))
	controles := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	controles.AppendChild(controle)
	m.AppendChild(controles)
	return m.Bytes()
}

func unbind(messageID int) []byte {
	return message(messageID, ber.Encode(ber.ClassApplication, ber.TypePrimitive, ldapstorage.AppUnbindRequest, nil, "UnbindRequest"))
}

// conversation joue RootDSE puis unbind sur une session, et rend les lignes
// émises, niveau et message.
func conversation(t *testing.T) []string {
	t.Helper()
	return jouer(t, rechercheRootDSE(1), unbind(2))
}

// jouer envoie des paquets sur une session et rend les lignes émises.
func jouer(t *testing.T, paquets ...[]byte) []string {
	t.Helper()

	var mu sync.Mutex
	var lignes []string
	logs.BrancherSortie(func(e logs.LogEntry) {
		if !strings.HasPrefix(e.Message, "ldap ") {
			return
		}
		mu.Lock()
		lignes = append(lignes, e.Level+" "+e.Message)
		mu.Unlock()
	})
	t.Cleanup(func() { logs.BrancherSortie(nil) })

	client, serveur := net.Pipe()
	defer client.Close()

	fini := make(chan struct{})
	go func() {
		defer close(fini)
		handleLDAPSession(serveur, "LDAP", "")
	}()

	// Un tube est synchrone : les réponses doivent être lues pour que le
	// serveur avance.
	go io.Copy(io.Discard, client)

	for _, paquet := range paquets {
		if _, err := client.Write(paquet); err != nil {
			t.Fatalf("envoi : %v", err)
		}
	}

	select {
	case <-fini:
	case <-time.After(5 * time.Second):
		t.Fatal("la session ne se termine pas après l'unbind")
	}

	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), lignes...)
}

func avecDetail(t *testing.T, debug bool, ldap *logs.Detail) {
	t.Helper()
	ancien := storage.Debug
	storage.Debug = debug
	if ldap != nil {
		logs.ReglerDetail(logs.SousLDAP, *ldap)
	}
	t.Cleanup(func() {
		storage.Debug = ancien
		logs.LaisserDetail(logs.SousLDAP)
	})
}

// sansNumero retire ce qui change d'une exécution à l'autre : le numéro de
// connexion, les durées, l'adresse du tube.
func sansNumero(ligne string) string {
	champs := strings.Fields(ligne)
	for i, c := range champs {
		if strings.HasPrefix(c, "conn=") {
			champs[i] = "conn=N"
		}
	}
	return strings.Join(champs, " ")
}

// LE test du point : en debug, une session écrit UNE ligne par opération.
func TestUneSessionEcritUneLigneParOperation(t *testing.T) {
	debug := logs.DetailDebug
	avecDetail(t, false, &debug)

	lignes := conversation(t)

	if len(lignes) != 4 {
		t.Fatalf("%d ligne(s), attendu 4 — ouverture, recherche, unbind, fermeture :\n%s",
			len(lignes), strings.Join(lignes, "\n"))
	}
	for i, attendu := range []struct{ debut, contient string }{
		{"INFO ldap conn=N ouverte LDAP depuis", ""},
		{`DEBUG ldap conn=N msg=1 SEARCH base="" scope=base filtre="(objectClass=*)" attrs="namingContexts" → 0 success, 1 entrée(s),`, "candidats=1"},
		{"DEBUG ldap conn=N msg=2 UNBIND → sans réponse,", ""},
		{"DEBUG ldap conn=N fermée (unbind) après", "2 opération(s), 1 entrée(s), aucun compte lié"},
	} {
		l := sansNumero(lignes[i])
		if !strings.HasPrefix(l, attendu.debut) || !strings.Contains(l, attendu.contient) {
			t.Errorf("ligne %d = %q\n  attendu : début %q, contenant %q", i, l, attendu.debut, attendu.contient)
		}
	}
	// Les quatre lignes portent le MÊME numéro : c'est ce qui permet de
	// filtrer une conversation.
	numero := ""
	for _, l := range lignes {
		for _, c := range strings.Fields(l) {
			if strings.HasPrefix(c, "conn=") {
				if numero == "" {
					numero = c
				} else if c != numero {
					t.Errorf("deux numéros de connexion dans la même session : %s et %s", numero, c)
				}
			}
		}
	}
}

// La demande de la recette : le debug allumé partout, l'annuaire coupé. Il ne
// reste de la session que sa ligne d'ouverture.
func TestLAnnuaireSeCoupeSousLeDebugGeneral(t *testing.T) {
	coupe := logs.DetailCoupe
	avecDetail(t, true, &coupe)

	lignes := conversation(t)

	if len(lignes) != 1 || !strings.HasPrefix(lignes[0], "INFO ldap conn=") {
		t.Fatalf("lignes émises avec « ldap: off » sous debug=true :\n%s", strings.Join(lignes, "\n"))
	}
}

// Sans rien régler, `debug: true` donne le DEBUG de l'annuaire — une ligne par
// opération — et jamais le déroulé.
func TestLeDebugGeneralNeDonnePasLeDeroule(t *testing.T) {
	avecDetail(t, true, nil)

	for _, l := range conversation(t) {
		if strings.HasPrefix(l, "TRACE") {
			t.Fatalf("ligne de déroulé sous le seul debug général : %s", l)
		}
	}
}

// En trace, le déroulé sort — paquets reçus compris — et chaque ligne porte le
// numéro de la connexion.
func TestLeDerouleDUneSession(t *testing.T) {
	trace := logs.DetailTrace
	avecDetail(t, false, &trace)

	lignes := conversation(t)

	var deroule []string
	for _, l := range lignes {
		if !strings.Contains(l, " ldap conn=") {
			t.Errorf("ligne sans numéro de connexion : %s", l)
		}
		if strings.HasPrefix(l, "TRACE") {
			deroule = append(deroule, l)
		}
	}
	if len(deroule) < 2 {
		t.Fatalf("déroulé = %v : attendu au moins les deux paquets reçus", deroule)
	}
	if !strings.Contains(strings.Join(deroule, "\n"), "paquet reçu") {
		t.Errorf("le vidage des paquets a disparu du déroulé : %v", deroule)
	}
}

// La pagination figure sur la ligne. Elle est rangée dans la recherche par le
// répartiteur, APRÈS que la boucle de lecture a décrit l'opération : sans la
// seconde description, la ligne d'une recherche paginée ne disait pas qu'elle
// l'était — et c'est la première chose qu'on y cherche quand un client boucle.
func TestLaPaginationFigureSurLaLigne(t *testing.T) {
	debug := logs.DetailDebug
	avecDetail(t, false, &debug)

	lignes := jouer(t, avecPage(rechercheRootDSE(1), 500), unbind(2))

	for _, l := range lignes {
		if strings.Contains(l, "msg=1 SEARCH") {
			if !strings.Contains(l, " page=500 ") {
				t.Fatalf("la ligne ne dit pas que la recherche est paginée : %s", l)
			}
			return
		}
	}
	t.Fatalf("aucune ligne pour la recherche :\n%s", strings.Join(lignes, "\n"))
}
