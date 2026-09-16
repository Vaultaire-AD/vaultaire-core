package serveurauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La liste d'empreintes de confiance.
//
// # Ce que ces tests gardent
//
// Le fichier d'empreintes est ce qui empêche un tiers de se faire passer pour le
// core. Une seule chose compte vraiment : qu'aucun chemin ne fasse ACCEPTER une
// clé qui ne figure pas dans la liste, et qu'aucun ne fasse REFUSER une clé qui
// y figure.
//
// Le second défaut est le plus insidieux. Refuser un core légitime coupe le
// parc, et le réflexe devant une machine coupée est d'effacer le fichier
// d'empreintes — c'est-à-dire de désactiver la vérification pour rétablir le
// service. Un faux refus finit donc par produire une machine sans protection.

func empreinteDeTest(c byte) string {
	return "SHA256:" + strings.Repeat(string(c), 43)
}

func ecrireListe(t *testing.T, dir string, lignes ...string) {
	t.Helper()
	chemin := filepath.Join(dir, FingerprintFileName)
	contenu := strings.Join(lignes, "\n") + "\n"
	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		t.Fatalf("écriture : %v", err)
	}
}

func TestUneListeEstLueEnEntier(t *testing.T) {
	dir := repertoireDeTest(t)
	a, b, c := empreinteDeTest('A'), empreinteDeTest('B'), empreinteDeTest('C')
	ecrireListe(t, dir, "# posées à l'installation", a, "", b, "# apprise le 14 août", c)

	liste, err := EmpreintesAttendues()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(liste) != 3 || liste[0] != a || liste[1] != b || liste[2] != c {
		t.Fatalf("liste = %v, attendu [%s %s %s] dans cet ordre", liste, a, b, c)
	}
}

// TestLOrdreEstConserve.
//
// La PREMIÈRE ligne est celle déposée par `-join`, donc la seule dont on sache
// par quel canal elle est arrivée. Trier la liste effacerait cette information,
// et personne ne pourrait plus dire, en lisant le fichier, laquelle a été
// apprise.
func TestLOrdreEstConserve(t *testing.T) {
	dir := repertoireDeTest(t)
	z, a := empreinteDeTest('Z'), empreinteDeTest('A')
	ecrireListe(t, dir, z, a)

	liste, _ := EmpreintesAttendues()
	if len(liste) != 2 || liste[0] != z {
		t.Errorf("liste = %v : l'ordre du fichier doit être conservé", liste)
	}
}

// TestUneLigneMalformeeNEmportePasLesAutres.
//
// Le cas qui compte : une faute de frappe dans le fichier ne doit pas faire
// perdre les empreintes valides qui l'entourent. Les perdre ferait retomber la
// machine en confiance au premier usage — c'est-à-dire désactiver la
// vérification au moment précis où le fichier est douteux.
func TestUneLigneMalformeeNEmportePasLesAutres(t *testing.T) {
	dir := repertoireDeTest(t)
	bonne := empreinteDeTest('A')
	ecrireListe(t, dir, "MD5:pas-la-bonne-fonction", bonne, "n'importe quoi")

	liste, err := EmpreintesAttendues()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(liste) != 1 || liste[0] != bonne {
		t.Fatalf("liste = %v, attendu [%s] : une ligne fautive a emporté les autres", liste, bonne)
	}
}

func TestLesDoublonsSontEcartes(t *testing.T) {
	dir := repertoireDeTest(t)
	a := empreinteDeTest('A')
	ecrireListe(t, dir, a, a, a)

	if liste, _ := EmpreintesAttendues(); len(liste) != 1 {
		t.Errorf("liste = %v, attendu une seule entrée", liste)
	}
}

// TestNImporteLaquelleDesEmpreintesSuffit.
//
// LE test de ce lot. Sans lui, distribuer une liste de cores ne servirait à
// rien : l'agent refuserait tous ceux qu'il ne connaît pas, c'est-à-dire tous
// sauf le premier.
func TestNImporteLaquelleDesEmpreintesSuffit(t *testing.T) {
	dir := repertoireDeTest(t)
	cle := clePubliquePEM(t)
	sienne, err := EmpreinteClePublique(cle)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// La bonne empreinte est en DERNIÈRE position, précédée de deux autres.
	ecrireListe(t, dir, empreinteDeTest('A'), empreinteDeTest('B'), sienne)

	avertissement, err := VerifierCleCore(cle)
	if err != nil {
		t.Fatalf("clé légitime refusée alors qu'elle figure dans la liste : %v", err)
	}
	if avertissement != "" {
		t.Errorf("avertissement %q : la clé est attestée, rien à signaler", avertissement)
	}
}

// TestUneCleAbsenteDeLaListeEstRefusee : la garantie elle-même.
func TestUneCleAbsenteDeLaListeEstRefusee(t *testing.T) {
	dir := repertoireDeTest(t)
	ecrireListe(t, dir, empreinteDeTest('A'), empreinteDeTest('B'))

	_, err := VerifierCleCore(clePubliquePEM(t))
	if err == nil {
		t.Fatal("une clé absente de la liste a été acceptée")
	}
	var inattendue *ErrCleCoreInattendue
	if !erreurEst(err, &inattendue) {
		t.Fatalf("erreur %T, attendu *ErrCleCoreInattendue — l'appelant doit pouvoir "+
			"distinguer ce cas d'une panne de réseau", err)
	}
	if len(inattendue.Attendues) != 2 {
		t.Errorf("%d empreinte(s) dans le message, attendu 2 : sur un parc à "+
			"plusieurs cores, n'en montrer qu'une fait chercher au mauvais endroit",
			len(inattendue.Attendues))
	}
}

// --- apprentissage ----------------------------------------------------------

// TestOnNApprendPasSansAncrage.
//
// La règle de l'arbitrage 3. Une liste vide signifie que la machine n'a aucun
// point d'ancrage : y ajouter une empreinte reçue du réseau serait de la
// confiance au premier usage sous un autre nom.
func TestOnNApprendPasSansAncrage(t *testing.T) {
	repertoireDeTest(t)

	appris, err := ApprendreEmpreinte(empreinteDeTest('A'))
	if err == nil {
		t.Fatal("une empreinte a été apprise alors qu'aucune n'était connue")
	}
	if appris {
		t.Error("appris = vrai malgré l'erreur")
	}
	if _, err := os.Stat(CoreFingerprintPath()); err == nil {
		t.Error("le fichier a été créé : la machine se retrouverait avec une " +
			"empreinte venue du réseau et d'elle seule")
	}
}

func TestUneEmpreinteApprisSAjouteEnQueue(t *testing.T) {
	dir := repertoireDeTest(t)
	origine := empreinteDeTest('A')
	ecrireListe(t, dir, origine)

	nouvelle := empreinteDeTest('B')
	appris, err := ApprendreEmpreinte(nouvelle)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !appris {
		t.Error("appris = faux sur une empreinte nouvelle")
	}

	liste, _ := EmpreintesAttendues()
	if len(liste) != 2 || liste[0] != origine || liste[1] != nouvelle {
		t.Fatalf("liste = %v, attendu [%s %s] — celle de l'installation doit "+
			"rester en tête", liste, origine, nouvelle)
	}
}

// TestApprendreDeuxFoisNEstPasUneErreur : le cas courant, à chaque 04_04.
func TestApprendreDeuxFoisNEstPasUneErreur(t *testing.T) {
	dir := repertoireDeTest(t)
	a := empreinteDeTest('A')
	ecrireListe(t, dir, a)

	appris, err := ApprendreEmpreinte(a)
	if err != nil {
		t.Fatalf("réapprendre une empreinte connue a produit une erreur : %v", err)
	}
	if appris {
		t.Error("appris = vrai sur une empreinte déjà connue")
	}
	if liste, _ := EmpreintesAttendues(); len(liste) != 1 {
		t.Errorf("liste = %v : le fichier a grossi sans raison", liste)
	}
}

// TestLaListeEstBornee.
//
// Un fichier de confiance qui grossit tout seul finit par ne plus rien attester :
// personne ne relit trente empreintes pour savoir laquelle n'a rien à y faire.
//
// Le refus est EXPLICITE plutôt qu'une éviction de la plus ancienne — qui
// retirerait justement celle déposée à l'installation, la seule dont on connaisse
// le canal.
func TestLaListeEstBornee(t *testing.T) {
	dir := repertoireDeTest(t)

	lignes := make([]string, 0, MaxEmpreintes)
	for i := 0; i < MaxEmpreintes; i++ {
		lignes = append(lignes, "SHA256:"+strings.Repeat(string(rune('a'+i)), 43))
	}
	ecrireListe(t, dir, lignes...)

	appris, err := ApprendreEmpreinte(empreinteDeTest('Z'))
	if err == nil {
		t.Fatal("une empreinte a été ajoutée au-delà de la borne")
	}
	if appris {
		t.Error("appris = vrai malgré l'erreur")
	}

	liste, _ := EmpreintesAttendues()
	if len(liste) != MaxEmpreintes {
		t.Errorf("%d empreinte(s) après refus, attendu %d — rien ne devait bouger",
			len(liste), MaxEmpreintes)
	}
	if liste[0] != lignes[0] {
		t.Error("la première empreinte a été évincée : c'est celle de l'installation")
	}
}

func TestUneEmpreinteMalFormeeNEstPasApprise(t *testing.T) {
	dir := repertoireDeTest(t)
	ecrireListe(t, dir, empreinteDeTest('A'))

	for _, mauvaise := range []string{"", "abcdef", "MD5:xxx", "sha256:minuscules"} {
		if _, err := ApprendreEmpreinte(mauvaise); err == nil {
			t.Errorf("empreinte %q apprise alors qu'elle est mal formée", mauvaise)
		}
	}
	if liste, _ := EmpreintesAttendues(); len(liste) != 1 {
		t.Errorf("liste = %v : une valeur mal formée est entrée dans le fichier", liste)
	}
}

// --- la clé locale ----------------------------------------------------------

// TestUneCleLocaleApprisEstConservee.
//
// Régression. Si la clé locale n'était comparée qu'à la PREMIÈRE empreinte,
// celle d'un core appris serait écartée à chaque démarrage : l'agent la
// redemanderait, la vérification — qui parcourt toute la liste — l'accepterait,
// et il la réécrirait. Une boucle sans effet visible, sinon un aller-retour
// réseau à chaque cycle.
func TestUneCleLocaleApprisEstConservee(t *testing.T) {
	dir := repertoireDeTest(t)
	cle := clePubliquePEM(t)
	sienne, err := EmpreinteClePublique(cle)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// La clé en place correspond à la SECONDE empreinte, apprise.
	ecrireListe(t, dir, empreinteDeTest('A'), sienne)
	if err := os.WriteFile(filepath.Join(dir, "serveurpublickey.pem"), []byte(cle), 0o644); err != nil {
		t.Fatalf("%v", err)
	}

	if aEcarter, motif := CleLocaleConforme(); aEcarter {
		t.Fatalf("une clé conforme à une empreinte apprise a été écartée : %s", motif)
	}
}

// erreurEst est un errors.As allégé, pour ne pas alourdir les imports du test.
func erreurEst(err error, cible **ErrCleCoreInattendue) bool {
	e, ok := err.(*ErrCleCoreInattendue)
	if ok {
		*cible = e
	}
	return ok
}
