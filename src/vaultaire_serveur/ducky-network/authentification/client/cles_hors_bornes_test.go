package client

import (
	"strings"
	"testing"

	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/sendmessage"
)

var errLecture = errString("lecture des clés impossible")

type errString string

func (e errString) Error() string { return string(e) }

// TestUnCompteAuxBornesPasse : dix clés de 4 096 caractères, le maximum que
// l'ajout accepte, doivent toujours tenir — sinon le contrôle du 138
// refuserait des comptes que rien n'a dépassés.
func TestUnCompteAuxBornesPasse(t *testing.T) {
	cles := make([]string, dbusers.MaxClesParCompte)
	for i := range cles {
		cles[i] = strings.Repeat("k", dbusers.LongueurMaxCle)
	}
	utilisateur := strings.Repeat("u", 255) + "@" + strings.Repeat("d", 255)
	trame := Acceptation(strings.Repeat("s", 128), utilisateur, true, strings.Join(cles, ","))
	if !sendmessage.TientDansUneTrame(trame) {
		t.Fatalf("un compte aux bornes de l'ajout serait refusé (%d octets chiffrés)",
			sendmessage.TailleChiffree(len(trame)))
	}
}

// TestLAcceptationGardeSaForme : la 02_04 est lue par les postes champ par
// champ. L'avoir sortie de CheckAuth ne doit pas en avoir déplacé un seul.
func TestLAcceptationGardeSaForme(t *testing.T) {
	got := Acceptation("CLE", "alice@acme.lan", true, "ssh-ed25519 AAAA a,ssh-ed25519 BBBB b")
	want := "02_04\nserveur_central\nCLE\nalice@acme.lan\ntrue\nssh-ed25519 AAAA a,ssh-ed25519 BBBB b\nYou are authentificate Has : \nalice@acme.lan"
	if got != want {
		t.Fatalf("trame 02_04 modifiée :\n got %q\nwant %q", got, want)
	}
}

// TestLeReleveDistingueCeQuiPartDeCeQuiNePartPlus (TO-DO 138).
func TestLeReleveDistingueCeQuiPartDeCeQuiNePartPlus(t *testing.T) {
	// Douze petites clés : au-delà du nombre, très loin de la taille.
	leger := dbusers.CompteHorsBornes{Utilisateur: "alice@acme.lan", Cles: 12, Caracteres: 12 * 100, PlusLongue: 100}
	if g := GraviteDuDepassement(leger); g != "WARNING" {
		t.Errorf("douze clés de cent caractères : gravité %s, attendu WARNING — la trame part", g)
	}
	m := MessageDuDepassement(leger)
	for _, attendu := range []string{`"alice@acme.lan"`, "12 clés (maximum 10)", "elle part encore", "Aucune clé n'est retirée", "vlt remove -u alice@acme.lan -k"} {
		if !strings.Contains(m, attendu) {
			t.Errorf("message du relevé sans %q :\n%s", attendu, m)
		}
	}

	// Soixante grosses clés RSA : le cas du constat.
	lourd := dbusers.CompteHorsBornes{Utilisateur: "bob@acme.lan", Cles: 60, Caracteres: 60 * 1200, PlusLongue: 1200}
	if g := GraviteDuDepassement(lourd); g != "ERROR" {
		t.Errorf("soixante clés de 1 200 caractères : gravité %s, attendu ERROR — la trame ne part plus", g)
	}
	m = MessageDuDepassement(lourd)
	for _, attendu := range []string{`"bob@acme.lan"`, "NE PEUT PLUS ouvrir de session", "Aucune clé n'est retirée"} {
		if !strings.Contains(m, attendu) {
			t.Errorf("message du relevé sans %q :\n%s", attendu, m)
		}
	}

	// Une seule clé, trop longue : c'est l'autre borne.
	longue := dbusers.CompteHorsBornes{Utilisateur: "carol@acme.lan", Cles: 1, Caracteres: 6000, PlusLongue: 6000}
	if m := MessageDuDepassement(longue); !strings.Contains(m, "une clé de 6000 caractères (maximum 4096)") {
		t.Errorf("la borne de longueur n'est pas nommée :\n%s", m)
	}
}

// TestLeRefusNommeLeCompte : la ligne du core doit porter le nom, le nombre de
// clés et la commande qui en retire — tout ce qui manquait à « trame de N
// octets ».
func TestLeRefusNommeLeCompte(t *testing.T) {
	m := MessageClesTropLourdes("bob@acme.lan", 60, 72000)
	for _, attendu := range []string{`"bob@acme.lan"`, "60 clé(s)", "72000 octets", "REFUSÉE", "aucune clé retirée", "vlt get -u bob@acme.lan -k", "vlt remove -u bob@acme.lan -k <id_clé>"} {
		if !strings.Contains(m, attendu) {
			t.Errorf("message de refus sans %q :\n%s", attendu, m)
		}
	}
}

func clesDEssai(nombre, longueur int) []storage.PublicKey {
	cles := make([]storage.PublicKey, nombre)
	for i := range cles {
		cles[i] = storage.PublicKey{Key: strings.Repeat("k", longueur)}
	}
	return cles
}

// LE cas du constat (TO-DO 138) : une soixantaine de grosses clés. Le compte
// est refusé AVANT que rien ne soit inscrit, par une trame qui part et qui dit
// pourquoi — au lieu d'une 02_04 que SendMessage jette sans nommer personne.
func TestUnCompteTropGarniEstRefuseParUneTrameQuiPart(t *testing.T) {
	acceptation, tient := ComposerAcceptation("CLE", "bob@acme.lan", false, clesDEssai(60, 1200), nil)
	if tient {
		t.Fatalf("soixante clés de 1 200 caractères tenues pour émissibles (%d octets chiffrés)",
			sendmessage.TailleChiffree(len(acceptation)))
	}

	refus := RefusPourPoids("CLE", "bob@acme.lan")
	if !sendmessage.TientDansUneTrame(refus) {
		t.Fatal("le refus lui-même ne tient pas dans une trame")
	}
	lignes := strings.Split(refus, "\n")
	// Le poste lit le compte en première ligne de contenu, le motif en seconde.
	if len(lignes) != 5 || lignes[0] != "02_07" || lignes[2] != "CLE" || lignes[3] != "bob@acme.lan" || !strings.Contains(lignes[4], "cles SSH") {
		t.Fatalf("refus mal formé pour le poste : %q", lignes)
	}
}

// Dix clés aux bornes : acceptées, et la trame porte TOUTES les clés — rien
// n'est tronqué pour la faire tenir.
func TestUnCompteAuxBornesGardeToutesSesCles(t *testing.T) {
	cles := clesDEssai(dbusers.MaxClesParCompte, dbusers.LongueurMaxCle)
	acceptation, tient := ComposerAcceptation("CLE", "alice@acme.lan", true, cles, nil)
	if !tient {
		t.Fatal("un compte aux bornes de l'ajout est refusé")
	}
	if n := strings.Count(acceptation, strings.Repeat("k", dbusers.LongueurMaxCle)); n != dbusers.MaxClesParCompte {
		t.Fatalf("%d clés dans la trame, attendu %d", n, dbusers.MaxClesParCompte)
	}
}

// Une lecture des clés en échec n'empêche pas d'entrer : « empty », comme avant.
func TestUneLectureDesClesEnEchecNeRefusePas(t *testing.T) {
	acceptation, tient := ComposerAcceptation("CLE", "alice@acme.lan", false, nil, errLecture)
	if !tient || !strings.Contains(acceptation, "\nempty\n") {
		t.Fatalf("acceptation sans clés lisibles : tient=%v %q", tient, acceptation)
	}
}
