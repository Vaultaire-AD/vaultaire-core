package gpo

import (
	"strings"
	"testing"
)

// L'ANALYSE des vérificateurs du magasin de confiance et du DNS.
//
// Aucune commande n'est lancée, aucun magasin système n'est lu : les certificats
// sont fabriqués ici, et la sortie de resolvectl est reproduite telle qu'elle
// apparaît sur une machine réelle.

// --- magasin de confiance ---------------------------------------------------

// Deux certificats minimaux mais VALIDES au sens PEM : le corps est du DER
// arbitraire, ce qui suffit — l'empreinte porte sur les octets décodés, elle ne
// demande pas un certificat X.509 bien formé.
const certA = `-----BEGIN CERTIFICATE-----
QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3ODkw
-----END CERTIFICATE-----
`

const certB = `-----BEGIN CERTIFICATE-----
Wllodmd0ZmVkY2JhMDk4NzY1NDMyMVpZWFdWVVRTUlFQT04=
-----END CERTIFICATE-----
`

func TestUneEmpreinteEstStableEtDistincte(t *testing.T) {
	a := EmpreintePEM(certA)
	b := EmpreintePEM(certB)

	if a == "" || b == "" {
		t.Fatalf("empreinte vide : a=%q b=%q", a, b)
	}
	if a == b {
		t.Error("deux certificats différents donnent la même empreinte")
	}
	if EmpreintePEM(certA) != a {
		t.Error("l'empreinte n'est pas stable d'un appel à l'autre")
	}
	if len(a) != 64 {
		t.Errorf("empreinte de %d caractères, 64 attendus pour un SHA-256 hexadécimal", len(a))
	}
}

// TestLEmpreinteResisteALaRemiseEnForme.
//
// LE test de ce lot. `update-ca-trust` réécrit les certificats qu'il agrège :
// longueur de ligne, fins de ligne, en-têtes. Une comparaison de TEXTE échouerait
// sur une machine parfaitement conforme — et signalerait une dérive que
// réappliquer ne corrigerait pas.
func TestLEmpreinteResisteALaRemiseEnForme(t *testing.T) {
	reference := EmpreintePEM(certA)

	// Même corps base64, découpé autrement et avec des fins de ligne Windows.
	remisEnForme := "-----BEGIN CERTIFICATE-----\r\n" +
		"QUJDREVGR0hJSktMTU5P\r\n" +
		"UFFSU1RVVldYWVoxMjM0\r\n" +
		"NTY3ODkw\r\n" +
		"-----END CERTIFICATE-----\r\n"

	if got := EmpreintePEM(remisEnForme); got != reference {
		t.Errorf("la remise en forme change l'empreinte :\n  %s\n  %s", reference, got)
	}
}

// bundle reproduit un magasin compilé : plusieurs certificats, des commentaires,
// et un bloc qui n'est pas un certificat.
var bundle = []byte("# Magasin de confiance genere automatiquement\n" +
	"# Ne pas editer\n" +
	certB +
	"\n# Autorite interne\n" +
	certA +
	"-----BEGIN DH PARAMETERS-----\nQUJD\n-----END DH PARAMETERS-----\n")

func TestUneCADuBundleEstTrouvee(t *testing.T) {
	for nom, cert := range map[string]string{"certA": certA, "certB": certB} {
		if !empreinteDansMagasin(bundle, EmpreintePEM(cert)) {
			t.Errorf("%s n'est pas trouvé dans le bundle alors qu'il y est", nom)
		}
	}
}

func TestUneCAAbsenteNEstPasTrouvee(t *testing.T) {
	absent := `-----BEGIN CERTIFICATE-----
bm90aGluZ3RvZG93aXRodGhlb3RoZXJzMDEyMzQ1Njc4OQ==
-----END CERTIFICATE-----
`
	if empreinteDansMagasin(bundle, EmpreintePEM(absent)) {
		t.Error("un certificat absent du bundle est déclaré présent")
	}
}

// TestUnBlocNonCertificatNEstPasCompte.
//
// Un bundle peut porter des paramètres DH ou des blocs « TRUSTED CERTIFICATE ».
// Les hacher comme des certificats ferait qu'un bloc quelconque de même contenu
// passerait pour la CA attendue.
func TestUnBlocNonCertificatNEstPasCompte(t *testing.T) {
	// Empreinte du corps du bloc DH présent dans le bundle.
	dh := "-----BEGIN DH PARAMETERS-----\nQUJD\n-----END DH PARAMETERS-----\n"
	if e := EmpreintePEM(dh); e != "" {
		t.Errorf("EmpreintePEM a rendu %q pour un bloc qui n'est pas un certificat", e)
	}
}

// TestUneEmpreinteVideNeTrouveJamaisRien.
//
// Une attente sans empreinte vient d'un état écrit par une version antérieure.
// La traiter comme « trouve tout » déclarerait conforme n'importe quoi ; la
// traiter comme « trouve rien » signalerait une dérive sur une machine saine.
// Le vérificateur, lui, ne compare pas du tout dans ce cas — c'est ici qu'on
// vérifie que la fonction sous-jacente ne trouve rien.
func TestUneEmpreinteVideNeTrouveJamaisRien(t *testing.T) {
	for _, vide := range []string{"", "   ", "\t"} {
		if empreinteDansMagasin(bundle, vide) {
			t.Errorf("empreinte %q déclarée présente", vide)
		}
	}
}

func TestLaCasseDeLEmpreinteNImportePas(t *testing.T) {
	e := EmpreintePEM(certA)
	if !empreinteDansMagasin(bundle, strings.ToUpper(e)) {
		t.Error("une empreinte en majuscules n'est pas reconnue")
	}
}

func TestUnBundleVideNeTrouveRien(t *testing.T) {
	if empreinteDansMagasin(nil, EmpreintePEM(certA)) {
		t.Error("un bundle vide a produit une correspondance")
	}
	if empreinteDansMagasin([]byte("pas du PEM du tout"), EmpreintePEM(certA)) {
		t.Error("un contenu non-PEM a produit une correspondance")
	}
}

// --- résolution DNS ---------------------------------------------------------

// resolvectlExemple reproduit la sortie de `resolvectl dns` sur une machine
// dont la GPO fixe le DNS global et dont l'interface reçoit un DNS par DHCP.
const resolvectlExemple = "Global: 10.0.0.1 10.0.0.2\n" +
	"Link 2 (eth0): 192.168.1.1\n" +
	"Link 3 (docker0):\n"

// TestSeuleLaLigneGlobaleEstLue.
//
// LE test de la partie DNS. Un DNS posé sur une INTERFACE vient d'un bail DHCP,
// pas de la politique. L'agréger au global ferait comparer des serveurs que
// personne n'a demandés à ceux de la GPO — donc une dérive permanente sur une
// machine correctement configurée, et qu'aucune réapplication ne corrigerait.
func TestSeuleLaLigneGlobaleEstLue(t *testing.T) {
	got := serveursDNSGlobaux(resolvectlExemple)

	attendu := []string{"10.0.0.1", "10.0.0.2"}
	if !egalesIgnorantLOrdre(got, attendu) {
		t.Errorf("serveurs globaux = %v, attendu %v", got, attendu)
	}
	for _, s := range got {
		if s == "192.168.1.1" {
			t.Error("un résolveur d'interface a été pris pour un résolveur global")
		}
	}
}

func TestUneSortieSansLigneGlobaleRendUneListeVide(t *testing.T) {
	cas := map[string]string{
		"aucune ligne Global": "Link 2 (eth0): 192.168.1.1\n",
		"sortie vide":         "",
		"Global sans valeur":  "Global:\nLink 2 (eth0): 192.168.1.1\n",
	}
	for quoi, sortie := range cas {
		if n := len(serveursDNSGlobaux(sortie)); n != 0 {
			t.Errorf("%s : %d serveur(s) rendus, 0 attendu", quoi, n)
		}
	}
}

// TestLesEspacesEtLIndentationNeGenentPas : resolvectl indente parfois ses
// lignes selon la version.
func TestLesEspacesEtLIndentationNeGenentPas(t *testing.T) {
	sortie := "   Global: 10.0.0.1   10.0.0.2  \n  Link 2 (eth0): 192.168.1.1\n"
	if got := serveursDNSGlobaux(sortie); len(got) != 2 {
		t.Errorf("%v : l'indentation ou les espaces multiples cassent la lecture", got)
	}
}

// --- ce que ce lot refuse d'affirmer ----------------------------------------

// TestAucuneAttenteSurLesDepotsNiLesHotesConnus.
//
// `package_repo` et `ssh_known_hosts` étaient candidats et ont été écartés :
// le scan des FICHIERS les couvre déjà. Désactiver un dépôt écrit `enabled=0`
// dans le fichier de la GPO, ou retire le fichier côté apt ; `ssh_known_hosts`
// n'a ni état compilé ni service à recharger.
//
// Le test lit la source parce que la propriété est une absence. Sans lui,
// quelqu'un croirait à un oubli et ajouterait une analyse fragile de `dnf
// repolist` pour ne rien constater de neuf.
func TestAucuneAttenteSurLesDepotsNiLesHotesConnus(t *testing.T) {
	source := lireSource(t, "appliers_sources.go") + lireSource(t, "appliers_hardening.go")

	for _, interdit := range []string{"CheckPackageRepo", "CheckKnownHosts"} {
		if strings.Contains(source, "recordCheck("+interdit) {
			t.Errorf("une attente %s est déclarée : elle ne constaterait que ce que "+
				"le scan des fichiers voit déjà", interdit)
		}
	}
}

// TestLAttenteCAEstDeclareeApresLaRegeneration.
//
// L'ordre compte : déclarée avant, l'attente porterait sur un magasin que
// `update-ca-trust` n'a pas encore régénéré — et le premier scan signalerait une
// dérive sur une machine que l'appliqueur vient de mettre en conformité.
func TestLAttenteCAEstDeclareeApresLaRegeneration(t *testing.T) {
	source := lireSource(t, "appliers_sources.go")

	iRegen := strings.Index(source, "regeneration du magasin de confiance impossible")
	iAttente := strings.Index(source, "recordCheck(CheckCADansMagasin, name, empreinte)")
	if iRegen < 0 || iAttente < 0 {
		t.Fatal("applyTrustedCA ne ressemble plus à ce que ce test garde")
	}
	if iAttente < iRegen {
		t.Error("l'attente est déclarée avant la régénération du magasin : le premier " +
			"scan signalerait une dérive sur une machine conforme")
	}
}
