package gpo

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// L'ANALYSE des vrais vérificateurs.
//
// Les commandes système ne sont pas lancées ici — leur sortie dépend de la
// machine, et un test qui en dépendrait serait soit ignoré, soit faux. Ce qui
// est éprouvé, c'est ce que le vérificateur FAIT de cette sortie : les
// équivalences qu'il accepte, celles qu'il refuse, et ce qu'il déclare quand il
// ne sait pas.
//
// C'est là que se logent les erreurs coûteuses. Une équivalence oubliée fait
// signaler une dérive sur une machine conforme ; une équivalence de trop déclare
// conforme une machine qui ne l'est pas — et **une vérification approximative
// est pire qu'aucune**, parce que personne ne va plus regarder.

func TestChampsAttendus(t *testing.T) {
	cas := []struct {
		quoi   string
		expect string
		clés   map[string]string
	}{
		{"une facette", "enabled=enabled", map[string]string{"enabled": "enabled"}},
		{"deux facettes", "enabled=enabled,active=started",
			map[string]string{"enabled": "enabled", "active": "started"}},
		{"espaces", " max = 90 , inactive = 30 ",
			map[string]string{"max": "90", "inactive": "30"}},
		{"valeur seule sans cle", "present", map[string]string{}},
		{"vide", "", map[string]string{}},
	}

	for _, c := range cas {
		got := champsAttendus(c.expect)
		if len(got) != len(c.clés) {
			t.Errorf("%s : %v, attendu %v", c.quoi, got, c.clés)
			continue
		}
		for k, v := range c.clés {
			if got[k] != v {
				t.Errorf("%s : %s = %q, attendu %q", c.quoi, k, got[k], v)
			}
		}
	}
}

// TestUnExpectIllisibleNeVerifieRien.
//
// Un Expect malformé vient d'un état écrit par une autre version. Le traiter
// comme un écart ferait réappliquer un module à chaque cycle, indéfiniment, sur
// une donnée qu'on n'a simplement pas su lire.
func TestUnExpectIllisibleNeVerifieRien(t *testing.T) {
	if len(champsAttendus("n'importe quoi sans separateur")) != 0 {
		t.Error("un Expect illisible a produit des facettes a verifier")
	}
}

// --- lecture de chage -------------------------------------------------------

// TestLireChageEstIndependantDeLaLangue.
//
// La sortie de `chage -l` est localisée. S'appuyer sur le libellé anglais
// donnerait un vérificateur juste sur la machine de développement et faux sur un
// parc francophone — donc des dérives signalées sur des comptes conformes.
func TestLireChageEstIndependantDeLaLangue(t *testing.T) {
	anglais := `Last password change					: Jan 01, 2026
Password expires					: never
Password inactive					: never
Account expires						: never
Minimum number of days between password change		: 0
Maximum number of days between password change		: 90
Number of days of warning before password expires	: 7`

	français := `Dernier changement de mot de passe				: 01 jan. 2026
Fin de validité du mot de passe					: jamais
Mot de passe désactivé						: jamais
Fin de validité du compte					: jamais
Nombre minimum de jours entre les changements de mot de passe	: 0
Nombre maximum de jours entre les changements de mot de passe	: 90
Nombre de jours d'avertissement avant la fin de validité		: 7`

	for nom, sortie := range map[string]string{"anglais": anglais, "français": français} {
		v := lireChage(sortie)
		if v["max"] != "90" {
			t.Errorf("%s : max = %q, attendu 90", nom, v["max"])
		}
	}
}

// TestLireChageNInventeRien.
//
// « never » et « jamais » ne sont pas des nombres. Les convertir en zéro ferait
// croire à une politique appliquée là où il n'y en a aucune — c'est exactement
// la fausse conformité que le point 4 cherche à supprimer.
func TestLireChageNInventeRien(t *testing.T) {
	sortie := `Maximum number of days between password change		: never
Password inactive					: never`

	v := lireChage(sortie)
	if _, connu := v["max"]; connu {
		t.Errorf("« never » a ete lu comme une valeur : %q", v["max"])
	}
	if _, connu := v["inactive"]; connu {
		t.Errorf("« never » a ete lu comme une valeur d'inactivite : %q", v["inactive"])
	}
}

// TestUneValeurInconnueProduitUnEcartExplicite.
//
// Le pendant du test précédent, vu du vérificateur : une facette qu'on n'a pas
// su lire doit produire un écart NOMMÉ, pas une conformité par défaut.
func TestUneValeurInconnueProduitUnEcartExplicite(t *testing.T) {
	if ouInconnu("", false) != "inconnu" {
		t.Error("une valeur non lue devrait se dire « inconnu »")
	}
	if ouInconnu("90", true) != "90" {
		t.Error("une valeur lue devrait se rendre telle quelle")
	}
}

// --- verrouillage de mot de passe -------------------------------------------

func avecShadow(t *testing.T, contenu string) {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(chemin, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	ancien := fichierShadow
	fichierShadow = chemin
	t.Cleanup(func() { fichierShadow = ancien })
}

// TestLesDeuxMarquesDeVerrouillageSontReconnues.
//
// `usermod -L` pose un « ! », d'autres outils un « * ». N'en reconnaître qu'une
// déclarerait déverrouillé un compte qui ne l'est pas — donc conforme une
// machine où la politique a été défaite.
func TestLesDeuxMarquesDeVerrouillageSontReconnues(t *testing.T) {
	avecShadow(t, strings.Join([]string{
		"pointexcl:!$6$sel$empreinte:19700:0:99999:7:::",
		"etoile:*:19700:0:99999:7:::",
		"ouvert:$6$sel$empreinte:19700:0:99999:7:::",
		"vide::19700:0:99999:7:::",
	}, "\n")+"\n")

	cas := map[string]bool{
		"pointexcl": true,
		"etoile":    true,
		"ouvert":    false,
		"vide":      false,
	}
	for compte, attendu := range cas {
		got, err := motDePasseVerrouille(compte)
		if err != nil {
			t.Errorf("%s : %v", compte, err)
			continue
		}
		if got != attendu {
			t.Errorf("%s : verrouille = %v, attendu %v", compte, got, attendu)
		}
	}
}

// TestUnCompteAbsentDeShadowNEstPasUnEcart.
//
// Le compte a disparu. Ce n'est pas « déverrouillé » — on ne peut rien affirmer
// sur son mot de passe. Le vérificateur doit rendre une ERREUR, que le scan
// traduira en « je n'ai pas pu savoir » et non en dérive.
func TestUnCompteAbsentDeShadowNEstPasUnEcart(t *testing.T) {
	avecShadow(t, "quelquun:!x:19700:0:99999:7:::\n")

	if _, err := motDePasseVerrouille("fantome"); err == nil {
		t.Error("un compte absent a ete traite comme deverrouille")
	}
}

// TestUnCompteVerrouilleEstConforme : le chemin nominal, de bout en bout.
func TestUnCompteVerrouilleEstConforme(t *testing.T) {
	avecShadow(t, "bob:!$6$sel$emp:19700:0:99999:7:::\n")

	conforme, detail, err := verifierVerrouillageCompte(SystemCheck{
		Kind: CheckAccountLock, Target: "bob", Expect: "locked=yes",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !conforme {
		t.Errorf("compte verrouille declare non conforme : %s", detail)
	}
}

// TestUnCompteDeverrouilleEstUneDerive.
//
// Le cas qui motive ce vérificateur : un `usermod -U` fait à la main, ou par un
// outil de dépannage, rendait au poste un accès que la politique avait fermé —
// sans laisser aucune trace.
func TestUnCompteDeverrouilleEstUneDerive(t *testing.T) {
	avecShadow(t, "bob:$6$sel$emp:19700:0:99999:7:::\n")

	conforme, detail, err := verifierVerrouillageCompte(SystemCheck{
		Kind: CheckAccountLock, Target: "bob", Expect: "locked=yes",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if conforme {
		t.Error("un compte deverrouille a ete declare conforme")
	}
	if !strings.Contains(detail, "bob") {
		t.Errorf("detail %q : il doit nommer le compte, c'est ce qu'on cherchera", detail)
	}
}

// --- le registre ------------------------------------------------------------

// constantesDAttente lit les constantes Check… déclarées dans les sources.
//
// # Pourquoi les lire plutôt que les écrire
//
// La version antérieure de ces garde-fous portait une liste tenue à la main,
// recopiée dans deux tests. Elle était juste pour cinq vérificateurs ; elle
// serait fausse à trente-six, et sa fausseté serait SILENCIEUSE — un
// vérificateur absent de la liste n'est pas signalé, il est simplement pas
// contrôlé.
//
// C'est le défaut même que ces tests existent pour empêcher, reproduit dans les
// tests. La liste vient donc des sources.
func constantesDAttente(t *testing.T) map[string]string {
	t.Helper()

	fichiers, err := filepath.Glob("verifiers*.go")
	if err != nil || len(fichiers) == 0 {
		t.Fatalf("aucun fichier de verificateur trouve : %v", err)
	}

	// Les fichiers de test déclarent des constantes factices ; les inclure
	// ferait exiger un vérificateur pour des types qui n'existent que dans un
	// test.
	motif := regexp.MustCompile(`(?m)^\s*(Check\w+)\s*=\s*"([^"]+)"`)
	out := map[string]string{}
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		contenu, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("lecture de %s : %v", f, err)
		}
		for _, m := range motif.FindAllStringSubmatch(string(contenu), -1) {
			out[m[1]] = m[2]
		}
	}
	if len(out) == 0 {
		t.Fatal("aucune constante Check… trouvee : ce garde-fou ne verifie plus rien")
	}
	return out
}

// TestChaqueConstanteDAttenteAUnVerificateur.
//
// Un vérificateur écrit mais non enregistré ne s'exécute jamais, et l'attente
// correspondante est ignorée en silence — c'est-à-dire une fausse conformité,
// exactement ce que le point 4 supprime.
func TestChaqueConstanteDAttenteAUnVerificateur(t *testing.T) {
	for nom, kind := range constantesDAttente(t) {
		if _, ok := CheckerFor(kind); !ok {
			t.Errorf("%s (%q) est declaree mais aucun verificateur n'est enregistre "+
				"pour elle : toute attente de ce type serait ignoree en silence", nom, kind)
		}
	}
}

// TestChaqueAttenteDeclareeSaitEtreVerifiee.
//
// LE garde-fou du lot. Un appliqueur qui déclarerait une attente sans
// vérificateur correspondant produirait un silence permanent : le scan passe
// l'attente, ne constate rien, et la machine reste conforme quoi qu'il arrive.
//
// La liste est confrontée aux sources plutôt qu'écrite à la main — une liste
// tenue à la main finit toujours par diverger de ce que le code fait.
func TestChaqueAttenteDeclareeSaitEtreVerifiee(t *testing.T) {
	fichiers, err := filepath.Glob("appliers_*.go")
	if err != nil || len(fichiers) == 0 {
		t.Fatalf("aucun fichier d'appliqueur trouve : %v", err)
	}

	// Les constantes, résolues depuis leur nom : les appliqueurs écrivent
	// `recordCheck(CheckSystemdUnit, ...)`, pas la chaîne littérale.
	parNom := constantesDAttente(t)

	trouvés := 0
	for _, f := range fichiers {
		contenu, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("lecture de %s : %v", f, err)
		}
		for _, ligne := range strings.Split(string(contenu), "\n") {
			idx := strings.Index(ligne, "recordCheck(")
			if idx < 0 {
				continue
			}
			trouvés++
			reste := ligne[idx+len("recordCheck("):]
			nom, _, _ := strings.Cut(reste, ",")
			nom = strings.TrimSpace(nom)

			kind, connu := parNom[nom]
			if !connu {
				t.Errorf("%s : recordCheck(%s, …) — constante inconnue de ce test, "+
					"ajoutez-la a parNom", f, nom)
				continue
			}
			if _, ok := CheckerFor(kind); !ok {
				t.Errorf("%s declare une attente %q qu'aucun verificateur ne sait "+
					"constater : silence permanent, donc fausse conformite", f, kind)
			}
		}
	}

	if trouvés == 0 {
		t.Fatal("aucun appel a recordCheck trouve : ce test ne verifie plus rien")
	}
}

// TestAucunVerificateurEnTrop.
//
// L'inverse : un vérificateur enregistré que plus aucun appliqueur ne déclare
// est du code mort, et surtout un signe que la déclaration a été retirée par
// mégarde — auquel cas plus rien n'est vérifié sur ce module.
func TestAucunVerificateurEnTrop(t *testing.T) {
	fichiers, _ := filepath.Glob("appliers_*.go")
	var tout strings.Builder
	for _, f := range fichiers {
		contenu, _ := os.ReadFile(f)
		tout.Write(contenu)
	}
	sources := tout.String()

	for nom, kind := range constantesDAttente(t) {
		if _, enregistré := CheckerFor(kind); !enregistré {
			continue
		}
		if !strings.Contains(sources, "recordCheck("+nom) {
			t.Errorf("le verificateur %q est enregistre mais aucun appliqueur ne "+
				"declare l'attente correspondante : plus rien n'est verifie sur "+
				"ce module", kind)
		}
	}
}
