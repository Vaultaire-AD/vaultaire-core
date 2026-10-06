package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire/core/storage"
)

// TO-DO 145 : le détail se règle par sous-système, et un niveau TRACE passe
// sous le DEBUG.
//
// # Ce que ces tests gardent
//
// Le défaut de départ était un journal où l'annuaire noyait tout le reste. Le
// correctif tient à deux choses qui ne se voient pas à la lecture : la ligne
// est rangée d'après le FICHIER de celui qui l'écrit, à une profondeur de pile
// fixe, et le rangement désigne des dossiers par leur nom. Un cadre de plus
// dans la pile, ou un dossier renommé, et les lignes suivent de nouveau le
// réglage général — sans erreur nulle part.

// etatPropre remet le détail dans l'état d'un serveur qui vient de démarrer.
func etatPropre(t *testing.T, debug bool) {
	t.Helper()
	ancienDebug := storage.Debug
	anciens := map[SousSysteme]int32{}
	for s, v := range reglagesDeDetail {
		anciens[s] = v.Load()
	}
	ancienRangement := rangement

	storage.Debug = debug
	for _, s := range SousSystemes() {
		LaisserDetail(s)
	}
	t.Cleanup(func() {
		storage.Debug = ancienDebug
		rangement = ancienRangement
		for _, s := range SousSystemes() {
			LaisserDetail(s)
		}
		for s, v := range anciens {
			if v != detailHerite {
				ReglerDetail(s, Detail(v))
			}
		}
	})
}

// rangerCePaquetSous fait passer ce fichier de test pour du code d'un
// sous-système : c'est le seul moyen d'éprouver la déduction par l'appelant
// depuis le paquet qui la fait.
func rangerCePaquetSous(s SousSysteme) {
	rangement = []struct {
		motif string
		sous  SousSysteme
	}{{"/core/logs/", s}}
}

func messages(recues *[]LogEntry) []string {
	out := []string{}
	for _, e := range *recues {
		out = append(out, e.Level+" "+e.Message)
	}
	return out
}

// Sans aucun réglage par sous-système, rien ne change : `debug` décide, et le
// TRACE ne sort jamais.
func TestSansReglageLeBooleenDecideCommeAvant(t *testing.T) {
	etatPropre(t, false)
	recues := capturer(t)

	Write_Log("DEBUG", "éteint")
	Write_Log("TRACE", "éteint")
	storage.Debug = true
	Write_Log("DEBUG", "allumé")
	Write_Log("TRACE", "jamais par le réglage général")

	got := messages(recues)
	if len(got) != 1 || got[0] != "DEBUG allumé" {
		t.Fatalf("lignes émises = %v, attendu la seule « DEBUG allumé »", got)
	}
}

// LA demande : le debug partout SAUF un sous-système.
func TestUnSousSystemeSeCoupeSousLeDebugGeneral(t *testing.T) {
	etatPropre(t, true)
	rangerCePaquetSous(SousLDAP)
	recues := capturer(t)

	ReglerDetail(SousLDAP, DetailCoupe)
	Write_Log("DEBUG", "annuaire")
	Write_LogCode("DEBUG", CodeNone, "annuaire")
	Write_LogCodeMeta("DEBUG", CodeNone, "annuaire", nil)

	if got := messages(recues); len(got) != 0 {
		t.Fatalf("lignes émises = %v : le sous-système coupé écrit encore — "+
			"c'est le journal noyé qu'on voulait éviter", got)
	}
}

// Et l'inverse : un sous-système SEUL, sur un serveur silencieux.
func TestUnSousSystemeSAllumeSeul(t *testing.T) {
	etatPropre(t, false)
	rangerCePaquetSous(SousLDAP)
	recues := capturer(t)

	ReglerDetail(SousLDAP, DetailDebug)
	Write_Log("DEBUG", "annuaire")
	Write_Log("TRACE", "pas encore")

	rangerCePaquetSous(SousDucky)
	Write_Log("DEBUG", "ducky, resté éteint")

	got := messages(recues)
	if len(got) != 1 || got[0] != "DEBUG annuaire" {
		t.Fatalf("lignes émises = %v, attendu la seule « DEBUG annuaire »", got)
	}
}

// Le TRACE se demande nommément, et entraîne le DEBUG.
func TestLeTraceSeDemandeParSousSysteme(t *testing.T) {
	etatPropre(t, false)
	rangerCePaquetSous(SousLDAP)
	recues := capturer(t)

	ReglerDetail(SousLDAP, DetailTrace)
	Write_Log("DEBUG", "opération")
	Write_Log("TRACE", "étape")

	got := messages(recues)
	if len(got) != 2 || got[0] != "DEBUG opération" || got[1] != "TRACE étape" {
		t.Fatalf("lignes émises = %v, attendu DEBUG puis TRACE", got)
	}
	if e := (*recues)[1]; e.Severity != SeverityDebug {
		t.Errorf("sévérité d'une ligne TRACE = %d, attendu %d : avec une autre valeur "+
			"elle partirait dans le journal commun en base, qui n'écarte que la sévérité 7",
			e.Severity, SeverityDebug)
	}
}

// Les TROIS fonctions d'écriture rangent la ligne d'après leur APPELANT. Si
// l'une passait par une autre, elle ajouterait un cadre à la pile et rangerait
// toutes ses lignes avec le paquet logs.
func TestLesTroisEcrituresLisentLeBonCadre(t *testing.T) {
	etatPropre(t, false)
	rangerCePaquetSous(SousGPO)
	ReglerDetail(SousGPO, DetailDebug)
	recues := capturer(t)

	Write_Log("DEBUG", "a")
	Write_LogCode("DEBUG", CodeNone, "b")
	Write_LogCodeMeta("DEBUG", CodeNone, "c", nil)

	if got := messages(recues); len(got) != 3 {
		t.Fatalf("lignes émises = %v, attendu les trois : une fonction d'écriture ne "+
			"regarde pas le cadre de son appelant", got)
	}
}

// Revenir à « defaut » rend le sous-système au réglage général — et rend au
// journal son chemin court.
func TestLaisserUnReglageLeRendAuDebug(t *testing.T) {
	etatPropre(t, true)

	ReglerDetail(SousBase, DetailCoupe)
	if DetailDe(SousBase) != DetailCoupe {
		t.Fatal("le réglage propre n'est pas pris")
	}
	LaisserDetail(SousBase)
	if d, propre := DetailRegle(SousBase); propre {
		t.Errorf("réglage propre encore présent : %v", d)
	}
	if DetailDe(SousBase) != DetailDebug {
		t.Errorf("détail effectif = %v, attendu debug (celui du réglage général)", DetailDe(SousBase))
	}
	if n := reglagesPoses.Load(); n != 0 {
		t.Errorf("%d réglage(s) comptés alors qu'aucun n'est posé : chaque ligne DEBUG "+
			"paierait la recherche de son appelant pour rien", n)
	}
}

// Régler deux fois, laisser deux fois : le compteur ne dérive pas.
func TestLeCompteDesReglagesNeDerivePas(t *testing.T) {
	etatPropre(t, false)

	ReglerDetail(SousLDAP, DetailDebug)
	ReglerDetail(SousLDAP, DetailTrace)
	LaisserDetail(SousLDAP)
	LaisserDetail(SousLDAP)

	if n := reglagesPoses.Load(); n != 0 {
		t.Fatalf("compteur = %d après autant de retraits que de poses", n)
	}
}

func TestLaSaisieDUnNiveau(t *testing.T) {
	for texte, attendu := range map[string]Detail{
		"off": DetailCoupe, "OFF": DetailCoupe, "debug": DetailDebug,
		" trace ": DetailTrace, "true": DetailDebug, "false": DetailCoupe,
	} {
		d, herite, err := LireDetail(texte)
		if err != nil || herite || d != attendu {
			t.Errorf("LireDetail(%q) = %v, herite=%v, err=%v ; attendu %v", texte, d, herite, err, attendu)
		}
	}
	if _, herite, err := LireDetail("defaut"); err != nil || !herite {
		t.Errorf("« defaut » doit retirer le réglage : herite=%v err=%v", herite, err)
	}
	// Une faute de frappe est REFUSÉE. Lue comme « off », elle couperait le
	// détail en laissant croire que rien n'a changé.
	for _, faute := range []string{"", "tarce", "debugg", "2"} {
		if _, _, err := LireDetail(faute); err == nil {
			t.Errorf("LireDetail(%q) accepté : une saisie inconnue ne doit rien régler", faute)
		}
	}
}

func TestLeRangementDesFichiers(t *testing.T) {
	for chemin, attendu := range map[string]SousSysteme{
		// Les trois formes sous lesquelles un chemin de source arrive.
		"/src/vaultaire_serveur/core/ldap/LDAP_common.go":                      SousLDAP,
		"vaultaire/core/ldap/LDAP_Journal/journal.go":                          SousLDAP, // -trimpath
		`C:\git\vaultaire-core\src\vaultaire_serveur\core\ldap\LDAP_common.go`: SousLDAP,

		// Le plus précis gagne : ces dossiers vivent SOUS un motif plus large.
		"/src/vaultaire_serveur/core/database/db_ldap/get_users_by_usernames.go": SousLDAP,
		"/src/vaultaire_serveur/core/database/db_gpo/get_domains_by_gpo.go":      SousGPO,
		"/src/vaultaire_serveur/ducky-network/gpo_manager/resolve.go":            SousGPO,

		"/src/vaultaire_serveur/core/gpo/resolve.go":                     SousGPO,
		"/src/vaultaire_serveur/ducky-network/trames_manager/cadrage.go": SousDucky,
		"/src/vaultaire_serveur/ducky-network/startDuckyServer.go":       SousDucky,
		"/src/vaultaire_serveur/core/database/db_users/get_user_info.go": SousBase,

		// Un motif désigne un DOSSIER : un nom qui commence pareil n'en est pas.
		"/src/vaultaire_serveur/core/ldapautre/x.go":                  "",
		"/src/vaultaire_serveur/core/database/db_ldap_archive/x.go":   SousBase,
		"/src/vaultaire_serveur/ducky-network/gpo_manager_essai/x.go": SousDucky,

		// Hors de tout sous-système : suit le réglage général.
		"/src/vaultaire_serveur/core/permission/permission-manager.go": "",
		"/src/vaultaire_serveur/core/logs/detail.go":                   "",
		"": "",
	} {
		if got := SousSystemeDuFichier(chemin); got != attendu {
			t.Errorf("SousSystemeDuFichier(%q) = %q, attendu %q", chemin, got, attendu)
		}
	}
}

// LA SENTINELLE : chaque motif du rangement désigne un dossier qui existe.
//
// Un dossier renommé ne casserait rien de visible — ses lignes suivraient
// simplement le réglage général, et « ldap: off » n'éteindrait plus ce qu'on
// croit éteindre.
func TestLeRangementDesigneDesDossiersQuiExistent(t *testing.T) {
	// Ce test tourne dans core/logs : la racine du module est deux niveaux
	// plus haut.
	racine, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for motif, sous := range MotifsDeRangement() {
		dossier := filepath.Join(racine, filepath.FromSlash(strings.Trim(motif, "/")))
		info, err := os.Stat(dossier)
		if err != nil || !info.IsDir() {
			t.Errorf("le rangement de %q nomme le dossier %s, qui n'existe pas : "+
				"ses lignes DEBUG ne suivraient plus leur réglage", sous, motif)
		}
	}
}

// Le plus précis d'abord : l'ordre du rangement n'est pas décoratif.
func TestUnMotifPlusPrecisPasseAvantLePlusLarge(t *testing.T) {
	for i, r := range rangement {
		for _, plusTard := range rangement[i+1:] {
			if strings.HasPrefix(plusTard.motif, r.motif) && plusTard.sous != r.sous {
				t.Errorf("%q (→ %s) est placé avant %q (→ %s), qu'il recouvre : "+
					"le second n'est jamais atteint", r.motif, r.sous, plusTard.motif, plusTard.sous)
			}
		}
	}
}

func TestLEtatSeLit(t *testing.T) {
	etatPropre(t, false)
	ReglerDetail(SousLDAP, DetailTrace)
	ReglerDetail(SousBase, DetailCoupe)

	etat := EtatDuDetail()
	for _, attendu := range []string{"debug=false", "ldap=trace", "ducky=(suit debug)", "base=off"} {
		if !strings.Contains(etat, attendu) {
			t.Errorf("état %q : %q manque", etat, attendu)
		}
	}
	if !UnDetailEstActif() {
		t.Error("un sous-système en trace, et UnDetailEstActif rend false : " +
			"l'avertissement de démarrage ne sortirait pas")
	}
}

// Un message qui reprend ce qu'un client a envoyé ne peut pas écrire une
// fausse ligne de journal : relevé en traitant le TO-DO 145, sur un bind LDAP
// dont le DN portait un retour à la ligne, une date et un niveau.
func TestUnMessageNePeutPasForgerUneLigne(t *testing.T) {
	forge := "bind: unknown user=x\n2026-10-03 13:00:00 [INFO    ] ldap bind: success user=admin"

	sortie := formatHumanReadable("WARNING", forge)

	lignes := strings.Split(sortie, "\n")
	if len(lignes) != 2 {
		t.Fatalf("%d ligne(s) : %q", len(lignes), sortie)
	}
	// Une vraie ligne commence par sa date, en première colonne.
	if !strings.HasPrefix(lignes[1], "\t") {
		t.Fatalf("la ligne de suite commence en première colonne : elle se lit comme "+
			"une vraie ligne de journal.\n%s", sortie)
	}
	// Le retour chariot, qui réécrirait la ligne dans un terminal, est rendu
	// visible.
	if s := SurUneSeuleEntree("avant\raprès"); strings.Contains(s, "\r") || !strings.Contains(s, `\r`) {
		t.Errorf("retour chariot laissé tel quel : %q", s)
	}
	// Un message ordinaire n'est pas touché.
	if s := SurUneSeuleEntree("ldap conn=1 ouverte"); s != "ldap conn=1 ouverte" {
		t.Errorf("message ordinaire modifié : %q", s)
	}
}
