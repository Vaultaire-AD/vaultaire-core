package gpo

import (
	"strings"
	"testing"
)

// L'ANALYSE des vérificateurs de cohérence.
//
// Aucune commande n'est lancée : sysctl, dpkg, getent et getfacl répondent
// différemment selon la machine, et un test qui en dépendrait serait ignoré en
// intégration continue ou faux en local. Ce qui est éprouvé ici, c'est ce que le
// vérificateur FAIT de la sortie — les équivalences qu'il accepte, celles qu'il
// refuse, et ce qu'il déclare quand il ne sait pas.

// --- sysctl -----------------------------------------------------------------

// TestUneValeurSysctlEstComparableMalgreLesTabulations.
//
// LE test de ce fichier pour sysctl. Plusieurs clés portent plusieurs valeurs,
// séparées par des TABULATIONS dans la sortie de sysctl et par des espaces dans
// la politique. Une comparaison littérale signalerait une dérive permanente sur
// une machine parfaitement conforme — et une dérive qu'aucune réapplication ne
// corrige fait cesser de lire les rapports.
func TestUneValeurSysctlEstComparableMalgreLesTabulations(t *testing.T) {
	cas := []struct {
		quoi      string
		sortie    string
		politique string
		egales    bool
	}{
		{"plage de ports, tabulation contre espace", "32768\t60999", "32768 60999", true},
		{"espaces multiples", "1   2    3", "1 2 3", true},
		{"espaces de bordure", "  1 ", "1", true},
		{"saut de ligne final", "1\n", "1", true},
		{"valeurs differentes", "32768\t60999", "1024 65535", false},
		{"ordre different", "1 2", "2 1", false},
		{"zero contre un", "0", "1", false},
	}

	for _, c := range cas {
		egales := normaliserEspaces(c.sortie) == normaliserEspaces(c.politique)
		if egales != c.egales {
			t.Errorf("%s : %q vs %q — egales=%v, attendu %v",
				c.quoi, c.sortie, c.politique, egales, c.egales)
		}
	}
}

// --- shell de connexion -----------------------------------------------------

func TestLeShellEstLeSeptiemeChampDePasswd(t *testing.T) {
	cas := []struct {
		quoi   string
		ligne  string
		shell  string
		erreur bool
	}{
		{"ligne standard",
			"alice:x:1000:1000:Alice:/home/alice:/bin/bash", "/bin/bash", false},
		// Le GECOS est le champ le plus susceptible de contenir des séparateurs :
		// finger y met le bureau et deux numéros de téléphone, séparés par des
		// virgules. Jamais de deux-points, et c'est ce qui rend le découpage sûr.
		{"GECOS a virgules",
			"bob:x:1001:1001:Bob,Bureau 12,0102030405,:/home/bob:/usr/bin/zsh",
			"/usr/bin/zsh", false},
		{"compte de service",
			"nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin",
			"/usr/sbin/nologin", false},
		{"saut de ligne final",
			"alice:x:1000:1000::/home/alice:/bin/sh\n", "/bin/sh", false},
		{"shell vide", "carol:x:1002:1002::/home/carol:", "", false},
		{"ligne tronquee", "alice:x:1000:1000:/home/alice", "", true},
		{"ligne vide", "", "", true},
	}

	for _, c := range cas {
		shell, err := shellDeLigneUtilisateur(c.ligne)
		if c.erreur {
			if err == nil {
				t.Errorf("%s : aucune erreur sur une ligne malformee", c.quoi)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s : %v", c.quoi, err)
			continue
		}
		if shell != c.shell {
			t.Errorf("%s : shell = %q, attendu %q", c.quoi, shell, c.shell)
		}
	}
}

// TestLaPremiereEntreeNSSFaitFoi.
//
// Un compte peut exister deux fois — une entrée locale et une entrée d'annuaire
// de même nom. NSS résout dans l'ordre de nsswitch.conf, et c'est la PREMIÈRE
// qui sert à l'ouverture de session. Retenir la dernière ferait constater un
// shell que personne n'obtient.
func TestLaPremiereEntreeNSSFaitFoi(t *testing.T) {
	sortie := "alice:x:1000:1000::/home/alice:/bin/bash\n" +
		"alice:x:5001:5001::/home/alice:/usr/sbin/nologin\n"

	shell, err := shellDeLignePasswd(sortie)
	if err != nil {
		t.Fatalf("analyse impossible : %v", err)
	}
	if shell != "/bin/bash" {
		t.Errorf("shell = %q, attendu /bin/bash : c'est la premiere entree NSS "+
			"qui sert a l'ouverture de session", shell)
	}
}

func TestUneSortieGetentVideEstUneErreur(t *testing.T) {
	if _, err := shellDeLignePasswd("   \n\n"); err == nil {
		t.Error("une sortie vide a produit un shell : le vérificateur conclurait " +
			"a un ecart sur un compte qu'il n'a pas su lire")
	}
}

// --- ACL --------------------------------------------------------------------

func TestLaCibleACLSeDecoupeSurLeDernierSeparateur(t *testing.T) {
	cas := []struct {
		quoi   string
		cible  string
		chemin string
		spec   string
		ok     bool
	}{
		{"cas courant", "/srv/data|u:alice", "/srv/data", "u:alice", true},
		// Un « | » dans un nom de fichier est pathologique mais légal sous Unix ;
		// une spécification d'entrée n'en contient jamais. Couper sur le dernier
		// sépare correctement les deux, couper sur le premier casse le premier.
		{"chemin contenant un separateur", "/srv/a|b|g:dev", "/srv/a|b", "g:dev", true},
		{"sans separateur", "/srv/data", "", "", false},
		{"specification vide", "/srv/data|", "", "", false},
		{"chemin vide", "|u:alice", "", "", false},
	}

	for _, c := range cas {
		chemin, spec, ok := decouperCibleACL(c.cible)
		if ok != c.ok {
			t.Errorf("%s : ok = %v, attendu %v", c.quoi, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if chemin != c.chemin || spec != c.spec {
			t.Errorf("%s : (%q, %q), attendu (%q, %q)", c.quoi, chemin, spec, c.chemin, c.spec)
		}
	}
}

func TestLesAbreviationsSetfaclDeviennentLaFormeGetfacl(t *testing.T) {
	cas := map[string]string{
		"u:alice":     "user:alice:",
		"user:alice":  "user:alice:",
		"g:dev":       "group:dev:",
		"group:dev":   "group:dev:",
		"m:":          "",
		"inconnu:bob": "",
		"alice":       "",
		"u:":          "",
	}
	for spec, attendu := range cas {
		if got := prefixeLongACL(spec); got != attendu {
			t.Errorf("%q : prefixe %q, attendu %q", spec, got, attendu)
		}
	}
}

// getfaclExemple reproduit une sortie réelle de `getfacl --absolute-names -c`.
//
// L'annotation « #effective » n'apparaît que sur les entrées que le masque
// rabote, séparée par une tabulation.
const getfaclExemple = "user::rwx\n" +
	"user:alice:rw-\n" +
	"user:bob:rwx\t\t\t#effective:r--\n" +
	"group::r-x\n" +
	"group:dev:r-x\n" +
	"mask::r--\n" +
	"other::---\n" +
	"default:user::rwx\n" +
	"default:user:carol:rwx\n"

func TestUneEntreeACLEstRetrouvee(t *testing.T) {
	droits, effectifs, present := entreeACL(getfaclExemple, "u:alice")
	if !present {
		t.Fatal("entree user:alice non trouvee")
	}
	if droits != "rw-" {
		t.Errorf("droits = %q, attendu rw-", droits)
	}
	if effectifs != "" {
		t.Errorf("effectifs = %q, attendu vide : cette entree n'est pas annotee", effectifs)
	}
}

// TestLesDroitsEffectifsSontLus.
//
// Le masque d'une ACL réduit toutes les entrées nommées. « bob:rwx » sous un
// masque « r-- » ne donne à bob qu'une lecture. Ne lire que l'entrée déclarerait
// conforme une politique que le masque annule — c'est exactement la fausse
// conformité que ce lot supprime.
func TestLesDroitsEffectifsSontLus(t *testing.T) {
	droits, effectifs, present := entreeACL(getfaclExemple, "u:bob")
	if !present {
		t.Fatal("entree user:bob non trouvee")
	}
	if droits != "rwx" {
		t.Errorf("droits accordes = %q, attendu rwx", droits)
	}
	if effectifs != "r--" {
		t.Errorf("droits effectifs = %q, attendu r-- : le masque n'est pas lu, "+
			"une politique annulee par le masque passerait pour appliquee", effectifs)
	}
}

// TestLesEntreesParDefautNeComptentPas.
//
// Les lignes « default: » décrivent ce qu'hériteront les fichiers créés ENSUITE,
// pas les droits en vigueur sur ce chemin. Les confondre ferait constater une
// entrée là où l'ACL d'accès a justement été retirée.
func TestLesEntreesParDefautNeComptentPas(t *testing.T) {
	if _, _, present := entreeACL(getfaclExemple, "u:carol"); present {
		t.Error("l'entree default:user:carol a ete prise pour une ACL d'acces")
	}
}

func TestUneEntreeAbsenteEstSignaleeAbsente(t *testing.T) {
	if _, _, present := entreeACL(getfaclExemple, "u:dave"); present {
		t.Error("entree user:dave trouvee alors qu'elle n'est pas dans la sortie")
	}
	if _, _, present := entreeACL(getfaclExemple, "g:ops"); present {
		t.Error("entree group:ops trouvee alors qu'elle n'est pas dans la sortie")
	}
}

// TestUnPrefixeNEstPasUnNom.
//
// « user:alice » ne doit pas répondre pour « user:alice2 » ni l'inverse. Le
// deux-points terminal du préfixe est ce qui l'empêche ; l'oublier ferait
// constater l'ACL d'un compte sur celle d'un autre.
func TestUnPrefixeNEstPasUnNom(t *testing.T) {
	sortie := "user:alice2:rwx\ngroup:devops:r-x\n"

	if _, _, present := entreeACL(sortie, "u:alice"); present {
		t.Error("user:alice a ete trouve dans une sortie qui ne contient qu'alice2")
	}
	if _, _, present := entreeACL(sortie, "g:dev"); present {
		t.Error("group:dev a ete trouve dans une sortie qui ne contient que devops")
	}
}

func TestUnGenreInconnuNeTrouveRien(t *testing.T) {
	if _, _, present := entreeACL(getfaclExemple, "x:alice"); present {
		t.Error("un genre inconnu a produit une entree")
	}
}

// --- ce que le lot refuse d'affirmer ----------------------------------------

// TestLaVerificationRecursiveNEstPasDeclaree.
//
// Garde-fou de la décision la plus facile à défaire par inadvertance. Une
// politique récursive pose l'ACL sur toute une arborescence ; le vérificateur ne
// constate que le chemin de tête. Déclarer l'attente quand même ferait passer
// pour conforme une ACL retirée sur un sous-répertoire.
//
// Le test lit la source parce que la condition n'est pas atteignable autrement :
// applyFileACL lance setfacl, absent de la plupart des machines de compilation.
func TestLaVerificationRecursiveNEstPasDeclaree(t *testing.T) {
	source := lireSource(t, "appliers_user_extra.go")

	if !strings.Contains(source, "verifiable := !recursif") {
		t.Error("applyFileACL ne conditionne plus son attente a l'absence de recursion : " +
			"une ACL retiree sur un sous-repertoire passerait pour conforme")
	}
	if !strings.Contains(source, "if verifiable {") {
		t.Error("applyFileACL declare son attente sans condition")
	}
}

// TestAucuneAttenteSurCeQuiDependDUnRedemarrage.
//
// boot_params et kernel_module_policy écrivent une configuration qui ne prend
// effet qu'au prochain démarrage — l'appliqueur de modules le dit lui-même :
// « effectif au redemarrage ». Constater /proc/cmdline ou lsmod signalerait donc
// une dérive sur toute machine en attente de redémarrage, c'est-à-dire une
// alerte permanente que personne ne peut lever.
//
// Ils seront vérifiables le jour où l'état saura porter « en attente de
// redémarrage ». D'ici là, ce test garde la décision explicite.
func TestAucuneAttenteSurCeQuiDependDUnRedemarrage(t *testing.T) {
	source := lireSource(t, "appliers_hardening.go") + lireSource(t, "appliers_system.go")

	for _, interdit := range []string{"CheckBootParams", "CheckKernelModule"} {
		if strings.Contains(source, "recordCheck("+interdit) {
			t.Errorf("une attente %s est declaree : elle signalerait une derive sur "+
				"toute machine en attente de redemarrage", interdit)
		}
	}
}
