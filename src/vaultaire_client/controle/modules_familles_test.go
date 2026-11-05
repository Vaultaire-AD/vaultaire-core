package controle

import (
	"regexp"
	"strings"
	"testing"
)

// Les plafonds de glibc des modules natifs (TO-DO 173 et 178) sont écrits à
// TROIS endroits : auto-compil.sh (VAULTAIRE_FAMILLE_MODULES), le job de la
// release, et celui des tests au merge dans dev. S'ils divergent, la CI de dev
// valide un module que la release refuserait — ou l'inverse —, et l'on ne le
// découvre qu'au moment de publier. Ce test les tient d'accord.
func TestLesPlafondsGlibcSontLesMemesPartout(t *testing.T) {
	attendus := map[string]struct{ image, glibc string }{
		"rocky":  {"rockylinux:9", "2.34"},
		"debian": {"ubuntu:22.04", "2.35"},
	}

	compil := lire(t, "../../../auto-compil.sh")
	for famille, a := range attendus {
		motif := regexp.MustCompile(famille + `\)\s+MODULES_OUT="\$PAM_OUT/` + famille +
			`";\s+export VAULTAIRE_GLIBC_MAX="\$\{VAULTAIRE_GLIBC_MAX:-` + regexp.QuoteMeta(a.glibc) + `\}"`)
		if !motif.MatchString(compil) {
			t.Errorf("auto-compil.sh : la famille %s n'a plus le plafond %s", famille, a.glibc)
		}
	}

	tests := lire(t, "../../../.github/workflows/tests.yaml")
	for famille, a := range attendus {
		bloc := regexp.MustCompile(`(?s)- famille: ` + famille + `\s+image: (\S+)\s+glibc: "([0-9.]+)"`).FindStringSubmatch(tests)
		if bloc == nil || bloc[1] != a.image || bloc[2] != a.glibc {
			t.Errorf("tests.yaml : famille %s = %q, attendu %s et glibc %s", famille, bloc, a.image, a.glibc)
		}
	}

	release := lire(t, "../../../.github/workflows/release.yaml")
	if !strings.Contains(release, "container: rockylinux:9") {
		t.Error("release.yaml ne compile plus sur rockylinux:9")
	}
	if !strings.Contains(release, "VAULTAIRE_FAMILLE_MODULES: rocky") {
		t.Error("release.yaml ne range plus les modules de Rocky dans rocky/")
	}
	debian := regexp.MustCompile(`(?s)modules-debian:.*?container: (\S+).*?VAULTAIRE_GLIBC_MAX: "([0-9.]+)"`).FindStringSubmatch(release)
	if debian == nil || debian[1] != attendus["debian"].image || debian[2] != attendus["debian"].glibc {
		t.Errorf("release.yaml : job modules-debian = %q, attendu %s et glibc %s", debian,
			attendus["debian"].image, attendus["debian"].glibc)
	}
}
