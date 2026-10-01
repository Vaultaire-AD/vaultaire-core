package rpmrepo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildRPM fabrique un vrai paquet avec rpmbuild. Le test est ignoré si
// l'outil manque : aucun binaire n'est versionné dans le dépôt.
func buildRPM(t *testing.T, name, version string) string {
	t.Helper()
	if _, err := exec.LookPath("rpmbuild"); err != nil {
		t.Skip("rpmbuild absent")
	}
	top := t.TempDir()
	spec := `Name: ` + name + `
Version: ` + version + `
Release: 1
Summary: Paquet de test <Nexus> & co
License: MIT
BuildArch: noarch
Requires: bash >= 4.0
Provides: nexus-test-capability = 1.2
Obsoletes: vieux-paquet < 2

%description
Description du paquet de test.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/etc/nexus-test %{buildroot}/usr/share/doc/nexus-test
echo '#!/bin/sh' > %{buildroot}/usr/bin/` + name + `
echo 'x=1' > %{buildroot}/etc/nexus-test/conf
echo doc > %{buildroot}/usr/share/doc/nexus-test/README

%files
%attr(0755,root,root) /usr/bin/` + name + `
%dir /etc/nexus-test
%config /etc/nexus-test/conf
/usr/share/doc/nexus-test/README
`
	specPath := filepath.Join(top, name+".spec")
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rpmbuild", "-bb", "--define", "_topdir "+top, specPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rpmbuild : %v\n%s", err, out)
	}
	matches, _ := filepath.Glob(filepath.Join(top, "RPMS", "noarch", "*.rpm"))
	if len(matches) != 1 {
		t.Fatalf("rpm introuvable : %v", matches)
	}
	return matches[0]
}

func TestParse(t *testing.T) {
	path := buildRPM(t, "nexus-test", "1.2.3")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "nexus-test" || p.Version != "1.2.3" || p.Release != "1" || p.Arch != "noarch" {
		t.Fatalf("identité lue : %+v", p)
	}
	if p.CanonicalFilename() != filepath.Base(path) {
		t.Errorf("nom canonique %s, fichier %s", p.CanonicalFilename(), filepath.Base(path))
	}
	var bashReq bool
	for _, r := range p.Requires {
		if strings.HasPrefix(r.Name, "rpmlib(") {
			t.Errorf("dépendance rpmlib non filtrée : %s", r.Name)
		}
		if r.Name == "bash" && r.Flags == "GE" && r.Ver == "4.0" {
			bashReq = true
		}
	}
	if !bashReq {
		t.Errorf("Requires bash >= 4.0 absent : %+v", p.Requires)
	}
	var files []string
	for _, fl := range p.Files {
		files = append(files, fl.Path)
	}
	if !strings.Contains(strings.Join(files, " "), "/usr/bin/nexus-test") {
		t.Errorf("fichiers : %v", files)
	}
	if p.HeaderStart <= 96 || p.HeaderEnd <= p.HeaderStart {
		t.Errorf("header-range incohérent : %d-%d", p.HeaderStart, p.HeaderEnd)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse(strings.NewReader(strings.Repeat("x", 200))); err == nil {
		t.Fatal("un fichier quelconque a été accepté comme RPM")
	}
}

// TestGenerateWithDNF construit un dépôt et demande à dnf de le lire.
func TestGenerateWithDNF(t *testing.T) {
	if _, err := exec.LookPath("dnf"); err != nil {
		t.Skip("dnf absent")
	}
	repo := t.TempDir()
	pkgDir := filepath.Join(repo, "Packages")
	os.MkdirAll(pkgDir, 0o755)
	var inputs []Input
	for _, v := range []string{"1.0.0", "1.1.0"} {
		src := buildRPM(t, "nexus-test", v)
		data, _ := os.ReadFile(src)
		f, _ := os.Open(src)
		p, err := Parse(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(pkgDir, filepath.Base(src)), data, 0o644)
		detail, _ := json.Marshal(p)
		h := sha256.Sum256(data)
		inputs = append(inputs, Input{Filename: filepath.Base(src), SHA256: hex.EncodeToString(h[:]), Size: int64(len(data)), UploadedAt: time.Now(), Detail: detail})
	}
	idx := filepath.Join(t.TempDir(), "idx")
	if err := Generate(idx, inputs, nil); err != nil {
		t.Fatal(err)
	}
	// dnf lit repodata/ à côté de Packages/ : on assemble les deux.
	if err := os.Rename(filepath.Join(idx, "repodata"), filepath.Join(repo, "repodata")); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	cmd := exec.Command("dnf", "-q", "--setopt=cachedir="+cache, "--disablerepo=*",
		"--repofrompath=nexus,file://"+repo, "--enablerepo=nexus", "--setopt=nexus.gpgcheck=0",
		"--releasever=9", "repoquery", "--qf", "%{name}-%{version} %{requires}", "nexus-test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dnf : %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "nexus-test-1.0.0") || !strings.Contains(s, "nexus-test-1.1.0") {
		t.Fatalf("dnf ne voit pas les deux versions :\n%s", s)
	}
	cmd = exec.Command("dnf", "-q", "--setopt=cachedir="+cache, "--disablerepo=*",
		"--repofrompath=nexus,file://"+repo, "--enablerepo=nexus", "--releasever=9",
		"repoquery", "--whatprovides", "/usr/bin/nexus-test")
	out, err = cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "nexus-test") {
		t.Fatalf("recherche par fichier : %v\n%s", err, out)
	}
}
