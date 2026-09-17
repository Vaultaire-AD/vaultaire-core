package debrepo

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildDeb fabrique un .deb avec dpkg-deb, dans la compression demandée.
func buildDeb(t *testing.T, name, version, arch, comp string) string {
	t.Helper()
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb absent")
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "DEBIAN"), 0o755)
	os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Test <t@example.com>\nRecommends: bash (>= 4)\nDescription: paquet de test\n longue description\n .\n seconde partie\n", name, version, arch)
	os.WriteFile(filepath.Join(root, "DEBIAN/control"), []byte(control), 0o644)
	os.WriteFile(filepath.Join(root, "usr/bin", name), []byte("#!/bin/sh\n"), 0o755)
	out := filepath.Join(t.TempDir(), "p.deb")
	cmd := exec.Command("dpkg-deb", "--root-owner-group", "-Z"+comp, "--build", root, out)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb : %v\n%s", err, o)
	}
	return out
}

func TestParseCompressions(t *testing.T) {
	for _, comp := range []string{"gzip", "xz", "zstd", "none"} {
		t.Run(comp, func(t *testing.T) {
			p := buildDeb(t, "nexus-test", "1:2.0-1", "amd64", comp)
			f, _ := os.Open(p)
			defer f.Close()
			c, err := Parse(f)
			if err != nil {
				t.Fatal(err)
			}
			if c.Package() != "nexus-test" || c.Version() != "1:2.0-1" || c.Architecture() != "amd64" {
				t.Fatalf("control lu : %+v", c)
			}
			if !strings.Contains(c.Get("Description"), "seconde partie") {
				t.Errorf("continuations perdues : %q", c.Get("Description"))
			}
			if c.CanonicalFilename() != "nexus-test_2.0-1_amd64.deb" {
				t.Errorf("nom canonique : %s", c.CanonicalFilename())
			}
		})
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse(strings.NewReader("!<arch>\nnimportequoi")); err == nil {
		t.Fatal("archive invalide acceptée")
	}
}

// TestGenerateWithApt construit un dépôt et le fait lire par apt-get.
func TestGenerateWithApt(t *testing.T) {
	if _, err := exec.LookPath("apt-get"); err != nil {
		t.Skip("apt-get absent")
	}
	repo := t.TempDir()
	s := Settings{Origin: "Vaultaire", Label: "Nexus", Distribution: "stable", Component: "main", Description: "test"}
	var inputs []Input
	for _, it := range []struct{ v, a string }{{"1.0", "amd64"}, {"1.1", "amd64"}, {"0.5", "all"}} {
		name := "nexus-test"
		if it.a == "all" {
			name = "nexus-doc"
		}
		src := buildDeb(t, name, it.v, it.a, "xz")
		data, _ := os.ReadFile(src)
		f, _ := os.Open(src)
		c, err := Parse(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		fn := c.CanonicalFilename()
		dst := filepath.Join(repo, PoolPath(s.Component, *c, fn))
		os.MkdirAll(filepath.Dir(dst), 0o755)
		os.WriteFile(dst, data, 0o644)
		detail, _ := json.Marshal(c)
		m := md5.Sum(data)
		s1 := sha1.Sum(data)
		s2 := sha256.Sum256(data)
		inputs = append(inputs, Input{Filename: fn, Size: int64(len(data)), MD5: hex.EncodeToString(m[:]),
			SHA1: hex.EncodeToString(s1[:]), SHA256: hex.EncodeToString(s2[:]), Detail: detail})
	}
	idx := filepath.Join(t.TempDir(), "idx")
	if err := Generate(idx, s, inputs, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(idx, "dists"), filepath.Join(repo, "dists")); err != nil {
		t.Fatal(err)
	}

	state := t.TempDir()
	for _, d := range []string{"lists/partial", "cache/archives/partial", "etc/sources.list.d", "etc/preferences.d", "status"} {
		os.MkdirAll(filepath.Join(state, d), 0o755)
	}
	os.Remove(filepath.Join(state, "status"))
	os.WriteFile(filepath.Join(state, "status"), nil, 0o644)
	src := filepath.Join(state, "etc", "sources.list")
	os.WriteFile(src, []byte(fmt.Sprintf("deb [trusted=yes arch=amd64] file://%s stable main\n", repo)), 0o644)
	opts := []string{
		"-o", "Dir::Etc::sourcelist=" + src,
		"-o", "Dir::Etc::sourceparts=" + filepath.Join(state, "etc/sources.list.d"),
		"-o", "Dir::Etc::preferencesparts=" + filepath.Join(state, "etc/preferences.d"),
		"-o", "Dir::State::Lists=" + filepath.Join(state, "lists"),
		"-o", "Dir::State::status=" + filepath.Join(state, "status"),
		"-o", "Dir::Cache=" + filepath.Join(state, "cache"),
		"-o", "APT::Architecture=amd64",
		"-o", "APT::Sandbox::User=root",
		"-o", "Debug::NoLocking=1",
	}
	run := func(args ...string) string {
		cmd := exec.Command("apt-get", append(opts, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("apt-get %v : %v\n%s", args, err, out)
		}
		return string(out)
	}
	run("update")
	out := run("-s", "--no-install-recommends", "install", "nexus-test", "nexus-doc")
	if !strings.Contains(out, "nexus-test (1.1") || !strings.Contains(out, "nexus-doc (0.5") {
		t.Fatalf("apt ne choisit pas les bonnes versions :\n%s", out)
	}
	cmd := exec.Command("apt-cache", append(opts, "madison", "nexus-test")...)
	o, _ := cmd.CombinedOutput()
	if !strings.Contains(string(o), "1.0") || !strings.Contains(string(o), "1.1") {
		t.Fatalf("apt-cache madison :\n%s", o)
	}
}
