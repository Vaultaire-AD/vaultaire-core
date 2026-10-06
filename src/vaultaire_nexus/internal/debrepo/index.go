package debrepo

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Input est un paquet du dépôt, tel que le catalogue le connaît.
type Input struct {
	Filename string
	Size     int64
	MD5      string
	SHA1     string
	SHA256   string
	Detail   []byte // JSON de Control
}

// Signer produit InRelease (clair-signé) et Release.gpg (détaché).
type Signer interface {
	ClearSign(data []byte) ([]byte, error)
	DetachSign(data []byte) ([]byte, error)
}

// Settings décrit la distribution servie.
type Settings struct {
	Origin       string
	Label        string
	Distribution string // suite et codename
	Component    string
	Description  string
}

// arches par défaut : un paquet « all » doit apparaître dans chaque index, et
// apt réclame les index des architectures qu'il connaît même s'ils sont vides.
var defaultArches = []string{"amd64", "arm64"}

// Generate écrit <dir>/dists/<distribution>/… pour les paquets donnés.
func Generate(dir string, s Settings, pkgs []Input, sign Signer) error {
	type entry struct {
		in Input
		c  Control
	}
	byArch := map[string][]entry{}
	archSet := map[string]bool{}
	for _, a := range defaultArches {
		archSet[a] = true
	}
	var all []entry
	for _, in := range pkgs {
		var c Control
		if err := json.Unmarshal(in.Detail, &c); err != nil {
			return fmt.Errorf("%s : métadonnées illisibles : %w", in.Filename, err)
		}
		a := c.Architecture()
		if a == "all" {
			all = append(all, entry{in, c})
			continue
		}
		archSet[a] = true
		byArch[a] = append(byArch[a], entry{in, c})
	}
	var arches []string
	for a := range archSet {
		arches = append(arches, a)
	}
	sort.Strings(arches)

	stage := dir + ".new"
	os.RemoveAll(stage)
	distDir := filepath.Join(stage, "dists", s.Distribution)

	type indexFile struct {
		rel  string
		data []byte
	}
	var indexes []indexFile

	for _, a := range arches {
		list := append(append([]entry{}, byArch[a]...), all...)
		sort.Slice(list, func(i, j int) bool {
			if list[i].c.Package() != list[j].c.Package() {
				return list[i].c.Package() < list[j].c.Package()
			}
			return list[i].c.Version() < list[j].c.Version()
		})
		var buf bytes.Buffer
		for _, e := range list {
			writeStanza(&buf, s.Component, e.c, e.in)
		}
		rel := filepath.ToSlash(filepath.Join(s.Component, "binary-"+a, "Packages"))
		gz, err := gzipBytes(buf.Bytes())
		if err != nil {
			return err
		}
		indexes = append(indexes, indexFile{rel, buf.Bytes()}, indexFile{rel + ".gz", gz})

		release := fmt.Sprintf("Archive: %s\nComponent: %s\nOrigin: %s\nLabel: %s\nArchitecture: %s\n",
			s.Distribution, s.Component, s.Origin, s.Label, a)
		indexes = append(indexes, indexFile{filepath.ToSlash(filepath.Join(s.Component, "binary-"+a, "Release")), []byte(release)})
	}

	for _, f := range indexes {
		p := filepath.Join(distDir, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, f.data, 0o640); err != nil {
			return err
		}
	}

	var rel bytes.Buffer
	fmt.Fprintf(&rel, "Origin: %s\nLabel: %s\nSuite: %s\nCodename: %s\n", s.Origin, s.Label, s.Distribution, s.Distribution)
	fmt.Fprintf(&rel, "Date: %s\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&rel, "Architectures: %s\nComponents: %s\nDescription: %s\n", strings.Join(arches, " "), s.Component, s.Description)
	for _, algo := range []struct {
		name string
		sum  func([]byte) string
	}{
		{"MD5Sum", func(b []byte) string { h := md5.Sum(b); return hex.EncodeToString(h[:]) }},
		{"SHA1", func(b []byte) string { h := sha1.Sum(b); return hex.EncodeToString(h[:]) }},
		{"SHA256", func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }},
	} {
		fmt.Fprintf(&rel, "%s:\n", algo.name)
		for _, f := range indexes {
			fmt.Fprintf(&rel, " %s %16d %s\n", algo.sum(f.data), len(f.data), f.rel)
		}
	}
	if err := os.MkdirAll(distDir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(distDir, "Release"), rel.Bytes(), 0o640); err != nil {
		return err
	}
	if sign != nil {
		in, err := sign.ClearSign(rel.Bytes())
		if err != nil {
			return fmt.Errorf("InRelease : %w", err)
		}
		det, err := sign.DetachSign(rel.Bytes())
		if err != nil {
			return fmt.Errorf("Release.gpg : %w", err)
		}
		if err := os.WriteFile(filepath.Join(distDir, "InRelease"), in, 0o640); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(distDir, "Release.gpg"), det, 0o640); err != nil {
			return err
		}
	}

	old := dir + ".old"
	os.RemoveAll(old)
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, old); err != nil {
			return err
		}
	}
	if err := os.Rename(stage, dir); err != nil {
		return err
	}
	os.RemoveAll(old)
	return nil
}

// champs ajoutés par le dépôt : on ignore ceux du paquet s'il les portait.
var generated = map[string]bool{"filename": true, "size": true, "md5sum": true, "sha1": true, "sha256": true}

func writeStanza(w *bytes.Buffer, component string, c Control, in Input) {
	for _, f := range c.Fields {
		if generated[strings.ToLower(f.Name)] {
			continue
		}
		fmt.Fprintf(w, "%s: %s\n", f.Name, f.Value)
	}
	fmt.Fprintf(w, "Filename: %s\n", PoolPath(component, c, in.Filename))
	fmt.Fprintf(w, "Size: %d\nMD5sum: %s\nSHA1: %s\nSHA256: %s\n\n", in.Size, in.MD5, in.SHA1, in.SHA256)
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SourcesLine rend la ligne à mettre dans /etc/apt/sources.list.d/.
func SourcesLine(baseURL, repo string, s Settings, signed bool) string {
	opt := "[trusted=yes] "
	if signed {
		opt = "[signed-by=/etc/apt/keyrings/vaultaire-nexus.asc] "
	}
	return fmt.Sprintf("deb %s%s/repo/deb/%s %s %s", opt, baseURL, repo, s.Distribution, s.Component)
}
