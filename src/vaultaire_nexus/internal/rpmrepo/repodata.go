package rpmrepo

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// Input est un paquet du dépôt, tel que le catalogue le connaît.
type Input struct {
	Filename   string
	SHA256     string // hex
	Size       int64
	UploadedAt time.Time
	Detail     []byte // JSON de Package
}

// Signer signe un fichier (signature détachée ASCII-armor).
type Signer interface {
	DetachSign(data []byte) ([]byte, error)
}

// primaryFiles : createrepo ne met dans primary.xml que les fichiers
// susceptibles d'être des dépendances ; le reste va dans filelists.xml.
var primaryFiles = regexp.MustCompile(`^(/etc/|/usr/lib/sendmail$|.*bin/)`)

// Generate écrit <dir>/repodata/ pour les paquets donnés. Le répertoire est
// construit à côté puis échangé : dnf ne voit jamais un index à moitié écrit.
func Generate(dir string, pkgs []Input, sign Signer) error {
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Filename < pkgs[j].Filename })
	var parsed []struct {
		in Input
		p  Package
	}
	for _, in := range pkgs {
		var p Package
		if err := json.Unmarshal(in.Detail, &p); err != nil {
			return fmt.Errorf("%s : métadonnées illisibles : %w", in.Filename, err)
		}
		parsed = append(parsed, struct {
			in Input
			p  Package
		}{in, p})
	}

	var primary, filelists, other bytes.Buffer
	n := len(parsed)
	fmt.Fprintf(&primary, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"%d\">\n", n)
	fmt.Fprintf(&filelists, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"%d\">\n", n)
	fmt.Fprintf(&other, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" packages=\"%d\">\n", n)

	for _, it := range parsed {
		p, in := it.p, it.in
		arch := p.Arch
		if p.IsSource {
			arch = "src"
		}
		ver := fmt.Sprintf(`<version epoch="%s" ver="%s" rel="%s"/>`, esc(p.Epoch), esc(p.Version), esc(p.Release))

		w := &primary
		fmt.Fprintf(w, "<package type=\"rpm\">\n  <name>%s</name>\n  <arch>%s</arch>\n  %s\n", esc(p.Name), esc(arch), ver)
		fmt.Fprintf(w, "  <checksum type=\"sha256\" pkgid=\"YES\">%s</checksum>\n", in.SHA256)
		fmt.Fprintf(w, "  <summary>%s</summary>\n  <description>%s</description>\n", esc(p.Summary), esc(p.Description))
		fmt.Fprintf(w, "  <packager>%s</packager>\n  <url>%s</url>\n", esc(p.Packager), esc(p.URL))
		fmt.Fprintf(w, "  <time file=\"%d\" build=\"%d\"/>\n", in.UploadedAt.Unix(), p.BuildTime)
		fmt.Fprintf(w, "  <size package=\"%d\" installed=\"%d\" archive=\"%d\"/>\n", in.Size, p.InstalledSize, p.ArchiveSize)
		fmt.Fprintf(w, "  <location href=\"Packages/%s\"/>\n", esc(in.Filename))
		fmt.Fprintf(w, "  <format>\n")
		fmt.Fprintf(w, "    <rpm:license>%s</rpm:license>\n    <rpm:vendor>%s</rpm:vendor>\n    <rpm:group>%s</rpm:group>\n", esc(p.License), esc(p.Vendor), esc(p.Group))
		fmt.Fprintf(w, "    <rpm:buildhost>%s</rpm:buildhost>\n    <rpm:sourcerpm>%s</rpm:sourcerpm>\n", esc(p.BuildHost), esc(p.SourceRPM))
		fmt.Fprintf(w, "    <rpm:header-range start=\"%d\" end=\"%d\"/>\n", p.HeaderStart, p.HeaderEnd)
		writeEntries(w, "provides", p.Provides)
		writeEntries(w, "requires", p.Requires)
		writeEntries(w, "conflicts", p.Conflicts)
		writeEntries(w, "obsoletes", p.Obsoletes)
		for _, f := range p.Files {
			if primaryFiles.MatchString(f.Path) {
				writeFile(w, "    ", f)
			}
		}
		fmt.Fprintf(w, "  </format>\n</package>\n")

		fmt.Fprintf(&filelists, "<package pkgid=\"%s\" name=\"%s\" arch=\"%s\">\n  %s\n", in.SHA256, esc(p.Name), esc(arch), ver)
		for _, f := range p.Files {
			writeFile(&filelists, "  ", f)
		}
		fmt.Fprintf(&filelists, "</package>\n")

		fmt.Fprintf(&other, "<package pkgid=\"%s\" name=\"%s\" arch=\"%s\">\n  %s\n</package>\n", in.SHA256, esc(p.Name), esc(arch), ver)
	}
	primary.WriteString("</metadata>\n")
	filelists.WriteString("</filelists>\n")
	other.WriteString("</otherdata>\n")

	stage := dir + ".new"
	os.RemoveAll(stage)
	rd := filepath.Join(stage, "repodata")
	if err := os.MkdirAll(rd, 0o750); err != nil {
		return err
	}
	now := time.Now().Unix()
	var md bytes.Buffer
	fmt.Fprintf(&md, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n  <revision>%d</revision>\n", now)
	for _, part := range []struct {
		kind string
		data []byte
	}{{"primary", primary.Bytes()}, {"filelists", filelists.Bytes()}, {"other", other.Bytes()}} {
		gz, err := gzipBytes(part.data)
		if err != nil {
			return err
		}
		gzSum := sum(gz)
		name := fmt.Sprintf("%s-%s.xml.gz", gzSum, part.kind)
		if err := os.WriteFile(filepath.Join(rd, name), gz, 0o640); err != nil {
			return err
		}
		fmt.Fprintf(&md, "  <data type=\"%s\">\n", part.kind)
		fmt.Fprintf(&md, "    <checksum type=\"sha256\">%s</checksum>\n", gzSum)
		fmt.Fprintf(&md, "    <open-checksum type=\"sha256\">%s</open-checksum>\n", sum(part.data))
		fmt.Fprintf(&md, "    <location href=\"repodata/%s\"/>\n", name)
		fmt.Fprintf(&md, "    <timestamp>%d</timestamp>\n    <size>%d</size>\n    <open-size>%d</open-size>\n  </data>\n", now, len(gz), len(part.data))
	}
	md.WriteString("</repomd>\n")
	if err := os.WriteFile(filepath.Join(rd, "repomd.xml"), md.Bytes(), 0o640); err != nil {
		return err
	}
	if sign != nil {
		sig, err := sign.DetachSign(md.Bytes())
		if err != nil {
			return fmt.Errorf("signature de repomd.xml : %w", err)
		}
		if err := os.WriteFile(filepath.Join(rd, "repomd.xml.asc"), sig, 0o640); err != nil {
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

func writeEntries(w *bytes.Buffer, kind string, es []Entry) {
	if len(es) == 0 {
		return
	}
	fmt.Fprintf(w, "    <rpm:%s>\n", kind)
	for _, e := range es {
		fmt.Fprintf(w, "      <rpm:entry name=\"%s\"", esc(e.Name))
		if e.Flags != "" {
			fmt.Fprintf(w, " flags=\"%s\" epoch=\"%s\" ver=\"%s\"", e.Flags, esc(e.Epoch), esc(e.Ver))
			if e.Rel != "" {
				fmt.Fprintf(w, " rel=\"%s\"", esc(e.Rel))
			}
		}
		if e.Pre {
			w.WriteString(` pre="1"`)
		}
		w.WriteString("/>\n")
	}
	fmt.Fprintf(w, "    </rpm:%s>\n", kind)
}

func writeFile(w *bytes.Buffer, indent string, f File) {
	attr := ""
	switch {
	case f.Dir:
		attr = ` type="dir"`
	case f.Ghost:
		attr = ` type="ghost"`
	}
	fmt.Fprintf(w, "%s<file%s>%s</file>\n", indent, attr, esc(f.Path))
}

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
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

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
