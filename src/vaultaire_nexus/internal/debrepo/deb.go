// Package debrepo lit les paquets .deb et produit l'arborescence d'un dépôt
// APT (dists/…/Packages, Release, InRelease), sans dpkg-scanpackages.
//
// # Format d'un .deb
//
// Une archive ar contenant, dans cet ordre :
//
//	debian-binary     « 2.0\n »
//	control.tar[.gz|.xz|.zst]   le fichier control et les scripts
//	data.tar[...]     les fichiers installés — jamais lus ici
package debrepo

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Field est un champ du fichier control, dans l'ordre d'origine.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"` // les lignes de continuation gardent leur espace initial
}

// Control est le fichier control d'un paquet.
type Control struct {
	Fields []Field `json:"fields"`
}

// Get rend la valeur d'un champ (nom insensible à la casse).
func (c Control) Get(name string) string {
	for _, f := range c.Fields {
		if strings.EqualFold(f.Name, name) {
			return f.Value
		}
	}
	return ""
}

// Package est l'identité d'un .deb.
func (c Control) Package() string      { return c.Get("Package") }
func (c Control) Version() string      { return c.Get("Version") }
func (c Control) Architecture() string { return c.Get("Architecture") }

// Source rend le paquet source (sans sa version entre parenthèses).
func (c Control) Source() string {
	s := c.Get("Source")
	if s == "" {
		return c.Package()
	}
	if i := strings.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	return s
}

// Summary rend la première ligne de Description.
func (c Control) Summary() string {
	d := c.Get("Description")
	if i := strings.IndexByte(d, '\n'); i >= 0 {
		d = d[:i]
	}
	return strings.TrimSpace(d)
}

var (
	validName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	validVer  = regexp.MustCompile(`^[A-Za-z0-9.+~:-]+$`)
	validArch = regexp.MustCompile(`^[a-z0-9-]+$`)
)

const maxControl = 4 << 20

// Parse lit le fichier control d'un .deb.
func Parse(r io.Reader) (*Control, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != "!<arch>\n" {
		return nil, errors.New("ce fichier n'est pas un paquet Debian (archive ar attendue)")
	}
	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("paquet Debian sans control.tar")
			}
			return nil, err
		}
		name := strings.TrimRight(strings.TrimSpace(string(hdr[0:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return nil, errors.New("en-tête ar invalide")
		}
		if strings.HasPrefix(name, "control.tar") {
			if size > maxControl*4 {
				return nil, errors.New("control.tar déraisonnablement volumineux")
			}
			body := io.LimitReader(br, size)
			return readControlTar(name, body)
		}
		skip := size + size%2 // les membres sont alignés sur 2
		if _, err := io.CopyN(io.Discard, br, skip); err != nil {
			return nil, err
		}
	}
}

func readControlTar(member string, r io.Reader) (*Control, error) {
	var tr io.Reader
	switch path.Ext(member) {
	case ".tar":
		tr = r
	case ".gz":
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		tr = zr
	case ".xz":
		zr, err := xz.NewReader(r)
		if err != nil {
			return nil, err
		}
		tr = zr
	case ".zst":
		zr, err := zstd.NewReader(r, zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		tr = zr
	default:
		return nil, fmt.Errorf("compression de %s non prise en charge", member)
	}
	t := tar.NewReader(tr)
	for {
		h, err := t.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("control.tar sans fichier control")
			}
			return nil, err
		}
		if path.Clean(h.Name) != "control" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(t, maxControl))
		if err != nil {
			return nil, err
		}
		return parseControl(data)
	}
}

func parseControl(data []byte) (*Control, error) {
	c := &Control{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxControl)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			if len(c.Fields) > 0 {
				break // fin du premier paragraphe
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(c.Fields) == 0 {
				return nil, errors.New("control : ligne de continuation sans champ")
			}
			c.Fields[len(c.Fields)-1].Value += "\n" + line
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return nil, fmt.Errorf("control : ligne invalide %q", line)
		}
		c.Fields = append(c.Fields, Field{Name: line[:i], Value: strings.TrimSpace(line[i+1:])})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !validName.MatchString(c.Package()) {
		return nil, fmt.Errorf("control : nom de paquet invalide %q", c.Package())
	}
	if !validVer.MatchString(c.Version()) {
		return nil, fmt.Errorf("control : version invalide %q", c.Version())
	}
	if !validArch.MatchString(c.Architecture()) {
		return nil, fmt.Errorf("control : architecture invalide %q", c.Architecture())
	}
	return c, nil
}

// CanonicalFilename rend name_version_arch.deb (l'époque est retirée, comme le
// fait dpkg-name).
func (c Control) CanonicalFilename() string {
	v := c.Version()
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	return fmt.Sprintf("%s_%s_%s.deb", c.Package(), v, c.Architecture())
}

// PoolPath rend le chemin sous pool/ : pool/<composant>/<l>/<source>/<fichier>.
func PoolPath(component string, c Control, filename string) string {
	src := c.Source()
	prefix := src[:1]
	if strings.HasPrefix(src, "lib") && len(src) > 3 {
		prefix = src[:4]
	}
	return path.Join("pool", component, prefix, src, filename)
}
