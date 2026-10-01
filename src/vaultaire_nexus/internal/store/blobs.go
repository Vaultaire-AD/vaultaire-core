// Package store range les octets : un stockage adressé par contenu.
//
// # Pourquoi adresser par contenu
//
// Un fichier est rangé sous son SHA-256. Trois propriétés en découlent sans
// code supplémentaire :
//
//   - l'intégrité : ce qu'on relit est, par construction, ce qui a été vérifié ;
//   - la déduplication : une couche Docker partagée par dix images, ou un paquet
//     publié dans deux dépôts, n'occupe qu'une place ;
//   - l'immuabilité : réécrire un contenu sous le même nom est impossible.
//
// Les métadonnées (quel paquet, quelle version) vivent à part, dans catalog.
package store

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrNotFound : aucun blob sous ce condensat.
var ErrNotFound = errors.New("blob introuvable")

var hexSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ValidDigest dit si « sha256:<hex> » est bien formé.
func ValidDigest(d string) bool {
	return strings.HasPrefix(d, "sha256:") && hexSHA256.MatchString(d[7:])
}

// Blobs est un magasin de fichiers adressés par SHA-256.
type Blobs struct {
	root string // <data_dir>/blobs
	tmp  string // <data_dir>/tmp — même système de fichiers, pour que rename soit atomique
}

// OpenBlobs prépare les répertoires.
func OpenBlobs(dataDir string) (*Blobs, error) {
	b := &Blobs{
		root: filepath.Join(dataDir, "blobs", "sha256"),
		tmp:  filepath.Join(dataDir, "tmp"),
	}
	for _, d := range []string{b.root, b.tmp} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// TmpDir rend le répertoire des fichiers en cours d'écriture.
func (b *Blobs) TmpDir() string { return b.tmp }

func (b *Blobs) path(hexsum string) string {
	return filepath.Join(b.root, hexsum[:2], hexsum)
}

// Result décrit un blob écrit.
type Result struct {
	Digest string // sha256:<hex>
	Hex    string
	Size   int64
	MD5    string // hex — exigé par les index APT
	SHA1   string // hex
}

type hashes struct {
	sha256, md5, sha1 hash.Hash
}

func newHashes() hashes { return hashes{sha256.New(), md5.New(), sha1.New()} }

func (h hashes) writer() io.Writer { return io.MultiWriter(h.sha256, h.md5, h.sha1) }

// Put écrit le flux, calcule son condensat et le range. Si expected est non
// vide, le contenu doit y correspondre, sinon rien n'est gardé.
func (b *Blobs) Put(r io.Reader, expected string, limit int64) (Result, error) {
	f, err := os.CreateTemp(b.tmp, "put-*")
	if err != nil {
		return Result{}, err
	}
	name := f.Name()
	defer os.Remove(name) // sans effet après le rename

	h := newHashes()
	src := r
	if limit > 0 {
		src = io.LimitReader(r, limit+1)
	}
	n, err := io.Copy(io.MultiWriter(f, h.writer()), src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Result{}, err
	}
	if limit > 0 && n > limit {
		return Result{}, fmt.Errorf("contenu trop volumineux (limite %d Mo)", limit>>20)
	}
	return b.adopt(name, h, n, expected)
}

// Adopt range un fichier temporaire déjà écrit (téléversements par morceaux).
func (b *Blobs) Adopt(tmpPath string, expected string) (Result, error) {
	f, err := os.Open(tmpPath)
	if err != nil {
		return Result{}, err
	}
	h := newHashes()
	n, err := io.Copy(h.writer(), f)
	f.Close()
	if err != nil {
		return Result{}, err
	}
	return b.adopt(tmpPath, h, n, expected)
}

func (b *Blobs) adopt(tmpPath string, h hashes, size int64, expected string) (Result, error) {
	hx := hex.EncodeToString(h.sha256.Sum(nil))
	res := Result{
		Digest: "sha256:" + hx, Hex: hx, Size: size,
		MD5:  hex.EncodeToString(h.md5.Sum(nil)),
		SHA1: hex.EncodeToString(h.sha1.Sum(nil)),
	}
	if expected != "" && expected != res.Digest {
		os.Remove(tmpPath)
		return Result{}, fmt.Errorf("condensat attendu %s, obtenu %s", expected, res.Digest)
	}
	dst := b.path(hx)
	if _, err := os.Stat(dst); err == nil {
		// Déjà présent : rien à écrire, le contenu est identique par définition.
		os.Remove(tmpPath)
		now := time.Now()
		_ = os.Chtimes(dst, now, now) // rafraîchit l'âge vu par le ramasse-miettes
		return res, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return Result{}, err
	}
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return Result{}, err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return Result{}, err
	}
	return res, nil
}

// Open ouvre un blob en lecture.
func (b *Blobs) Open(digest string) (*os.File, int64, error) {
	if !ValidDigest(digest) {
		return nil, 0, ErrNotFound
	}
	f, err := os.Open(b.path(digest[7:]))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// Stat rend la taille d'un blob.
func (b *Blobs) Stat(digest string) (int64, error) {
	if !ValidDigest(digest) {
		return 0, ErrNotFound
	}
	st, err := os.Stat(b.path(digest[7:]))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// ReadAll lit un petit blob en entier (manifestes).
func (b *Blobs) ReadAll(digest string) ([]byte, error) {
	f, _, err := b.Open(digest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 16<<20))
}

// GCStats décrit un passage du ramasse-miettes.
type GCStats struct {
	Scanned  int
	Removed  int
	Freed    int64
	Kept     int
	TmpFreed int
}

// GC supprime les blobs qu'aucune métadonnée ne référence.
//
// Un blob plus récent que grace est épargné : il peut appartenir à un envoi en
// cours dont les métadonnées ne sont pas encore écrites — une image Docker
// pousse ses couches AVANT son manifeste.
func (b *Blobs) GC(referenced map[string]bool, grace time.Duration, dryRun bool) (GCStats, error) {
	var st GCStats
	cutoff := time.Now().Add(-grace)
	err := filepath.WalkDir(b.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		st.Scanned++
		digest := "sha256:" + d.Name()
		if referenced[digest] {
			st.Kept++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.ModTime().After(cutoff) {
			st.Kept++
			return nil
		}
		st.Removed++
		st.Freed += info.Size()
		if !dryRun {
			return os.Remove(p)
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	// Fichiers temporaires abandonnés (envois interrompus).
	entries, _ := os.ReadDir(b.tmp)
	for _, e := range entries {
		if e.IsDir() {
			continue // sous-répertoires gérés par leur propriétaire (envois Docker)
		}
		info, err := e.Info()
		if err == nil && info.ModTime().Before(time.Now().Add(-24*time.Hour)) {
			st.TmpFreed++
			if !dryRun {
				os.Remove(filepath.Join(b.tmp, e.Name()))
			}
		}
	}
	return st, nil
}

// Usage rend le nombre de blobs et leur taille totale.
func (b *Blobs) Usage() (count int, size int64) {
	_ = filepath.WalkDir(b.root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, e := d.Info(); e == nil {
				count++
				size += info.Size()
			}
		}
		return nil
	})
	return
}
