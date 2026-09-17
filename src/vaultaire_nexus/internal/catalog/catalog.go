// Package catalog tient ce que le dépôt contient : quels paquets, quelles
// versions, quelles images, et à quel blob chacun renvoie.
//
// # Stockage
//
// Un fichier JSON par dépôt, dans <data_dir>/meta/repos/, réécrit
// atomiquement à chaque modification, et tout le catalogue en mémoire. C'est
// volontairement simple : un dépôt de paquets change rarement et se lit
// souvent. Au-delà de quelques dizaines de milliers de versions par dépôt, il
// faudra une vraie base — l'interface Catalog est le seul point à changer.
package catalog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/store"
	"vaultaire_nexus/internal/vercmp"
)

// Erreurs métier, traduites en codes HTTP par l'appelant.
var (
	ErrRepoNotFound    = errors.New("dépôt introuvable")
	ErrRepoExists      = errors.New("ce dépôt existe déjà")
	ErrPackageNotFound = errors.New("paquet introuvable")
	ErrVersionExists   = errors.New("cette version existe déjà — une version publiée est immuable, supprimez-la d'abord")
	ErrWrongType       = errors.New("opération impossible sur ce type de dépôt")
)

// Repo décrit un dépôt.
type Repo struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Description  string    `json:"description,omitempty"`
	Public       bool      `json:"public"`
	KeepVersions int       `json:"keep_versions"`
	Distribution string    `json:"distribution,omitempty"` // deb
	Component    string    `json:"component,omitempty"`    // deb
	Readers      []string  `json:"readers,omitempty"`      // groupes en plus du rôle global
	Publishers   []string  `json:"publishers,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
	Generation   int64     `json:"generation"` // incrémenté à chaque changement de contenu
}

// Package est UNE version publiée d'un fichier.
type Package struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Arch       string            `json:"arch,omitempty"`
	Filename   string            `json:"filename"`
	Digest     string            `json:"digest"` // sha256:<hex>
	Size       int64             `json:"size"`
	MD5        string            `json:"md5,omitempty"`  // deb : exigé par Packages
	SHA1       string            `json:"sha1,omitempty"` // deb, rpm
	Summary    string            `json:"summary,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Detail     []byte            `json:"detail,omitempty"` // format propre au type (rpm.Package, deb.Control)
	UploadedAt time.Time         `json:"uploaded_at"`
	UploadedBy string            `json:"uploaded_by"`
}

// Image est une image Docker/OCI : des étiquettes vers des manifestes.
type Image struct {
	Name      string              `json:"name"`
	Tags      map[string]string   `json:"tags"`      // tag -> digest
	Manifests map[string]Manifest `json:"manifests"` // digest -> manifeste
	UpdatedAt time.Time           `json:"updated_at"`
}

// Manifest décrit un manifeste stocké comme blob.
type Manifest struct {
	Digest    string    `json:"digest"`
	MediaType string    `json:"media_type"`
	Size      int64     `json:"size"`
	Refs      []string  `json:"refs"` // blobs et manifestes référencés
	Platform  string    `json:"platform,omitempty"`
	PushedAt  time.Time `json:"pushed_at"`
	PushedBy  string    `json:"pushed_by"`
}

type repoFile struct {
	Repo     Repo              `json:"repo"`
	Packages []Package         `json:"packages"`
	Images   map[string]*Image `json:"images,omitempty"`
}

// Catalog est l'état complet, protégé par un verrou.
type Catalog struct {
	mu    sync.RWMutex
	dir   string
	repos map[string]*repoFile
	// OnChange est appelé (hors verrou) après toute modification d'un dépôt :
	// les index rpm/deb s'y régénèrent.
	OnChange func(repo Repo)
}

// Open charge le catalogue.
func Open(dataDir string) (*Catalog, error) {
	c := &Catalog{dir: filepath.Join(dataDir, "meta", "repos"), repos: map[string]*repoFile{}}
	if err := os.MkdirAll(c.dir, 0o750); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rf repoFile
		if _, err := store.LoadJSON(filepath.Join(c.dir, e.Name()), &rf); err != nil {
			return nil, fmt.Errorf("catalogue %s : %w", e.Name(), err)
		}
		if rf.Images == nil {
			rf.Images = map[string]*Image{}
		}
		c.repos[rf.Repo.Name] = &rf
	}
	return c, nil
}

func (c *Catalog) save(rf *repoFile) error {
	return store.SaveJSON(filepath.Join(c.dir, rf.Repo.Name+".json"), rf)
}

func (c *Catalog) changed(rf *repoFile) (Repo, error) {
	rf.Repo.Generation++
	if err := c.save(rf); err != nil {
		return Repo{}, err
	}
	return rf.Repo, nil
}

func (c *Catalog) notify(r Repo) {
	if c.OnChange != nil {
		c.OnChange(r)
	}
}

// EnsureRepo crée le dépôt s'il n'existe pas (dépôts déclarés en configuration).
func (c *Catalog) EnsureRepo(rc config.RepoConfig) error {
	c.mu.RLock()
	_, ok := c.repos[rc.Name]
	c.mu.RUnlock()
	if ok {
		return nil
	}
	_, err := c.CreateRepo(Repo{
		Name: rc.Name, Type: rc.Type, Description: rc.Description, Public: rc.Public,
		KeepVersions: rc.KeepVersions, Distribution: rc.Distribution, Component: rc.Component,
		Readers: rc.Readers, Publishers: rc.Publishers,
	}, "configuration")
	return err
}

// CreateRepo ajoute un dépôt.
func (c *Catalog) CreateRepo(r Repo, by string) (Repo, error) {
	if !config.ValidRepoName(r.Name) {
		return Repo{}, fmt.Errorf("nom de dépôt invalide : a-z, 0-9, . _ - (63 caractères au plus)")
	}
	if !config.ValidRepoType(r.Type) {
		return Repo{}, fmt.Errorf("type de dépôt inconnu : %q", r.Type)
	}
	if r.KeepVersions < 0 {
		r.KeepVersions = 0
	}
	if r.Type == config.RepoDeb {
		if r.Distribution == "" {
			r.Distribution = "stable"
		}
		if r.Component == "" {
			r.Component = "main"
		}
	}
	r.CreatedAt = time.Now().UTC()
	r.CreatedBy = by
	c.mu.Lock()
	if _, ok := c.repos[r.Name]; ok {
		c.mu.Unlock()
		return Repo{}, ErrRepoExists
	}
	rf := &repoFile{Repo: r, Images: map[string]*Image{}}
	c.repos[r.Name] = rf
	out, err := c.changed(rf)
	c.mu.Unlock()
	if err != nil {
		return Repo{}, err
	}
	c.notify(out)
	return out, nil
}

// UpdateRepo modifie les réglages (pas le nom ni le type).
func (c *Catalog) UpdateRepo(name string, fn func(r *Repo)) (Repo, error) {
	c.mu.Lock()
	rf, ok := c.repos[name]
	if !ok {
		c.mu.Unlock()
		return Repo{}, ErrRepoNotFound
	}
	n, t := rf.Repo.Name, rf.Repo.Type
	fn(&rf.Repo)
	rf.Repo.Name, rf.Repo.Type = n, t
	out, err := c.changed(rf)
	c.mu.Unlock()
	if err == nil {
		c.notify(out)
	}
	return out, err
}

// DeleteRepo supprime un dépôt et ses métadonnées. Les blobs partent au
// prochain ramasse-miettes.
func (c *Catalog) DeleteRepo(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.repos[name]; !ok {
		return ErrRepoNotFound
	}
	delete(c.repos, name)
	return os.Remove(filepath.Join(c.dir, name+".json"))
}

// Repo rend un dépôt.
func (c *Catalog) Repo(name string) (Repo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, ok := c.repos[name]
	if !ok {
		return Repo{}, ErrRepoNotFound
	}
	return rf.Repo, nil
}

// Repos rend tous les dépôts, triés par nom.
func (c *Catalog) Repos() []Repo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Repo, 0, len(c.repos))
	for _, rf := range c.repos {
		out = append(out, rf.Repo)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RepoStats résume un dépôt.
type RepoStats struct {
	Packages int   // noms distincts (ou images)
	Versions int   // versions (ou manifestes)
	Size     int64 // somme des tailles déclarées
}

// Stats rend le résumé d'un dépôt.
func (c *Catalog) Stats(name string) RepoStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, ok := c.repos[name]
	if !ok {
		return RepoStats{}
	}
	var s RepoStats
	names := map[string]bool{}
	for _, p := range rf.Packages {
		names[p.Name] = true
		s.Versions++
		s.Size += p.Size
	}
	s.Packages = len(names)
	for _, im := range rf.Images {
		s.Packages++
		for _, m := range im.Manifests {
			s.Versions++
			s.Size += m.Size
		}
	}
	return s
}

// AddPackage publie une version. Une version existante (même nom, version,
// architecture) est refusée : une version publiée est immuable. Rend aussi
// les versions retirées par la rétention.
func (c *Catalog) AddPackage(repo string, p Package) (Package, []Package, error) {
	c.mu.Lock()
	rf, ok := c.repos[repo]
	if !ok {
		c.mu.Unlock()
		return Package{}, nil, ErrRepoNotFound
	}
	if rf.Repo.Type == config.RepoDocker {
		c.mu.Unlock()
		return Package{}, nil, ErrWrongType
	}
	for _, q := range rf.Packages {
		if q.Name == p.Name && q.Version == p.Version && q.Arch == p.Arch && q.Filename == p.Filename {
			c.mu.Unlock()
			return Package{}, nil, ErrVersionExists
		}
		// Deux paquets différents ne peuvent pas porter le même nom de fichier :
		// dnf et apt les téléchargent par ce nom.
		if q.Filename == p.Filename && (rf.Repo.Type == config.RepoRPM || rf.Repo.Type == config.RepoDeb) {
			c.mu.Unlock()
			return Package{}, nil, fmt.Errorf("le fichier %s existe déjà dans ce dépôt", p.Filename)
		}
	}
	p.ID = newID()
	p.UploadedAt = time.Now().UTC()
	rf.Packages = append(rf.Packages, p)
	removed := applyRetention(rf)
	out, err := c.changed(rf)
	c.mu.Unlock()
	if err != nil {
		return Package{}, nil, err
	}
	c.notify(out)
	return p, removed, nil
}

// applyRetention garde les keep_versions versions les plus récentes de chaque
// (nom, architecture). 0 = illimité.
func applyRetention(rf *repoFile) []Package {
	keep := rf.Repo.KeepVersions
	if keep <= 0 {
		return nil
	}
	groups := map[string][]int{}
	for i, p := range rf.Packages {
		k := p.Name + "\x00" + p.Arch
		groups[k] = append(groups[k], i)
	}
	drop := map[int]bool{}
	for _, idx := range groups {
		if len(idx) <= keep {
			continue
		}
		sort.Slice(idx, func(a, b int) bool {
			return vercmp.Less(rf.Packages[idx[b]].Version, rf.Packages[idx[a]].Version) // décroissant
		})
		for _, i := range idx[keep:] {
			drop[i] = true
		}
	}
	if len(drop) == 0 {
		return nil
	}
	var kept, removed []Package
	for i, p := range rf.Packages {
		if drop[i] {
			removed = append(removed, p)
		} else {
			kept = append(kept, p)
		}
	}
	rf.Packages = kept
	return removed
}

// DeletePackage retire une version.
func (c *Catalog) DeletePackage(repo, id string) (Package, error) {
	c.mu.Lock()
	rf, ok := c.repos[repo]
	if !ok {
		c.mu.Unlock()
		return Package{}, ErrRepoNotFound
	}
	for i, p := range rf.Packages {
		if p.ID == id {
			rf.Packages = append(rf.Packages[:i], rf.Packages[i+1:]...)
			out, err := c.changed(rf)
			c.mu.Unlock()
			if err == nil {
				c.notify(out)
			}
			return p, err
		}
	}
	c.mu.Unlock()
	return Package{}, ErrPackageNotFound
}

// Packages rend les versions d'un dépôt, filtrées par nom si name != "".
// Tri : nom, puis version décroissante.
func (c *Catalog) Packages(repo, name string) ([]Package, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, ok := c.repos[repo]
	if !ok {
		return nil, ErrRepoNotFound
	}
	out := make([]Package, 0, len(rf.Packages))
	for _, p := range rf.Packages {
		if name == "" || p.Name == name {
			out = append(out, p)
		}
	}
	SortPackages(out)
	return out, nil
}

// SortPackages : nom croissant, version décroissante, architecture.
func SortPackages(ps []Package) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Name != ps[j].Name {
			return ps[i].Name < ps[j].Name
		}
		if c := vercmp.Compare(ps[i].Version, ps[j].Version); c != 0 {
			return c > 0
		}
		return ps[i].Arch < ps[j].Arch
	})
}

// Package rend une version par identifiant.
func (c *Catalog) Package(repo, id string) (Package, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, ok := c.repos[repo]
	if !ok {
		return Package{}, ErrRepoNotFound
	}
	for _, p := range rf.Packages {
		if p.ID == id {
			return p, nil
		}
	}
	return Package{}, ErrPackageNotFound
}

// FindFile rend la version dont le nom de fichier correspond (téléchargements
// dnf/apt, qui ne connaissent que le nom de fichier).
func (c *Catalog) FindFile(repo, filename string) (Package, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rf, ok := c.repos[repo]
	if !ok {
		return Package{}, ErrRepoNotFound
	}
	for _, p := range rf.Packages {
		if p.Filename == filename {
			return p, nil
		}
	}
	return Package{}, ErrPackageNotFound
}

// FindVersion rend le fichier d'une version (dépôts de fichiers). version
// « latest » désigne la plus haute.
func (c *Catalog) FindVersion(repo, name, version, filename string) (Package, error) {
	ps, err := c.Packages(repo, name)
	if err != nil {
		return Package{}, err
	}
	if version == "latest" {
		version = ""
		for _, p := range ps {
			if version == "" || vercmp.Compare(p.Version, version) > 0 {
				version = p.Version
			}
		}
	}
	for _, p := range ps {
		if p.Version == version && (filename == "" || p.Filename == filename) {
			return p, nil
		}
	}
	return Package{}, ErrPackageNotFound
}

// PackageSummary regroupe les versions d'un même nom.
type PackageSummary struct {
	Name     string
	Latest   string
	Versions int
	Size     int64
	Summary  string
	Updated  time.Time
	Arches   []string
}

// Summaries rend un résumé par nom de paquet.
func (c *Catalog) Summaries(repo string) ([]PackageSummary, error) {
	ps, err := c.Packages(repo, "")
	if err != nil {
		return nil, err
	}
	idx := map[string]*PackageSummary{}
	var order []string
	for _, p := range ps {
		s, ok := idx[p.Name]
		if !ok {
			s = &PackageSummary{Name: p.Name, Latest: p.Version, Summary: p.Summary}
			idx[p.Name] = s
			order = append(order, p.Name)
		}
		s.Versions++
		s.Size += p.Size
		if p.UploadedAt.After(s.Updated) {
			s.Updated = p.UploadedAt
		}
		if p.Arch != "" && !contains(s.Arches, p.Arch) {
			s.Arches = append(s.Arches, p.Arch)
		}
	}
	out := make([]PackageSummary, 0, len(order))
	for _, n := range order {
		out = append(out, *idx[n])
	}
	return out, nil
}

// SearchHit est un résultat de recherche.
type SearchHit struct {
	Repo     string
	RepoType string
	Name     string
	Latest   string
	Summary  string
}

// Search cherche un nom de paquet ou d'image dans les dépôts donnés.
func (c *Catalog) Search(q string, allowed func(Repo) bool) []SearchHit {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	var hits []SearchHit
	for _, r := range c.Repos() {
		if !allowed(r) {
			continue
		}
		if r.Type == config.RepoDocker {
			for _, im := range c.Images(r.Name) {
				if strings.Contains(strings.ToLower(im.Name), q) {
					hits = append(hits, SearchHit{Repo: r.Name, RepoType: r.Type, Name: im.Name, Latest: latestTag(im)})
				}
			}
			continue
		}
		sums, _ := c.Summaries(r.Name)
		for _, s := range sums {
			if strings.Contains(strings.ToLower(s.Name), q) || strings.Contains(strings.ToLower(s.Summary), q) {
				hits = append(hits, SearchHit{Repo: r.Name, RepoType: r.Type, Name: s.Name, Latest: s.Latest, Summary: s.Summary})
			}
		}
	}
	return hits
}

func latestTag(im Image) string {
	if _, ok := im.Tags["latest"]; ok {
		return "latest"
	}
	best := ""
	for t := range im.Tags {
		if best == "" || vercmp.Compare(t, best) > 0 {
			best = t
		}
	}
	return best
}

// ReferencedDigests rend tous les blobs référencés (ramasse-miettes).
func (c *Catalog) ReferencedDigests() map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string]bool{}
	for _, rf := range c.repos {
		for _, p := range rf.Packages {
			out[p.Digest] = true
		}
		for _, im := range rf.Images {
			for d, m := range im.Manifests {
				out[d] = true
				for _, r := range m.Refs {
					out[r] = true
				}
			}
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
