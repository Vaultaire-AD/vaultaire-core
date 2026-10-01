// Package repos relie le stockage, le catalogue et les formats : il reçoit un
// fichier, le reconnaît, le range, et tient les index des dépôts à jour.
package repos

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/debrepo"
	"vaultaire_nexus/internal/rpmrepo"
	"vaultaire_nexus/internal/signing"
	"vaultaire_nexus/internal/store"
)

// ErrInvalid : fichier refusé (format, nom, version).
var ErrInvalid = errors.New("fichier refusé")

// Manager est le point d'entrée des publications.
type Manager struct {
	Cat      *catalog.Catalog
	Blobs    *store.Blobs
	Signer   *signing.GPG // nil : dépôts non signés
	Log      *slog.Logger
	indexDir string
	maxBytes int64

	mu      sync.Mutex
	pending map[string]*time.Timer
	indexMu sync.Map // repo -> *sync.Mutex
}

// New assemble le gestionnaire et branche la régénération des index.
func New(cfg *config.Config, cat *catalog.Catalog, blobs *store.Blobs, signer *signing.GPG, log *slog.Logger) *Manager {
	m := &Manager{
		Cat: cat, Blobs: blobs, Signer: signer, Log: log,
		indexDir: filepath.Join(cfg.DataDir, "index"),
		maxBytes: cfg.MaxUploadBytes(),
		pending:  map[string]*time.Timer{},
	}
	cat.OnChange = func(r catalog.Repo) { m.scheduleIndex(r.Name) }
	return m
}

// UploadMeta complète un envoi quand le fichier ne se décrit pas lui-même
// (dépôts vaultaire et generic).
type UploadMeta struct {
	Filename string
	Name     string
	Version  string
	Arch     string
	Summary  string
}

var (
	safeFile    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,199}$`)
	safeName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$`)
)

// Ingest reçoit un fichier et le publie.
func (m *Manager) Ingest(repoName string, r io.Reader, meta UploadMeta, by string) (catalog.Package, []catalog.Package, error) {
	repo, err := m.Cat.Repo(repoName)
	if err != nil {
		return catalog.Package{}, nil, err
	}
	if repo.Type == config.RepoDocker {
		return catalog.Package{}, nil, fmt.Errorf("%w : un dépôt Docker se remplit avec docker push", ErrInvalid)
	}
	res, err := m.Blobs.Put(r, "", m.maxBytes)
	if err != nil {
		return catalog.Package{}, nil, err
	}
	p := catalog.Package{Digest: res.Digest, Size: res.Size, MD5: res.MD5, SHA1: res.SHA1, UploadedBy: by}

	switch repo.Type {
	case config.RepoRPM:
		err = m.describeRPM(&p, res)
	case config.RepoDeb:
		err = m.describeDeb(&p, res)
	default:
		err = describeFile(&p, meta)
	}
	if err != nil {
		// Le blob reste orphelin et partira au ramasse-miettes.
		return catalog.Package{}, nil, err
	}
	added, removed, err := m.Cat.AddPackage(repoName, p)
	if err != nil {
		return catalog.Package{}, nil, err
	}
	return added, removed, nil
}

func (m *Manager) describeRPM(p *catalog.Package, res store.Result) error {
	f, _, err := m.Blobs.Open(res.Digest)
	if err != nil {
		return err
	}
	defer f.Close()
	rp, err := rpmrepo.Parse(f)
	if err != nil {
		return fmt.Errorf("%w : %v", ErrInvalid, err)
	}
	if rp.IsSource {
		return fmt.Errorf("%w : les RPM sources ne sont pas servis", ErrInvalid)
	}
	p.Name = rp.Name
	p.Version = rp.FullVersion()
	p.Arch = rp.Arch
	p.Filename = rp.CanonicalFilename()
	p.Summary = rp.Summary
	p.Fields = map[string]string{"license": rp.License, "url": rp.URL, "vendor": rp.Vendor, "packager": rp.Packager}
	p.Detail, err = json.Marshal(rp)
	return err
}

func (m *Manager) describeDeb(p *catalog.Package, res store.Result) error {
	f, _, err := m.Blobs.Open(res.Digest)
	if err != nil {
		return err
	}
	defer f.Close()
	c, err := debrepo.Parse(f)
	if err != nil {
		return fmt.Errorf("%w : %v", ErrInvalid, err)
	}
	p.Name = c.Package()
	p.Version = c.Version()
	p.Arch = c.Architecture()
	p.Filename = c.CanonicalFilename()
	p.Summary = c.Summary()
	p.Fields = map[string]string{"maintainer": c.Get("Maintainer"), "section": c.Get("Section"), "depends": c.Get("Depends"), "homepage": c.Get("Homepage")}
	p.Detail, err = json.Marshal(c)
	return err
}

func describeFile(p *catalog.Package, meta UploadMeta) error {
	fn := path.Base(strings.ReplaceAll(meta.Filename, `\`, "/"))
	switch {
	case !safeFile.MatchString(fn):
		return fmt.Errorf("%w : nom de fichier invalide %q", ErrInvalid, meta.Filename)
	case !safeName.MatchString(meta.Name):
		return fmt.Errorf("%w : nom d'artefact invalide %q", ErrInvalid, meta.Name)
	case !safeVersion.MatchString(meta.Version):
		return fmt.Errorf("%w : version invalide %q", ErrInvalid, meta.Version)
	case meta.Arch != "" && !safeName.MatchString(meta.Arch):
		return fmt.Errorf("%w : architecture invalide %q", ErrInvalid, meta.Arch)
	}
	p.Filename = fn
	p.Name = meta.Name
	p.Version = strings.TrimPrefix(meta.Version, "v")
	p.Arch = meta.Arch
	p.Summary = meta.Summary
	return nil
}

// Delete retire une version.
func (m *Manager) Delete(repo, id string) (catalog.Package, error) {
	return m.Cat.DeletePackage(repo, id)
}

// --- index ---------------------------------------------------------------

func (m *Manager) scheduleIndex(repo string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.pending[repo]; ok {
		t.Stop()
	}
	// Un envoi en rafale (CI qui pousse vingt paquets) ne régénère qu'une fois.
	m.pending[repo] = time.AfterFunc(1500*time.Millisecond, func() {
		m.mu.Lock()
		delete(m.pending, repo)
		m.mu.Unlock()
		if err := m.RebuildIndex(repo); err != nil {
			m.Log.Error("index: régénération", "repo", repo, "err", err)
		}
	})
}

// RebuildIndex régénère l'index d'un dépôt maintenant.
func (m *Manager) RebuildIndex(repoName string) error {
	repo, err := m.Cat.Repo(repoName)
	if errors.Is(err, catalog.ErrRepoNotFound) {
		os.RemoveAll(filepath.Join(m.indexDir, "rpm", repoName))
		os.RemoveAll(filepath.Join(m.indexDir, "deb", repoName))
		return nil
	}
	if err != nil {
		return err
	}
	lk, _ := m.indexMu.LoadOrStore(repoName, &sync.Mutex{})
	lk.(*sync.Mutex).Lock()
	defer lk.(*sync.Mutex).Unlock()

	pkgs, err := m.Cat.Packages(repoName, "")
	if err != nil {
		return err
	}
	// Un *GPG nil rangé dans une interface n'est PAS une interface nil : on ne
	// l'y range que s'il existe, sinon les générateurs tenteraient de signer.
	start := time.Now()
	switch repo.Type {
	case config.RepoRPM:
		in := make([]rpmrepo.Input, 0, len(pkgs))
		for _, p := range pkgs {
			in = append(in, rpmrepo.Input{Filename: p.Filename, SHA256: strings.TrimPrefix(p.Digest, "sha256:"), Size: p.Size, UploadedAt: p.UploadedAt, Detail: p.Detail})
		}
		var s rpmrepo.Signer
		if m.Signer != nil {
			s = m.Signer
		}
		err = rpmrepo.Generate(m.RPMIndexDir(repoName), in, s)
	case config.RepoDeb:
		in := make([]debrepo.Input, 0, len(pkgs))
		for _, p := range pkgs {
			in = append(in, debrepo.Input{Filename: p.Filename, Size: p.Size, MD5: p.MD5, SHA1: p.SHA1, SHA256: strings.TrimPrefix(p.Digest, "sha256:"), Detail: p.Detail})
		}
		var s debrepo.Signer
		if m.Signer != nil {
			s = m.Signer
		}
		err = debrepo.Generate(m.DebIndexDir(repoName), m.DebSettings(repo), in, s)
	default:
		return nil
	}
	if err == nil {
		m.Log.Info("index: régénéré", "repo", repoName, "paquets", len(pkgs), "durée", time.Since(start).Round(time.Millisecond).String())
	}
	return err
}

// RebuildAll régénère tous les index (démarrage, changement de clé).
func (m *Manager) RebuildAll() {
	// Les régénérations en attente sont couvertes par celle-ci.
	m.mu.Lock()
	for r, t := range m.pending {
		t.Stop()
		delete(m.pending, r)
	}
	m.mu.Unlock()
	for _, r := range m.Cat.Repos() {
		if err := m.RebuildIndex(r.Name); err != nil {
			m.Log.Error("index: régénération", "repo", r.Name, "err", err)
		}
	}
}

// Flush attend la fin des régénérations planifiées (tests, arrêt).
func (m *Manager) Flush() {
	m.mu.Lock()
	var repos []string
	for r, t := range m.pending {
		if t.Stop() {
			repos = append(repos, r)
		}
		delete(m.pending, r)
	}
	m.mu.Unlock()
	for _, r := range repos {
		_ = m.RebuildIndex(r)
	}
}

// RPMIndexDir rend le répertoire contenant repodata/ d'un dépôt.
func (m *Manager) RPMIndexDir(repo string) string { return filepath.Join(m.indexDir, "rpm", repo) }

// DebIndexDir rend le répertoire contenant dists/ d'un dépôt.
func (m *Manager) DebIndexDir(repo string) string { return filepath.Join(m.indexDir, "deb", repo) }

// DebSettings rend la description APT d'un dépôt.
func (m *Manager) DebSettings(r catalog.Repo) debrepo.Settings {
	return debrepo.Settings{
		Origin: "Vaultaire", Label: "Vaultaire Nexus " + r.Name,
		Distribution: r.Distribution, Component: r.Component,
		Description: firstNonEmpty(r.Description, "Dépôt "+r.Name),
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// GC lance le ramasse-miettes des blobs.
func (m *Manager) GC(dryRun bool) (store.GCStats, error) {
	return m.Blobs.GC(m.Cat.ReferencedDigests(), time.Hour, dryRun)
}
