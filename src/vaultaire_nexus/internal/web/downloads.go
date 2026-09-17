package web

import (
	"bytes"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vaultaire_nexus/internal/auth"
	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/debrepo"
	"vaultaire_nexus/internal/files"
	"vaultaire_nexus/internal/usage"
)

// readableRepo authentifie l'appelant et vérifie qu'il peut lire le dépôt du
// type attendu. Rend false après avoir déjà répondu.
func (s *Server) readableRepo(w http.ResponseWriter, r *http.Request, typ string) (catalog.Repo, *auth.Principal, bool) {
	p, ok := s.authenticateRequest(r)
	if !ok {
		s.Usage.Record(usage.Event{Action: usage.ActionDownload, Repo: r.PathValue("repo"), RepoType: typ,
			User: "?", IP: s.clientIP(r), Agent: r.UserAgent(), Status: http.StatusUnauthorized})
		challenge(w)
		return catalog.Repo{}, nil, false
	}
	repo, err := s.Cat.Repo(r.PathValue("repo"))
	if err != nil || (typ != "" && repo.Type != typ && !(typ == config.RepoGeneric && repo.Type == config.RepoVaultaire)) {
		http.NotFound(w, r)
		return catalog.Repo{}, nil, false
	}
	if !auth.CanRead(p, repoView(repo)) {
		if p.IsAnonymous() {
			challenge(w)
		} else {
			http.Error(w, "accès refusé", http.StatusForbidden)
		}
		s.Usage.Record(usage.Event{Action: usage.ActionDownload, Repo: repo.Name, RepoType: repo.Type,
			User: p.Username, IP: s.clientIP(r), Agent: r.UserAgent(), Status: http.StatusForbidden})
		return catalog.Repo{}, nil, false
	}
	return repo, p, true
}

// sendPackage sert le blob d'une version et trace le téléchargement.
func (s *Server) sendPackage(w http.ResponseWriter, r *http.Request, repo catalog.Repo, p *auth.Principal, pkg catalog.Package, contentType string) {
	start := time.Now()
	f, _, err := s.Mgr.Blobs.Open(pkg.Digest)
	if err != nil {
		s.Log.Error("téléchargement: blob manquant", "repo", repo.Name, "fichier", pkg.Filename, "digest", pkg.Digest)
		http.Error(w, "contenu indisponible", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("ETag", `"`+pkg.Digest+`"`)
	h.Set("X-Checksum-Sha256", strings.TrimPrefix(pkg.Digest, "sha256:"))
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	if r.URL.Query().Get("download") == "1" {
		h.Set("Content-Disposition", `attachment; filename="`+pkg.Filename+`"`)
	}
	sw := &statusWriter{ResponseWriter: w}
	http.ServeContent(sw, r, pkg.Filename, pkg.UploadedAt, f)
	if r.Method == http.MethodHead {
		return
	}
	// Une reprise (Range) ne compte pas comme un téléchargement de plus.
	if sw.status == http.StatusOK || (sw.status == http.StatusPartialContent && strings.HasPrefix(r.Header.Get("Range"), "bytes=0-")) {
		s.Usage.Record(usage.Event{
			Action: usage.ActionDownload, Repo: repo.Name, RepoType: repo.Type,
			Name: pkg.Name, Version: pkg.Version, File: pkg.Filename,
			User: p.Username, IP: s.clientIP(r), Agent: r.UserAgent(),
			Bytes: sw.bytes, Status: sw.status, Millis: time.Since(start).Milliseconds(),
		})
	}
}

// serveIndexFile sert un fichier d'index généré, en restant sous root.
func serveIndexFile(w http.ResponseWriter, r *http.Request, root, rel string, contentType string) {
	clean := path.Clean("/" + rel)
	full := filepath.Join(root, filepath.FromSlash(clean))
	if !strings.HasPrefix(full, filepath.Clean(root)+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	// Les index changent : validation à chaque usage (dnf et apt gèrent If-Modified-Since).
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}

func indexContentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".gz"):
		return "application/gzip"
	case strings.HasSuffix(name, ".xml"):
		return "application/xml"
	case strings.HasSuffix(name, ".asc"), strings.HasSuffix(name, ".gpg"):
		return "application/pgp-signature"
	}
	return "text/plain; charset=utf-8"
}

// GET /repo/rpm/{repo}/…
func (s *Server) serveRPM(w http.ResponseWriter, r *http.Request) {
	repo, p, ok := s.readableRepo(w, r, config.RepoRPM)
	if !ok {
		return
	}
	rest := r.PathValue("path")
	switch {
	case strings.HasPrefix(rest, "repodata/"):
		serveIndexFile(w, r, s.Mgr.RPMIndexDir(repo.Name), rest, indexContentType(rest))
	case strings.HasPrefix(rest, "Packages/"):
		name := strings.TrimPrefix(rest, "Packages/")
		pkg, err := s.Cat.FindFile(repo.Name, name)
		if err != nil || strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		s.sendPackage(w, r, repo, p, pkg, "application/x-rpm")
	case rest == "nexus.repo":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(rpmRepoFile(repo, s.baseURL(r), s.Mgr.Signer != nil)))
	default:
		http.NotFound(w, r)
	}
}

// GET /repo/deb/{repo}/…
func (s *Server) serveDeb(w http.ResponseWriter, r *http.Request) {
	repo, p, ok := s.readableRepo(w, r, config.RepoDeb)
	if !ok {
		return
	}
	rest := r.PathValue("path")
	switch {
	case strings.HasPrefix(rest, "dists/"):
		serveIndexFile(w, r, s.Mgr.DebIndexDir(repo.Name), rest, indexContentType(rest))
	case strings.HasPrefix(rest, "pool/"):
		name := path.Base(rest)
		pkg, err := s.Cat.FindFile(repo.Name, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// Le chemin demandé doit être exactement celui de l'index.
		var c debrepo.Control
		if err := jsonUnmarshal(pkg.Detail, &c); err != nil || debrepo.PoolPath(repo.Component, c, pkg.Filename) != rest {
			http.NotFound(w, r)
			return
		}
		s.sendPackage(w, r, repo, p, pkg, "application/vnd.debian.binary-package")
	case rest == "nexus.list":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(debrepo.SourcesLine(s.baseURL(r), repo.Name, s.Mgr.DebSettings(repo), s.Mgr.Signer != nil) + "\n"))
	default:
		http.NotFound(w, r)
	}
}

// GET /repo/files/{repo}/{name}/{version}/{file} — version peut valoir « latest ».
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request) {
	repo, p, ok := s.readableRepo(w, r, config.RepoGeneric)
	if !ok {
		return
	}
	pkg, err := s.Cat.FindVersion(repo.Name, r.PathValue("name"), r.PathValue("version"), r.PathValue("file"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.sendPackage(w, r, repo, p, pkg, "application/octet-stream")
}

// --- API compatible releases GitHub ------------------------------------------

func (s *Server) releaseBase(r *http.Request, repo string) string {
	return s.baseURL(r) + "/repo/vaultaire/" + repo + "/download"
}

func (s *Server) releasesOf(w http.ResponseWriter, r *http.Request) (catalog.Repo, []files.Release, *auth.Principal, bool) {
	repo, p, ok := s.readableRepo(w, r, config.RepoVaultaire)
	if !ok {
		return repo, nil, nil, false
	}
	pkgs, _ := s.Cat.Packages(repo.Name, "")
	return repo, files.Releases(pkgs), p, true
}

func (s *Server) releasesList(w http.ResponseWriter, r *http.Request) {
	repo, rels, _, ok := s.releasesOf(w, r)
	if !ok {
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if n <= 0 || n > 100 {
		n = 30
	}
	if len(rels) > n {
		rels = rels[:n]
	}
	out := make([]map[string]any, 0, len(rels))
	for _, rel := range rels {
		out = append(out, rel.GitHubJSON(s.releaseBase(r, repo.Name)))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) releaseLatest(w http.ResponseWriter, r *http.Request) {
	repo, rels, _, ok := s.releasesOf(w, r)
	if !ok {
		return
	}
	for _, rel := range rels {
		if !strings.Contains(rel.Version, "~") && !strings.Contains(rel.Version, "-rc") {
			writeJSON(w, http.StatusOK, rel.GitHubJSON(s.releaseBase(r, repo.Name)))
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
}

func (s *Server) releaseByTag(w http.ResponseWriter, r *http.Request) {
	repo, _, ok := s.readableRepo(w, r, config.RepoVaultaire)
	if !ok {
		return
	}
	pkgs, _ := s.Cat.Packages(repo.Name, "")
	rel, found := files.FindRelease(pkgs, r.PathValue("tag"))
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
		return
	}
	writeJSON(w, http.StatusOK, rel.GitHubJSON(s.releaseBase(r, repo.Name)))
}

func (s *Server) releaseAsset(w http.ResponseWriter, r *http.Request) {
	repo, p, ok := s.readableRepo(w, r, config.RepoVaultaire)
	if !ok {
		return
	}
	pkgs, _ := s.Cat.Packages(repo.Name, "")
	rel, found := files.FindRelease(pkgs, r.PathValue("tag"))
	if !found {
		http.NotFound(w, r)
		return
	}
	name := r.PathValue("file")
	if name == "SHA256SUMS" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeContent(w, r, name, rel.Published, bytes.NewReader(rel.SHA256SUMS()))
		return
	}
	for _, a := range rel.Assets {
		if a.Filename == name {
			s.sendPackage(w, r, repo, p, a, "application/octet-stream")
			return
		}
	}
	http.NotFound(w, r)
}

// GET /repo/keys/nexus.asc
func (s *Server) servePublicKey(w http.ResponseWriter, r *http.Request) {
	if s.Mgr.Signer == nil {
		http.Error(w, "les dépôts ne sont pas signés", http.StatusNotFound)
		return
	}
	key, err := s.Mgr.Signer.PublicKey()
	if err != nil {
		http.Error(w, "clé indisponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Write(key)
}

// serveCertificate sert le certificat TLS du service : c'est ce que chaque
// hôte Docker doit déposer dans /etc/docker/certs.d/<hôte>:<port>/ca.crt quand
// le certificat est auto-signé. Public par nature — la clé privée n'est jamais lue ici.
func (s *Server) serveCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.TLS.Enable {
		http.Error(w, "TLS terminé par un mandataire : pas de certificat ici", http.StatusNotFound)
		return
	}
	path := s.Cfg.TLS.CertFile
	if path == "" {
		path = filepath.Join(s.Cfg.DataDir, "tls", "nexus.crt")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "certificat indisponible", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="nexus.crt"`)
	w.Write(b)
}

func rpmRepoFile(repo catalog.Repo, base string, signed bool) string {
	var b strings.Builder
	b.WriteString("[nexus-" + repo.Name + "]\n")
	b.WriteString("name=Vaultaire Nexus - " + repo.Name + "\n")
	b.WriteString("baseurl=" + base + "/repo/rpm/" + repo.Name + "/\n")
	b.WriteString("enabled=1\n")
	b.WriteString("metadata_expire=300\n")
	if signed {
		b.WriteString("repo_gpgcheck=1\ngpgkey=" + base + "/repo/keys/nexus.asc\n")
	} else {
		b.WriteString("repo_gpgcheck=0\n")
	}
	// gpgcheck porte sur la signature des PAQUETS, qui se fait à la construction.
	b.WriteString("gpgcheck=0\n")
	if !repo.Public {
		b.WriteString("username=<compte>\npassword=<jeton nxs_…>\n")
	}
	return b.String()
}
