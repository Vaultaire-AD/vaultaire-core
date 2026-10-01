package web

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vaultaire_nexus/internal/auth"
	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/repos"
	"vaultaire_nexus/internal/usage"
	"vaultaire_nexus/version"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// statusFor traduit une erreur métier en code HTTP.
func statusFor(err error) int {
	switch {
	case errors.Is(err, catalog.ErrRepoNotFound), errors.Is(err, catalog.ErrPackageNotFound), errors.Is(err, catalog.ErrManifestUnknown):
		return http.StatusNotFound
	case errors.Is(err, catalog.ErrRepoExists), errors.Is(err, catalog.ErrVersionExists):
		return http.StatusConflict
	case errors.Is(err, repos.ErrInvalid), errors.Is(err, catalog.ErrWrongType):
		return http.StatusUnprocessableEntity
	case strings.Contains(err.Error(), "trop volumineux"):
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// apiAuth : Bearer, Basic, ou session web (avec jeton CSRF pour les écritures).
func (s *Server) apiAuth(next func(http.ResponseWriter, *http.Request, *auth.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p *auth.Principal
		if r.Header.Get("Authorization") != "" {
			var ok bool
			p, ok = s.authenticateRequest(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="Vaultaire Nexus"`)
				apiError(w, http.StatusUnauthorized, "identifiants refusés")
				return
			}
		} else if sess, ok := s.session(r); ok {
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-CSRF-Token") != sess.CSRF {
				apiError(w, http.StatusForbidden, "jeton CSRF manquant ou invalide")
				return
			}
			p = sess.Principal
		} else {
			p = auth.Anonymous
		}
		next(w, r.WithContext(withPrincipal(r.Context(), p)), p)
	}
}

func requireAuth(w http.ResponseWriter, p *auth.Principal) bool {
	if p.IsAnonymous() {
		w.Header().Set("WWW-Authenticate", `Basic realm="Vaultaire Nexus"`)
		apiError(w, http.StatusUnauthorized, "authentification requise")
		return false
	}
	return true
}

func (s *Server) routesAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health", s.apiHealth)
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": version.Version, "complete": version.Complete()})
	})
	mux.HandleFunc("GET /api/v1/whoami", s.apiAuth(s.apiWhoami))
	mux.HandleFunc("GET /api/v1/repos", s.apiAuth(s.apiRepos))
	mux.HandleFunc("POST /api/v1/repos", s.apiAuth(s.apiCreateRepo))
	mux.HandleFunc("GET /api/v1/repos/{repo}", s.apiAuth(s.apiRepo))
	mux.HandleFunc("PATCH /api/v1/repos/{repo}", s.apiAuth(s.apiUpdateRepo))
	mux.HandleFunc("DELETE /api/v1/repos/{repo}", s.apiAuth(s.apiDeleteRepo))
	mux.HandleFunc("GET /api/v1/repos/{repo}/packages", s.apiAuth(s.apiPackages))
	mux.HandleFunc("GET /api/v1/repos/{repo}/packages/{id}", s.apiAuth(s.apiPackage))
	mux.HandleFunc("DELETE /api/v1/repos/{repo}/packages/{id}", s.apiAuth(s.apiDeletePackage))
	mux.HandleFunc("PUT /api/v1/repos/{repo}/upload", s.apiAuth(s.apiUpload))
	mux.HandleFunc("POST /api/v1/repos/{repo}/upload", s.apiAuth(s.apiUpload))
	// « curl -T fichier …/upload/ » ajoute lui-même le nom du fichier à l'URL.
	mux.HandleFunc("PUT /api/v1/repos/{repo}/upload/{filename}", s.apiAuth(s.apiUpload))
	mux.HandleFunc("GET /api/v1/repos/{repo}/images", s.apiAuth(s.apiImages))
	mux.HandleFunc("POST /api/v1/repos/{repo}/reindex", s.apiAuth(s.apiReindex))
	mux.HandleFunc("POST /api/v1/repos/{repo}/import-github", s.apiAuth(s.apiImportGitHub))
	mux.HandleFunc("GET /api/v1/search", s.apiAuth(s.apiSearch))
	mux.HandleFunc("GET /api/v1/usage", s.apiAuth(s.apiUsage))
	mux.HandleFunc("GET /api/v1/usage/export", s.apiAuth(s.apiUsageExport))
	mux.HandleFunc("GET /api/v1/tokens", s.apiAuth(s.apiTokens))
	mux.HandleFunc("POST /api/v1/tokens", s.apiAuth(s.apiCreateToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.apiAuth(s.apiRevokeToken))
	mux.HandleFunc("POST /api/v1/admin/gc", s.apiAuth(s.apiGC))
}

func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	count, size := s.Mgr.Blobs.Usage()
	body := map[string]any{
		"status": "ok", "version": version.Complete(), "uptime_s": int(time.Since(s.started).Seconds()),
		"repos": len(s.Cat.Repos()), "blobs": count, "blob_bytes": size,
		"usage_dropped": s.Usage.Dropped(), "auth_mode": s.Auth.Mode(),
	}
	if s.Cluster != nil {
		body["cluster"] = s.Cluster()
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) apiWhoami(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username": p.Username, "display": p.Display, "source": p.Source,
		"groups": p.Groups, "rights": p.Rights, "role": p.EffectiveRole(), "token": p.TokenID,
	})
}

type repoJSON struct {
	catalog.Repo
	Packages int    `json:"packages"`
	Versions int    `json:"versions"`
	Size     int64  `json:"size"`
	URL      string `json:"url"`
	CanWrite bool   `json:"can_publish"`
}

func (s *Server) repoJSON(r *http.Request, p *auth.Principal, repo catalog.Repo) repoJSON {
	st := s.Cat.Stats(repo.Name)
	return repoJSON{Repo: repo, Packages: st.Packages, Versions: st.Versions, Size: st.Size,
		URL: s.repoURL(r, repo), CanWrite: auth.CanPublish(p, repoView(repo))}
}

func (s *Server) repoURL(r *http.Request, repo catalog.Repo) string {
	base := s.baseURL(r)
	switch repo.Type {
	case config.RepoRPM:
		return base + "/repo/rpm/" + repo.Name + "/"
	case config.RepoDeb:
		return base + "/repo/deb/" + repo.Name + "/"
	case config.RepoDocker:
		return strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://") + "/" + repo.Name + "/"
	case config.RepoVaultaire:
		return base + "/repo/vaultaire/" + repo.Name + "/api"
	}
	return base + "/repo/files/" + repo.Name + "/"
}

func (s *Server) visibleRepos(p *auth.Principal) []catalog.Repo {
	var out []catalog.Repo
	for _, r := range s.Cat.Repos() {
		if auth.CanRead(p, repoView(r)) {
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) apiRepos(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	out := []repoJSON{}
	for _, repo := range s.visibleRepos(p) {
		out = append(out, s.repoJSON(r, p, repo))
	}
	writeJSON(w, http.StatusOK, out)
}

// repoFor charge un dépôt lisible par p ; 404 sinon (on ne révèle pas
// l'existence d'un dépôt privé).
func (s *Server) repoFor(w http.ResponseWriter, r *http.Request, p *auth.Principal) (catalog.Repo, bool) {
	repo, err := s.Cat.Repo(r.PathValue("repo"))
	if err != nil || !auth.CanRead(p, repoView(repo)) {
		if err == nil && p.IsAnonymous() {
			requireAuth(w, p)
			return repo, false
		}
		apiError(w, http.StatusNotFound, "dépôt introuvable")
		return repo, false
	}
	return repo, true
}

func (s *Server) apiRepo(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.repoFor(w, r, p)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.repoJSON(r, p, repo))
}

type repoInput struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Description  *string  `json:"description"`
	Public       *bool    `json:"public"`
	KeepVersions *int     `json:"keep_versions"`
	Distribution string   `json:"distribution"`
	Component    string   `json:"component"`
	Readers      []string `json:"readers"`
	Publishers   []string `json:"publishers"`
}

func decodeJSON(r *http.Request, v any) error {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" {
		return errors.New("Content-Type application/json attendu")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) apiCreateRepo(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	if !auth.CanAdmin(p) {
		apiError(w, http.StatusForbidden, "réservé aux administrateurs")
		return
	}
	var in repoInput
	if err := decodeJSON(r, &in); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	repo := catalog.Repo{Name: in.Name, Type: in.Type, Distribution: in.Distribution, Component: in.Component,
		Readers: cleanList(in.Readers), Publishers: cleanList(in.Publishers)}
	if in.Description != nil {
		repo.Description = *in.Description
	}
	if in.Public != nil {
		repo.Public = *in.Public
	}
	if in.KeepVersions != nil {
		repo.KeepVersions = *in.KeepVersions
	}
	out, err := s.Cat.CreateRepo(repo, p.Username)
	if err != nil {
		apiError(w, statusFor(err), err.Error())
		return
	}
	s.Log.Info("dépôt créé", "repo", out.Name, "type", out.Type, "par", p.Username)
	writeJSON(w, http.StatusCreated, s.repoJSON(r, p, out))
}

func (s *Server) apiUpdateRepo(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	if !auth.CanAdmin(p) {
		apiError(w, http.StatusForbidden, "réservé aux administrateurs")
		return
	}
	var in repoInput
	if err := decodeJSON(r, &in); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.Cat.UpdateRepo(r.PathValue("repo"), func(repo *catalog.Repo) {
		applyRepoInput(repo, in)
	})
	if err != nil {
		apiError(w, statusFor(err), err.Error())
		return
	}
	s.Log.Info("dépôt modifié", "repo", out.Name, "par", p.Username)
	writeJSON(w, http.StatusOK, s.repoJSON(r, p, out))
}

func applyRepoInput(repo *catalog.Repo, in repoInput) {
	if in.Description != nil {
		repo.Description = *in.Description
	}
	if in.Public != nil {
		repo.Public = *in.Public
	}
	if in.KeepVersions != nil && *in.KeepVersions >= 0 {
		repo.KeepVersions = *in.KeepVersions
	}
	if in.Readers != nil {
		repo.Readers = cleanList(in.Readers)
	}
	if in.Publishers != nil {
		repo.Publishers = cleanList(in.Publishers)
	}
}

func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		for _, part := range strings.Split(s, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func (s *Server) apiDeleteRepo(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	if !auth.CanAdmin(p) {
		apiError(w, http.StatusForbidden, "réservé aux administrateurs")
		return
	}
	name := r.PathValue("repo")
	if r.URL.Query().Get("confirm") != name {
		apiError(w, http.StatusBadRequest, "confirmez avec ?confirm=<nom du dépôt>")
		return
	}
	if err := s.Cat.DeleteRepo(name); err != nil {
		apiError(w, statusFor(err), err.Error())
		return
	}
	_ = s.Mgr.RebuildIndex(name)
	s.Log.Warn("dépôt supprimé", "repo", name, "par", p.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiPackages(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.repoFor(w, r, p)
	if !ok {
		return
	}
	pkgs, err := s.Cat.Packages(repo.Name, r.URL.Query().Get("name"))
	if err != nil {
		apiError(w, statusFor(err), err.Error())
		return
	}
	type pkgJSON struct {
		catalog.Package
		Detail    any    `json:"detail,omitempty"`
		URL       string `json:"url"`
		Downloads int64  `json:"downloads"`
	}
	out := []pkgJSON{}
	for _, pk := range pkgs {
		j := pkgJSON{Package: pk, URL: s.packageURL(r, repo, pk)}
		j.Package.Detail = nil
		if c, ok := s.Usage.For(repo.Name, pk.Name); ok {
			j.Downloads = c.ByVersion[pk.Version]
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) packageURL(r *http.Request, repo catalog.Repo, p catalog.Package) string {
	base := s.baseURL(r)
	switch repo.Type {
	case config.RepoRPM:
		return base + "/repo/rpm/" + repo.Name + "/Packages/" + p.Filename
	case config.RepoDeb:
		return base + "/repo/deb/" + repo.Name + "/" + s.debPool(repo, p)
	case config.RepoVaultaire:
		return base + "/repo/vaultaire/" + repo.Name + "/download/v" + p.Version + "/" + p.Filename
	}
	return base + "/repo/files/" + repo.Name + "/" + p.Name + "/" + p.Version + "/" + p.Filename
}

func (s *Server) apiPackage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.repoFor(w, r, p)
	if !ok {
		return
	}
	pk, err := s.Cat.Package(repo.Name, r.PathValue("id"))
	if err != nil {
		apiError(w, statusFor(err), err.Error())
		return
	}
	var detail any
	_ = json.Unmarshal(pk.Detail, &detail)
	pk.Detail = nil
	writeJSON(w, http.StatusOK, map[string]any{"package": pk, "detail": detail, "url": s.packageURL(r, repo, pk)})
}

func (s *Server) apiDeletePackage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	repo, ok := s.repoFor(w, r, p)
	if !ok {
		return
	}
	if !auth.CanPublish(p, repoView(repo)) {
		apiError(w, http.StatusForbidden, "droit de publication requis")
		return
	}
	pk, err := s.Mgr.Delete(repo.Name, r.PathValue("id"))
	if err != nil {
		apiError(w, statusFor(err), err.Error())
		return
	}
	s.Usage.Record(usage.Event{Action: usage.ActionDelete, Repo: repo.Name, RepoType: repo.Type, Name: pk.Name,
		Version: pk.Version, File: pk.Filename, User: p.Username, IP: s.clientIP(r), Status: http.StatusNoContent})
	s.Log.Info("version supprimée", "repo", repo.Name, "fichier", pk.Filename, "par", p.Username)
	w.WriteHeader(http.StatusNoContent)
}

// apiUpload accepte un corps brut (PUT, ?filename=&name=&version=&arch=) ou un
// formulaire multipart (POST, champ « file »).
func (s *Server) apiUpload(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	repo, ok := s.repoFor(w, r, p)
	if !ok {
		return
	}
	if !auth.CanPublish(p, repoView(repo)) {
		apiError(w, http.StatusForbidden, "droit de publication requis")
		return
	}
	pk, removed, status, err := s.handleUpload(w, r, p, repo, false)
	if err != nil {
		apiError(w, status, err.Error())
		return
	}
	var gone []string
	for _, g := range removed {
		gone = append(gone, g.Filename)
	}
	pk.Detail = nil
	writeJSON(w, http.StatusCreated, map[string]any{"package": pk, "url": s.packageURL(r, repo, pk), "retention_removed": gone})
}

// handleUpload est partagé par l'API et le formulaire de l'interface.
// formCSRF : l'envoi vient du formulaire de l'interface ; le champ « csrf »
// doit alors précéder le fichier dans le corps multipart.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request, p *auth.Principal, repo catalog.Repo, formCSRF bool) (catalog.Package, []catalog.Package, int, error) {
	start := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, s.Cfg.MaxUploadBytes()+1<<20)
	q := r.URL.Query()
	filename := q.Get("filename")
	if filename == "" {
		filename = r.PathValue("filename")
	}
	meta := repos.UploadMeta{Filename: filename, Name: q.Get("name"), Version: q.Get("version"), Arch: q.Get("arch"), Summary: q.Get("summary")}
	var body io.Reader = r.Body
	csrfOK := !formCSRF
	if formCSRF && !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return catalog.Package{}, nil, http.StatusBadRequest, errors.New("formulaire multipart attendu")
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			return catalog.Package{}, nil, http.StatusBadRequest, err
		}
		for {
			part, err := mr.NextPart()
			if err != nil {
				return catalog.Package{}, nil, http.StatusBadRequest, errors.New("champ « file » absent")
			}
			if part.FormName() == "file" {
				if !csrfOK {
					return catalog.Package{}, nil, http.StatusForbidden, errors.New("jeton CSRF manquant — rechargez la page")
				}
				if meta.Filename == "" {
					meta.Filename = part.FileName()
				}
				body = part
				break
			}
			val, _ := io.ReadAll(io.LimitReader(part, 4096))
			v := strings.TrimSpace(string(val))
			switch part.FormName() {
			case "name":
				meta.Name = v
			case "version":
				meta.Version = v
			case "arch":
				meta.Arch = v
			case "summary":
				meta.Summary = v
			case "csrf":
				if sess, ok := s.session(r); !ok || v != sess.CSRF {
					return catalog.Package{}, nil, http.StatusForbidden, errors.New("jeton CSRF invalide")
				}
				csrfOK = true
			}
		}
	}
	if meta.Name == "" && repo.Type == config.RepoVaultaire {
		// Nom d'archive standard : composant, version et architecture s'en déduisent.
		if n, v, a, ok := parseAsset(meta.Filename); ok {
			meta.Name, meta.Arch = n, a
			if meta.Version == "" {
				meta.Version = v
			}
		}
	}
	pk, removed, err := s.Mgr.Ingest(repo.Name, body, meta, p.Username)
	status := http.StatusCreated
	if err != nil {
		status = statusFor(err)
	}
	ev := usage.Event{Action: usage.ActionUpload, Repo: repo.Name, RepoType: repo.Type, Name: pk.Name, Version: pk.Version,
		File: pk.Filename, User: p.Username, IP: s.clientIP(r), Agent: r.UserAgent(), Bytes: pk.Size, Status: status,
		Millis: time.Since(start).Milliseconds()}
	s.Usage.Record(ev)
	if err != nil {
		s.Log.Warn("envoi refusé", "repo", repo.Name, "par", p.Username, "err", err)
		return pk, nil, status, err
	}
	s.Log.Info("version publiée", "repo", repo.Name, "paquet", pk.Name, "version", pk.Version, "par", p.Username)
	return pk, removed, status, nil
}

func (s *Server) apiImages(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.repoFor(w, r, p)
	if !ok {
		return
	}
	if repo.Type != config.RepoDocker {
		apiError(w, http.StatusUnprocessableEntity, "ce dépôt n'est pas un dépôt Docker")
		return
	}
	type imgJSON struct {
		Name      string             `json:"name"`
		Pull      string             `json:"pull"`
		Tags      map[string]string  `json:"tags"`
		Manifests []catalog.Manifest `json:"manifests"`
		Pulls     int64              `json:"pulls"`
		Updated   time.Time          `json:"updated_at"`
	}
	out := []imgJSON{}
	for _, im := range s.Cat.Images(repo.Name) {
		j := imgJSON{Name: im.Name, Pull: s.repoURL(r, repo) + im.Name, Tags: im.Tags, Updated: im.UpdatedAt}
		for _, m := range im.Manifests {
			j.Manifests = append(j.Manifests, m)
		}
		if c, ok := s.Usage.For(repo.Name, im.Name); ok {
			j.Pulls = c.Downloads
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiReindex(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	repo, ok := s.repoFor(w, r, p)
	if !ok {
		return
	}
	if !auth.CanPublish(p, repoView(repo)) {
		apiError(w, http.StatusForbidden, "droit de publication requis")
		return
	}
	if err := s.Mgr.RebuildIndex(repo.Name); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "index régénéré"})
}

func (s *Server) apiImportGitHub(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	repo, ok := s.repoFor(w, r, p)
	if !ok {
		return
	}
	if !auth.CanAdmin(p) {
		apiError(w, http.StatusForbidden, "réservé aux administrateurs")
		return
	}
	if repo.Type != config.RepoVaultaire {
		apiError(w, http.StatusUnprocessableEntity, "import réservé aux dépôts de type vaultaire")
		return
	}
	var in struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
	}
	if err := decodeJSON(r, &in); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Repository == "" {
		in.Repository = "Vaultaire-AD/vaultaire-core"
	}
	res, err := s.Importer.Import(r.Context(), repo.Name, in.Repository, in.Tag, p.Username)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "partial": res})
		return
	}
	s.Log.Info("import GitHub", "repo", repo.Name, "source", in.Repository, "tag", res.Tag, "fichiers", len(res.Imported), "par", p.Username)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) apiSearch(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	hits := s.Cat.Search(r.URL.Query().Get("q"), func(repo catalog.Repo) bool { return auth.CanRead(p, repoView(repo)) })
	if hits == nil {
		hits = []catalog.SearchHit{}
	}
	writeJSON(w, http.StatusOK, hits)
}

func (s *Server) readableRepoNames(p *auth.Principal) func(string) bool {
	allowed := map[string]bool{}
	for _, r := range s.visibleRepos(p) {
		allowed[r.Name] = true
	}
	return func(n string) bool { return allowed[n] }
}

func (s *Server) apiUsage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	q := r.URL.Query()
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 || days > 366 {
		days = 30
	}
	allowed := s.readableRepoNames(p)
	body := map[string]any{
		"days":   s.Usage.Days(days),
		"totals": s.Usage.Totals(days),
		"top":    topJSON(s.Usage.Top(q.Get("repo"), 50, allowed)),
		"recent": s.Usage.Recent(100, func(e usage.Event) bool {
			return allowed(e.Repo) && (q.Get("repo") == "" || e.Repo == q.Get("repo")) && (q.Get("name") == "" || e.Name == q.Get("name"))
		}),
	}
	if auth.CanAdmin(p) {
		body["clients"] = clientsJSON(s.Usage.Clients(100))
		body["dropped"] = s.Usage.Dropped()
	}
	writeJSON(w, http.StatusOK, body)
}

func topJSON(cs []usage.Counter) []map[string]any {
	out := []map[string]any{}
	for _, c := range cs {
		out = append(out, map[string]any{"repo": c.Repo, "name": c.Name, "downloads": c.Downloads,
			"bytes": c.Bytes, "users": len(c.Users), "last": c.Last, "by_version": c.ByVersion})
	}
	return out
}

func clientsJSON(cs []usage.Client) []map[string]any {
	out := []map[string]any{}
	for _, c := range cs {
		users := []string{}
		for u := range c.Users {
			users = append(users, u)
		}
		out = append(out, map[string]any{"ip": c.IP, "users": users, "agent": c.Agent,
			"downloads": c.Downloads, "bytes": c.Bytes, "last": c.Last})
	}
	return out
}

// apiUsageExport : journal brut en JSON Lines (administrateurs).
func (s *Server) apiUsageExport(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	if !auth.CanAdmin(p) {
		apiError(w, http.StatusForbidden, "réservé aux administrateurs")
		return
	}
	q := r.URL.Query()
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -7)
	if v, err := time.Parse("2006-01-02", q.Get("from")); err == nil {
		from = v
	}
	if v, err := time.Parse("2006-01-02", q.Get("to")); err == nil {
		to = v.Add(24*time.Hour - time.Nanosecond)
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="nexus-usage.jsonl"`)
	repo := q.Get("repo")
	_ = s.Usage.Export(bufio.NewWriter(w), from, to, func(e usage.Event) bool { return repo == "" || e.Repo == repo })
}

func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	owner := p.Username
	if auth.CanAdmin(p) && r.URL.Query().Get("all") == "1" {
		owner = ""
	}
	writeJSON(w, http.StatusOK, s.Auth.Tokens.List(owner))
}

func (s *Server) apiCreateToken(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	var in struct {
		Label string `json:"label"`
		Scope string `json:"scope"`
		Days  int    `json:"expires_days"`
	}
	if err := decodeJSON(r, &in); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Scope == "" {
		in.Scope = config.RoleReader
	}
	tk, raw, err := s.Auth.Tokens.Create(p, in.Label, in.Scope, time.Duration(in.Days)*24*time.Hour)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Log.Info("jeton créé", "id", tk.ID, "titulaire", p.Username, "portée", tk.Scope)
	tk.Hash = ""
	writeJSON(w, http.StatusCreated, map[string]any{"token": raw, "info": tk,
		"note": "Ce secret n'est affiché qu'une fois."})
}

func (s *Server) apiRevokeToken(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	owner := p.Username
	if auth.CanAdmin(p) {
		owner = ""
	}
	if err := s.Auth.Tokens.Revoke(r.PathValue("id"), owner); err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	s.Log.Info("jeton révoqué", "id", r.PathValue("id"), "par", p.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiGC(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !requireAuth(w, p) {
		return
	}
	if !auth.CanAdmin(p) {
		apiError(w, http.StatusForbidden, "réservé aux administrateurs")
		return
	}
	dry := r.URL.Query().Get("dry_run") == "1"
	st, err := s.Mgr.GC(dry)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.reg.CleanupUploads()
	s.Log.Info("ramasse-miettes", "supprimés", st.Removed, "octets", st.Freed, "simulation", dry, "par", p.Username)
	writeJSON(w, http.StatusOK, map[string]any{"scanned": st.Scanned, "removed": st.Removed, "freed_bytes": st.Freed, "kept": st.Kept, "dry_run": dry})
}
