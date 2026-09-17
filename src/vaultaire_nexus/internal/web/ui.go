package web

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"vaultaire_nexus/internal/auth"
	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/files"
	"vaultaire_nexus/internal/usage"
	"vaultaire_nexus/version"
)

// --- gabarits ---------------------------------------------------------------

var funcs = template.FuncMap{
	"bytes": humanBytes,
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("02/01/2006 15:04")
	},
	"ago":       ago,
	"join":      strings.Join,
	"typeLabel": typeLabel,
	"roleLabel": roleLabel,
	"short": func(d string) string {
		d = strings.TrimPrefix(d, "sha256:")
		if len(d) > 12 {
			return d[:12]
		}
		return d
	},
	"pathEscape":  url.PathEscape,
	"queryEscape": url.QueryEscape,
	"pct": func(v, max int64) int64 {
		if max <= 0 {
			return 0
		}
		return v * 100 / max
	},
	"add":    func(a, b int) int { return a + b },
	"mul":    func(a, b int) int { return a * b },
	"isType": func(r catalog.Repo, t string) bool { return r.Type == t },
}

func (s *Server) loadTemplates() error {
	s.tmpl = map[string]*template.Template{}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	for _, p := range pages {
		name := path.Base(p)
		if name == "layout.html" || name == "partials.html" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", p)
		if err != nil {
			return fmt.Errorf("gabarit %s : %w", name, err)
		}
		s.tmpl[strings.TrimSuffix(name, ".html")] = t
	}
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d o", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %co", float64(n)/float64(div), "KMGTPE"[exp])
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "jamais"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "à l'instant"
	case d < time.Hour:
		return fmt.Sprintf("il y a %d min", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("il y a %d h", int(d.Hours()))
	case d < 60*24*time.Hour:
		return fmt.Sprintf("il y a %d j", int(d.Hours()/24))
	}
	return t.Local().Format("02/01/2006")
}

func typeLabel(t string) string {
	switch t {
	case config.RepoRPM:
		return "RPM (dnf/yum)"
	case config.RepoDeb:
		return "Debian (apt)"
	case config.RepoDocker:
		return "Docker / OCI"
	case config.RepoVaultaire:
		return "Releases Vaultaire"
	case config.RepoGeneric:
		return "Fichiers"
	}
	return t
}

func roleLabel(r string) string {
	switch r {
	case config.RoleAdmin:
		return "administrateur"
	case config.RolePublisher:
		return "publieur"
	case config.RoleReader:
		return "lecteur"
	}
	return "aucun"
}

type flash struct {
	Kind string // ok, err, info
	Text string
}

// page est la donnée commune à tous les gabarits.
type page struct {
	Title    string
	Nav      string
	User     *auth.Principal
	CSRF     string
	IsAdmin  bool
	Flash    []flash
	Version  string
	BaseURL  string
	Host     string // pour docker : l'URL sans schéma
	AuthMode string
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title, nav string, data any, fl ...flash) {
	t, ok := s.tmpl[name]
	if !ok {
		http.Error(w, "gabarit inconnu", http.StatusInternalServerError)
		return
	}
	pg := page{Title: title, Nav: nav, Version: version.Complete(), BaseURL: s.baseURL(r), Host: hostOf(s.baseURL(r)), AuthMode: s.Auth.Mode(), Data: data, Flash: fl}
	if sess, ok := s.session(r); ok {
		pg.User, pg.CSRF, pg.IsAdmin = sess.Principal, sess.CSRF, auth.CanAdmin(sess.Principal)
	}
	// Messages de retour transmis par redirection. Bornés : une URL forgée ne
	// doit pas pouvoir afficher un roman dans la page.
	if m := r.URL.Query().Get("ok"); m != "" {
		pg.Flash = append(pg.Flash, flash{"ok", clip(m, 300)})
	}
	if m := r.URL.Query().Get("err"); m != "" {
		pg.Flash = append(pg.Flash, flash{"err", clip(m, 300)})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := t.Execute(w, pg); err != nil {
		s.Log.Error("rendu", "page", name, "err", err)
	}
}

func hostOf(base string) string {
	return strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func redirect(w http.ResponseWriter, r *http.Request, to, kind, msg string) {
	if msg != "" {
		sep := "?"
		if strings.Contains(to, "?") {
			sep = "&"
		}
		to += sep + kind + "=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// ui protège une page : session obligatoire, jeton CSRF sur les POST.
func (s *Server) ui(next func(http.ResponseWriter, *http.Request, *auth.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			if err := r.ParseForm(); err != nil || r.PostForm.Get("csrf") != sess.CSRF {
				http.Error(w, "jeton CSRF invalide — rechargez la page", http.StatusForbidden)
				return
			}
		}
		next(w, r.WithContext(withPrincipal(r.Context(), sess.Principal)), sess.Principal)
	}
}

func (s *Server) routesUI(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /{$}", s.ui(s.dashboard))
	mux.HandleFunc("GET /ui/repos", s.ui(s.reposPage))
	mux.HandleFunc("POST /ui/repos", s.ui(s.reposCreate))
	mux.HandleFunc("GET /ui/repos/{repo}", s.ui(s.repoPage))
	mux.HandleFunc("POST /ui/repos/{repo}/upload", s.ui(s.repoUpload))
	mux.HandleFunc("POST /ui/repos/{repo}/settings", s.ui(s.repoSettings))
	mux.HandleFunc("POST /ui/repos/{repo}/delete", s.ui(s.repoDelete))
	mux.HandleFunc("POST /ui/repos/{repo}/import", s.ui(s.repoImport))
	mux.HandleFunc("POST /ui/repos/{repo}/reindex", s.ui(s.repoReindex))
	mux.HandleFunc("GET /ui/repos/{repo}/package", s.ui(s.packagePage))
	mux.HandleFunc("POST /ui/repos/{repo}/package/delete", s.ui(s.packageDelete))
	mux.HandleFunc("GET /ui/repos/{repo}/image", s.ui(s.imagePage))
	mux.HandleFunc("POST /ui/repos/{repo}/image/delete", s.ui(s.imageDelete))
	mux.HandleFunc("GET /ui/search", s.ui(s.searchPage))
	mux.HandleFunc("GET /ui/usage", s.ui(s.usagePage))
	mux.HandleFunc("GET /ui/tokens", s.ui(s.tokensPage))
	mux.HandleFunc("POST /ui/tokens", s.ui(s.tokensCreate))
	mux.HandleFunc("POST /ui/tokens/revoke", s.ui(s.tokensRevoke))
	mux.HandleFunc("GET /ui/admin", s.ui(s.adminPage))
	mux.HandleFunc("POST /ui/admin/password", s.ui(s.adminPassword))
	mux.HandleFunc("POST /ui/admin/gc", s.ui(s.adminGC))
}

// --- connexion ----------------------------------------------------------------

func safeNext(n string) string {
	if n == "" || !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.Contains(n, `\`) {
		return "/"
	}
	return n
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", "Connexion", "", map[string]any{
		"Next": safeNext(r.URL.Query().Get("next")), "LocalOnly": s.Auth.Mode() == config.AuthLocal,
		"LocalName": s.Auth.Local.Username(),
	})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "formulaire invalide", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostForm.Get("next"))
	ip := s.clientIP(r)
	p, err := s.Auth.Login(r.PostForm.Get("username"), r.PostForm.Get("password"), ip)
	if err != nil {
		msg := "Identifiant ou mot de passe incorrect."
		switch {
		case errors.Is(err, auth.ErrLocked):
			msg = "Trop d'échecs : réessayez dans quelques minutes."
		case errors.Is(err, auth.ErrUnavailable):
			msg = "L'annuaire Vaultaire ne répond pas. Le compte local reste utilisable."
			s.Log.Error("login: annuaire injoignable", "err", err)
		}
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login", "Connexion", "", map[string]any{"Next": next, "Username": r.PostForm.Get("username"),
			"LocalOnly": s.Auth.Mode() == config.AuthLocal, "LocalName": s.Auth.Local.Username()}, flash{"err", msg})
		return
	}
	sess := s.Auth.Sessions.Create(p, ip)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sess.ID, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil || strings.HasPrefix(s.Cfg.PublicURL, "https://"), SameSite: http.SameSiteStrictMode,
	})
	s.Log.Info("connexion", "user", p.Username, "source", p.Source, "rôle", p.Role, "ip", ip)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.session(r); ok {
		_ = r.ParseForm()
		if r.PostForm.Get("csrf") != sess.CSRF {
			http.Error(w, "jeton CSRF invalide", http.StatusForbidden)
			return
		}
		s.Auth.Sessions.Delete(sess.ID)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- tableau de bord ---------------------------------------------------------------

type repoCard struct {
	Repo     catalog.Repo
	Stats    catalog.RepoStats
	URL      string
	CanWrite bool
}

func (s *Server) repoCards(r *http.Request, p *auth.Principal) []repoCard {
	var cards []repoCard
	for _, repo := range s.visibleRepos(p) {
		cards = append(cards, repoCard{Repo: repo, Stats: s.Cat.Stats(repo.Name), URL: s.repoURL(r, repo), CanWrite: auth.CanPublish(p, repoView(repo))})
	}
	return cards
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	allowed := s.readableRepoNames(p)
	cards := s.repoCards(r, p)
	var total catalog.RepoStats
	for _, c := range cards {
		total.Packages += c.Stats.Packages
		total.Versions += c.Stats.Versions
		total.Size += c.Stats.Size
	}
	days := s.Usage.Days(14)
	var max int64
	for _, d := range days {
		if d.Downloads > max {
			max = d.Downloads
		}
	}
	s.render(w, r, "dashboard", "Tableau de bord", "home", map[string]any{
		"Repos": cards, "Total": total,
		"Day": s.Usage.Totals(1), "Week": s.Usage.Totals(7),
		"Days": days, "Max": max,
		"Top": s.Usage.Top("", 8, allowed),
		"Uploads": s.Usage.Recent(8, func(e usage.Event) bool {
			return allowed(e.Repo) && (e.Action == usage.ActionUpload || e.Action == usage.ActionPush) && e.Status < 400 && e.Name != ""
		}),
		"Recent": s.Usage.Recent(10, func(e usage.Event) bool {
			return allowed(e.Repo) && (e.Action == usage.ActionDownload || e.Action == usage.ActionPull)
		}),
	})
}

// --- dépôts --------------------------------------------------------------------------

func (s *Server) reposPage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	s.render(w, r, "repos", "Dépôts", "repos", map[string]any{"Repos": s.repoCards(r, p), "Types": repoTypes()})
}

type typeOpt struct{ Value, Label string }

func repoTypes() []typeOpt {
	var out []typeOpt
	for _, t := range []string{config.RepoRPM, config.RepoDeb, config.RepoDocker, config.RepoVaultaire, config.RepoGeneric} {
		out = append(out, typeOpt{t, typeLabel(t)})
	}
	return out
}

func (s *Server) reposCreate(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !auth.CanAdmin(p) {
		http.Error(w, "réservé aux administrateurs", http.StatusForbidden)
		return
	}
	f := r.PostForm
	keep := 0
	fmt.Sscanf(f.Get("keep_versions"), "%d", &keep)
	repo, err := s.Cat.CreateRepo(catalog.Repo{
		Name: strings.TrimSpace(f.Get("name")), Type: f.Get("type"), Description: strings.TrimSpace(f.Get("description")),
		Public: f.Get("public") == "on", KeepVersions: keep,
		Distribution: strings.TrimSpace(f.Get("distribution")), Component: strings.TrimSpace(f.Get("component")),
		Readers: cleanList([]string{f.Get("readers")}), Publishers: cleanList([]string{f.Get("publishers")}),
	}, p.Username)
	if err != nil {
		redirect(w, r, "/ui/repos", "err", err.Error())
		return
	}
	s.Log.Info("dépôt créé", "repo", repo.Name, "type", repo.Type, "par", p.Username)
	redirect(w, r, "/ui/repos/"+repo.Name, "ok", "Dépôt créé.")
}

func (s *Server) uiRepo(w http.ResponseWriter, r *http.Request, p *auth.Principal) (catalog.Repo, bool) {
	repo, err := s.Cat.Repo(r.PathValue("repo"))
	if err != nil || !auth.CanRead(p, repoView(repo)) {
		http.NotFound(w, r)
		return repo, false
	}
	return repo, true
}

type setupSnippet struct {
	Title string
	Code  string
}

func (s *Server) snippets(r *http.Request, repo catalog.Repo, p *auth.Principal) []setupSnippet {
	base := s.baseURL(r)
	host := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	user := p.Username
	switch repo.Type {
	case config.RepoRPM:
		out := []setupSnippet{{"Rocky / RHEL / Fedora", fmt.Sprintf("sudo curl -fsSo /etc/yum.repos.d/nexus-%s.repo %s/repo/rpm/%s/nexus.repo\nsudo dnf makecache", repo.Name, base, repo.Name)}}
		if !repo.Public {
			out[0].Code = fmt.Sprintf("sudo curl -fsS -u %s -o /etc/yum.repos.d/nexus-%s.repo %s/repo/rpm/%s/nexus.repo\n# renseignez username / password (jeton nxs_…) dans le fichier\nsudo dnf makecache", user, repo.Name, base, repo.Name)
		}
		out = append(out, setupSnippet{"Publier", fmt.Sprintf("curl -fsS -u %s:$NEXUS_TOKEN -T paquet.rpm %s/api/v1/repos/%s/upload", user, base, repo.Name)})
		return out
	case config.RepoDeb:
		settings := s.Mgr.DebSettings(repo)
		line := fmtSources(base, repo, settings.Distribution, settings.Component, s.Mgr.Signer != nil)
		code := ""
		if s.Mgr.Signer != nil {
			code = fmt.Sprintf("sudo install -d /etc/apt/keyrings\nsudo curl -fsSo /etc/apt/keyrings/vaultaire-nexus.asc %s/repo/keys/nexus.asc\n", base)
		}
		code += fmt.Sprintf("echo '%s' | sudo tee /etc/apt/sources.list.d/nexus-%s.list\n", line, repo.Name)
		if !repo.Public {
			code += fmt.Sprintf("printf 'machine %s login %s password <jeton nxs_…>\\n' | sudo tee /etc/apt/auth.conf.d/nexus.conf\nsudo chmod 600 /etc/apt/auth.conf.d/nexus.conf\n", host, user)
		}
		code += "sudo apt update"
		return []setupSnippet{{"Debian / Ubuntu", code},
			{"Publier", fmt.Sprintf("curl -fsS -u %s:$NEXUS_TOKEN -T paquet.deb %s/api/v1/repos/%s/upload", user, base, repo.Name)}}
	case config.RepoDocker:
		return []setupSnippet{
			{"Approuver le certificat (s'il est auto-signé)", fmt.Sprintf("sudo mkdir -p /etc/docker/certs.d/%s\nsudo curl -fsSk -o /etc/docker/certs.d/%s/ca.crt %s/repo/keys/nexus.crt", host, host, base)},
			{"Se connecter", fmt.Sprintf("docker login %s -u %s   # mot de passe ou jeton nxs_…", host, user)},
			{"Publier", fmt.Sprintf("docker tag mon-image:1.0 %s/%s/mon-image:1.0\ndocker push %s/%s/mon-image:1.0", host, repo.Name, host, repo.Name)},
			{"Récupérer", fmt.Sprintf("docker pull %s/%s/mon-image:1.0", host, repo.Name)},
		}
	case config.RepoVaultaire:
		return []setupSnippet{
			{"Mettre à jour la préprod depuis ce dépôt", fmt.Sprintf("VAULTAIRE_API_URL=%s/repo/vaultaire/%s/api \\\nVAULTAIRE_DL_URL=%s/repo/vaultaire/%s/download \\\n./deployments/pre-prod/docker-update.sh --list", base, repo.Name, base, repo.Name)},
			{"Récupérer une archive", fmt.Sprintf("curl -fsSLO %s/repo/vaultaire/%s/download/v2.1.0/vaultaire_client-v2.1.0-linux-amd64.tar.gz", base, repo.Name)},
			{"Publier", fmt.Sprintf("curl -fsS -u %s:$NEXUS_TOKEN -T vaultaire_client-v2.1.1-linux-amd64.tar.gz \\\n  %s/api/v1/repos/%s/upload/", user, base, repo.Name)},
		}
	}
	return []setupSnippet{
		{"Récupérer", fmt.Sprintf("curl -fsSLO %s/repo/files/%s/<nom>/latest/<fichier>", base, repo.Name)},
		{"Publier", fmt.Sprintf("curl -fsS -u %s:$NEXUS_TOKEN -T outil.tar.gz \\\n  '%s/api/v1/repos/%s/upload/outil.tar.gz?name=outil&version=1.0.0'", user, base, repo.Name)},
	}
}

func fmtSources(base string, repo catalog.Repo, dist, comp string, signed bool) string {
	opt := "[trusted=yes]"
	if signed {
		opt = "[signed-by=/etc/apt/keyrings/vaultaire-nexus.asc]"
	}
	return fmt.Sprintf("deb %s %s/repo/deb/%s %s %s", opt, base, repo.Name, dist, comp)
}

func (s *Server) repoPage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.uiRepo(w, r, p)
	if !ok {
		return
	}
	data := map[string]any{
		"Repo": repo, "Stats": s.Cat.Stats(repo.Name), "CanWrite": auth.CanPublish(p, repoView(repo)),
		"Snippets": s.snippets(r, repo, p), "URL": s.repoURL(r, repo),
		"Top": s.Usage.Top(repo.Name, 5, func(string) bool { return true }),
	}
	switch repo.Type {
	case config.RepoDocker:
		type imgRow struct {
			Image catalog.Image
			Tags  []string
			Pulls int64
		}
		var rows []imgRow
		for _, im := range s.Cat.Images(repo.Name) {
			row := imgRow{Image: im, Tags: im.TagList()}
			if c, ok := s.Usage.For(repo.Name, im.Name); ok {
				row.Pulls = c.Downloads
			}
			rows = append(rows, row)
		}
		data["Images"] = rows
	case config.RepoVaultaire:
		pkgs, _ := s.Cat.Packages(repo.Name, "")
		data["Releases"] = files.Releases(pkgs)
		fallthrough
	default:
		sums, _ := s.Cat.Summaries(repo.Name)
		type sumRow struct {
			catalog.PackageSummary
			Downloads int64
		}
		var rows []sumRow
		for _, sm := range sums {
			row := sumRow{PackageSummary: sm}
			if c, ok := s.Usage.For(repo.Name, sm.Name); ok {
				row.Downloads = c.Downloads
			}
			rows = append(rows, row)
		}
		data["Packages"] = rows
	}
	s.render(w, r, "repo", repo.Name, "repos", data)
}

func (s *Server) repoUpload(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.uiRepo(w, r, p)
	if !ok {
		return
	}
	back := "/ui/repos/" + repo.Name
	if !auth.CanPublish(p, repoView(repo)) {
		redirect(w, r, back, "err", "Droit de publication requis.")
		return
	}
	pk, removed, _, err := s.handleUpload(w, r, p, repo, true)
	if err != nil {
		redirect(w, r, back, "err", err.Error())
		return
	}
	msg := fmt.Sprintf("%s %s publié.", pk.Name, pk.Version)
	if len(removed) > 0 {
		msg += fmt.Sprintf(" Rétention : %d ancienne(s) version(s) retirée(s).", len(removed))
	}
	redirect(w, r, back, "ok", msg)
}

func (s *Server) repoSettings(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !auth.CanAdmin(p) {
		http.Error(w, "réservé aux administrateurs", http.StatusForbidden)
		return
	}
	f := r.PostForm
	desc := strings.TrimSpace(f.Get("description"))
	pub := f.Get("public") == "on"
	keep := 0
	fmt.Sscanf(f.Get("keep_versions"), "%d", &keep)
	in := repoInput{Description: &desc, Public: &pub, KeepVersions: &keep,
		Readers: []string{f.Get("readers")}, Publishers: []string{f.Get("publishers")}}
	repo, err := s.Cat.UpdateRepo(r.PathValue("repo"), func(rp *catalog.Repo) { applyRepoInput(rp, in) })
	if err != nil {
		redirect(w, r, "/ui/repos", "err", err.Error())
		return
	}
	s.Log.Info("dépôt modifié", "repo", repo.Name, "par", p.Username)
	redirect(w, r, "/ui/repos/"+repo.Name, "ok", "Réglages enregistrés.")
}

func (s *Server) repoDelete(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !auth.CanAdmin(p) {
		http.Error(w, "réservé aux administrateurs", http.StatusForbidden)
		return
	}
	name := r.PathValue("repo")
	if r.PostForm.Get("confirm") != name {
		redirect(w, r, "/ui/repos/"+name, "err", "Tapez le nom exact du dépôt pour confirmer.")
		return
	}
	if err := s.Cat.DeleteRepo(name); err != nil {
		redirect(w, r, "/ui/repos", "err", err.Error())
		return
	}
	_ = s.Mgr.RebuildIndex(name)
	s.Log.Warn("dépôt supprimé", "repo", name, "par", p.Username)
	redirect(w, r, "/ui/repos", "ok", "Dépôt "+name+" supprimé. Le ramasse-miettes libérera l'espace.")
}

func (s *Server) repoImport(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.uiRepo(w, r, p)
	if !ok {
		return
	}
	back := "/ui/repos/" + repo.Name
	if !auth.CanAdmin(p) || repo.Type != config.RepoVaultaire {
		redirect(w, r, back, "err", "Import réservé aux administrateurs, sur un dépôt de releases.")
		return
	}
	src := strings.TrimSpace(r.PostForm.Get("repository"))
	if src == "" {
		src = "Vaultaire-AD/vaultaire-core"
	}
	res, err := s.Importer.Import(r.Context(), repo.Name, src, strings.TrimSpace(r.PostForm.Get("tag")), p.Username)
	if err != nil {
		redirect(w, r, back, "err", "Import interrompu : "+err.Error())
		return
	}
	s.Log.Info("import GitHub", "repo", repo.Name, "source", src, "tag", res.Tag, "fichiers", len(res.Imported), "par", p.Username)
	redirect(w, r, back, "ok", fmt.Sprintf("%s : %d fichier(s) importé(s), %d ignoré(s).", res.Tag, len(res.Imported), len(res.Skipped)))
}

func (s *Server) repoReindex(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.uiRepo(w, r, p)
	if !ok {
		return
	}
	back := "/ui/repos/" + repo.Name
	if !auth.CanPublish(p, repoView(repo)) {
		redirect(w, r, back, "err", "Droit de publication requis.")
		return
	}
	if err := s.Mgr.RebuildIndex(repo.Name); err != nil {
		redirect(w, r, back, "err", err.Error())
		return
	}
	redirect(w, r, back, "ok", "Index régénéré.")
}

// --- paquets ------------------------------------------------------------------------

func (s *Server) packagePage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.uiRepo(w, r, p)
	if !ok {
		return
	}
	name := r.URL.Query().Get("name")
	pkgs, _ := s.Cat.Packages(repo.Name, name)
	if len(pkgs) == 0 {
		http.NotFound(w, r)
		return
	}
	type row struct {
		catalog.Package
		URL       string
		Downloads int64
	}
	counter, _ := s.Usage.For(repo.Name, name)
	var rows []row
	for _, pk := range pkgs {
		rows = append(rows, row{Package: pk, URL: s.packageURL(r, repo, pk), Downloads: counter.ByVersion[pk.Version]})
	}
	users := make([]string, 0, len(counter.Users))
	for u := range counter.Users {
		users = append(users, u)
	}
	sort.Strings(users)
	latest := pkgs[0]
	fields := []struct{ K, V string }{}
	keys := make([]string, 0, len(latest.Fields))
	for k, v := range latest.Fields {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields = append(fields, struct{ K, V string }{k, latest.Fields[k]})
	}
	s.render(w, r, "package", name, "repos", map[string]any{
		"Repo": repo, "Name": name, "Latest": latest, "Versions": rows, "Fields": fields,
		"Counter": counter, "Users": users, "CanWrite": auth.CanPublish(p, repoView(repo)),
		"Events": s.Usage.Recent(30, func(e usage.Event) bool { return e.Repo == repo.Name && e.Name == name }),
	})
}

func (s *Server) packageDelete(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.uiRepo(w, r, p)
	if !ok {
		return
	}
	name := r.PostForm.Get("name")
	back := "/ui/repos/" + repo.Name + "/package?name=" + url.QueryEscape(name)
	if !auth.CanPublish(p, repoView(repo)) {
		redirect(w, r, back, "err", "Droit de publication requis.")
		return
	}
	pk, err := s.Mgr.Delete(repo.Name, r.PostForm.Get("id"))
	if err != nil {
		redirect(w, r, back, "err", err.Error())
		return
	}
	s.Usage.Record(usage.Event{Action: usage.ActionDelete, Repo: repo.Name, RepoType: repo.Type, Name: pk.Name, Version: pk.Version,
		File: pk.Filename, User: p.Username, IP: s.clientIP(r), Status: http.StatusNoContent})
	s.Log.Info("version supprimée", "repo", repo.Name, "fichier", pk.Filename, "par", p.Username)
	if rest, _ := s.Cat.Packages(repo.Name, name); len(rest) == 0 {
		back = "/ui/repos/" + repo.Name
	}
	redirect(w, r, back, "ok", pk.Filename+" supprimé.")
}

// --- images ---------------------------------------------------------------------------

func (s *Server) imagePage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.uiRepo(w, r, p)
	if !ok {
		return
	}
	name := r.URL.Query().Get("name")
	im, err := s.Cat.Image(repo.Name, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	type manRow struct {
		catalog.Manifest
		Tags []string
	}
	byDigest := map[string][]string{}
	for t, d := range im.Tags {
		byDigest[d] = append(byDigest[d], t)
	}
	var rows []manRow
	for _, m := range im.Manifests {
		tags := byDigest[m.Digest]
		sort.Strings(tags)
		rows = append(rows, manRow{Manifest: m, Tags: tags})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].PushedAt.After(rows[j].PushedAt) })
	counter, _ := s.Usage.For(repo.Name, name)
	host := hostOf(s.baseURL(r))
	pullTag := ""
	if _, ok := im.Tags["latest"]; ok {
		pullTag = "latest"
	} else if tags := im.TagList(); len(tags) > 0 {
		pullTag = tags[len(tags)-1]
	}
	s.render(w, r, "image", name, "repos", map[string]any{
		"Repo": repo, "Image": im, "Manifests": rows, "Counter": counter, "PullTag": pullTag,
		"Pull": host + "/" + repo.Name + "/" + name, "CanWrite": auth.CanPublish(p, repoView(repo)),
		"Events": s.Usage.Recent(30, func(e usage.Event) bool { return e.Repo == repo.Name && e.Name == name }),
	})
}

func (s *Server) imageDelete(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	repo, ok := s.uiRepo(w, r, p)
	if !ok {
		return
	}
	name, ref := r.PostForm.Get("name"), r.PostForm.Get("ref")
	back := "/ui/repos/" + repo.Name + "/image?name=" + url.QueryEscape(name)
	if !auth.CanPublish(p, repoView(repo)) {
		redirect(w, r, back, "err", "Droit de publication requis.")
		return
	}
	if err := s.Cat.DeleteManifest(repo.Name, name, ref); err != nil {
		redirect(w, r, back, "err", err.Error())
		return
	}
	s.Usage.Record(usage.Event{Action: usage.ActionDelete, Repo: repo.Name, RepoType: repo.Type, Name: name, Version: ref,
		User: p.Username, IP: s.clientIP(r), Status: http.StatusAccepted})
	s.Log.Info("image supprimée", "repo", repo.Name, "image", name, "ref", ref, "par", p.Username)
	if _, err := s.Cat.Image(repo.Name, name); err != nil {
		back = "/ui/repos/" + repo.Name
	}
	redirect(w, r, back, "ok", ref+" supprimé.")
}

// --- recherche, usage, jetons ------------------------------------------------------------

func (s *Server) searchPage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	q := r.URL.Query().Get("q")
	hits := s.Cat.Search(q, func(repo catalog.Repo) bool { return auth.CanRead(p, repoView(repo)) })
	s.render(w, r, "search", "Recherche", "", map[string]any{"Q": q, "Hits": hits})
}

func (s *Server) usagePage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	allowed := s.readableRepoNames(p)
	repo := r.URL.Query().Get("repo")
	days := s.Usage.Days(30)
	var max int64
	for _, d := range days {
		if d.Downloads > max {
			max = d.Downloads
		}
	}
	data := map[string]any{
		"Days": days, "Max": max, "Totals": s.Usage.Totals(30), "RepoFilter": repo,
		"Repos": s.visibleRepos(p),
		"Top":   s.Usage.Top(repo, 30, allowed),
		"Recent": s.Usage.Recent(100, func(e usage.Event) bool {
			return allowed(e.Repo) && (repo == "" || e.Repo == repo)
		}),
	}
	if auth.CanAdmin(p) {
		data["Clients"] = s.Usage.Clients(50)
		data["Dropped"] = s.Usage.Dropped()
	}
	s.render(w, r, "usage", "Utilisation", "usage", data)
}

func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	all := auth.CanAdmin(p) && r.URL.Query().Get("all") == "1"
	owner := p.Username
	if all {
		owner = ""
	}
	s.render(w, r, "tokens", "Jetons d'accès", "tokens", map[string]any{"Tokens": s.Auth.Tokens.List(owner), "All": all})
}

func (s *Server) tokensCreate(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	f := r.PostForm
	days := 0
	fmt.Sscanf(f.Get("days"), "%d", &days)
	tk, raw, err := s.Auth.Tokens.Create(p, f.Get("label"), f.Get("scope"), time.Duration(days)*24*time.Hour)
	if err != nil {
		redirect(w, r, "/ui/tokens", "err", err.Error())
		return
	}
	s.Log.Info("jeton créé", "id", tk.ID, "titulaire", p.Username, "portée", tk.Scope)
	s.render(w, r, "tokens", "Jetons d'accès", "tokens", map[string]any{
		"Tokens": s.Auth.Tokens.List(p.Username), "New": raw, "NewInfo": tk,
	})
}

func (s *Server) tokensRevoke(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	owner := p.Username
	if auth.CanAdmin(p) {
		owner = ""
	}
	if err := s.Auth.Tokens.Revoke(r.PostForm.Get("id"), owner); err != nil {
		redirect(w, r, "/ui/tokens", "err", err.Error())
		return
	}
	s.Log.Info("jeton révoqué", "id", r.PostForm.Get("id"), "par", p.Username)
	redirect(w, r, "/ui/tokens", "ok", "Jeton révoqué.")
}

// --- administration ------------------------------------------------------------------------

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !auth.CanAdmin(p) {
		http.Error(w, "réservé aux administrateurs", http.StatusForbidden)
		return
	}
	count, size := s.Mgr.Blobs.Usage()
	var cl ClusterStatus
	if s.Cluster != nil {
		cl = s.Cluster()
	}
	s.render(w, r, "admin", "Administration", "admin", map[string]any{
		"Cfg": s.Cfg, "Blobs": count, "BlobSize": size, "Sessions": s.Auth.Sessions.Count(),
		"LocalEnabled": s.Auth.Local.Enabled(), "LocalFixed": s.Auth.Local.Fixed(), "IsLocal": p.Source == auth.SourceLocal,
		"Signed": s.Mgr.Signer != nil, "Cluster": cl, "Uptime": time.Since(s.started).Round(time.Second).String(),
		"Dropped": s.Usage.Dropped(),
	})
}

func (s *Server) adminPassword(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !auth.CanAdmin(p) || p.Source != auth.SourceLocal {
		http.Error(w, "réservé au compte local", http.StatusForbidden)
		return
	}
	f := r.PostForm
	if !s.Auth.Local.Check(p.Username, f.Get("current")) {
		redirect(w, r, "/ui/admin", "err", "Mot de passe actuel incorrect.")
		return
	}
	if f.Get("new") != f.Get("confirm") {
		redirect(w, r, "/ui/admin", "err", "Les deux saisies diffèrent.")
		return
	}
	if err := s.Auth.Local.SetPassword(f.Get("new")); err != nil {
		redirect(w, r, "/ui/admin", "err", err.Error())
		return
	}
	s.Log.Warn("mot de passe du compte local changé", "par", p.Username, "ip", s.clientIP(r))
	redirect(w, r, "/ui/admin", "ok", "Mot de passe changé.")
}

func (s *Server) adminGC(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if !auth.CanAdmin(p) {
		http.Error(w, "réservé aux administrateurs", http.StatusForbidden)
		return
	}
	dry := r.PostForm.Get("dry_run") == "on"
	st, err := s.Mgr.GC(dry)
	if err != nil {
		redirect(w, r, "/ui/admin", "err", err.Error())
		return
	}
	s.reg.CleanupUploads()
	verb := "supprimé(s)"
	if dry {
		verb = "à supprimer (simulation)"
	}
	s.Log.Info("ramasse-miettes", "supprimés", st.Removed, "octets", st.Freed, "simulation", dry, "par", p.Username)
	redirect(w, r, "/ui/admin", "ok", fmt.Sprintf("%d blob(s) %s, %s libérés, %d conservé(s).", st.Removed, verb, humanBytes(st.Freed), st.Kept))
}
