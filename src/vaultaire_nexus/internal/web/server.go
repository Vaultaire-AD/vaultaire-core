// Package web expose Nexus en HTTP : l'interface, l'API JSON, les dépôts
// (rpm, deb, fichiers, releases) et le registre Docker, sur un seul port.
package web

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"vaultaire_nexus/internal/auth"
	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/files"
	"vaultaire_nexus/internal/registry"
	"vaultaire_nexus/internal/repos"
	"vaultaire_nexus/internal/usage"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Server est le serveur HTTP.
type Server struct {
	Cfg      *config.Config
	Auth     *auth.Service
	Cat      *catalog.Catalog
	Mgr      *repos.Manager
	Usage    *usage.Tracker
	Log      *slog.Logger
	Importer *files.Importer
	Cluster  func() ClusterStatus // état du raccordement Ducky, pour l'interface

	reg      *registry.Registry
	tmpl     map[string]*template.Template
	trusted  []*net.IPNet
	started  time.Time
	baseHint string
	mfa      mfaPending
}

// ClusterStatus est affiché dans l'administration.
type ClusterStatus struct {
	Enabled bool
	State   string
	Detail  string
}

type ctxKey int

const (
	keyPrincipal ctxKey = iota
	keySession
)

const sessionCookie = "nexus_session"

// New prépare le serveur.
func New(s *Server) (*Server, error) {
	s.started = time.Now()
	for _, c := range s.Cfg.Proxy.CIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		s.trusted = append(s.trusted, n)
	}
	reg, err := registry.New(registry.Deps{
		Cat: s.Cat, Blobs: s.Mgr.Blobs, Usage: s.Usage, Log: s.Log,
		Realm: "Vaultaire Nexus", MaxBytes: s.Cfg.MaxUploadBytes(),
		Authenticate: s.authenticateRequest, ClientIP: s.clientIP,
	})
	if err != nil {
		return nil, err
	}
	s.reg = reg
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

// Handler rend le routeur complet.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Registre Docker : routage propre, les noms d'images contiennent des « / ».
	mux.Handle("/v2/", s.reg)
	mux.Handle("/v2", s.reg)

	// Dépôts
	mux.HandleFunc("GET /repo/rpm/{repo}/{path...}", s.serveRPM)
	mux.HandleFunc("HEAD /repo/rpm/{repo}/{path...}", s.serveRPM)
	mux.HandleFunc("GET /repo/deb/{repo}/{path...}", s.serveDeb)
	mux.HandleFunc("HEAD /repo/deb/{repo}/{path...}", s.serveDeb)
	mux.HandleFunc("GET /repo/files/{repo}/{name}/{version}/{file}", s.serveFile)
	mux.HandleFunc("HEAD /repo/files/{repo}/{name}/{version}/{file}", s.serveFile)
	mux.HandleFunc("GET /repo/vaultaire/{repo}/api/releases", s.releasesList)
	mux.HandleFunc("GET /repo/vaultaire/{repo}/api/releases/latest", s.releaseLatest)
	mux.HandleFunc("GET /repo/vaultaire/{repo}/api/releases/tags/{tag}", s.releaseByTag)
	mux.HandleFunc("GET /repo/vaultaire/{repo}/download/{tag}/{file}", s.releaseAsset)
	mux.HandleFunc("HEAD /repo/vaultaire/{repo}/download/{tag}/{file}", s.releaseAsset)
	mux.HandleFunc("GET /repo/keys/nexus.asc", s.servePublicKey)
	mux.HandleFunc("GET /repo/keys/nexus.crt", s.serveCertificate)

	// API
	s.routesAPI(mux)

	// Interface
	s.routesUI(mux)
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})

	return s.recoverer(s.securityHeaders(s.logRequests(mux)))
}

// --- intergiciels ---------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// ReadFrom garde le chemin rapide de sendfile pour les gros fichiers.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		lvl := slog.LevelDebug
		if sw.status >= 500 {
			lvl = slog.LevelError
		} else if sw.status == 401 || sw.status == 403 {
			lvl = slog.LevelInfo
		}
		s.Log.Log(r.Context(), lvl, "http", "méthode", r.Method, "chemin", r.URL.Path, "statut", sw.status,
			"octets", sw.bytes, "ip", s.clientIP(r), "durée_ms", time.Since(start).Milliseconds())
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if !strings.HasPrefix(r.URL.Path, "/v2") && !strings.HasPrefix(r.URL.Path, "/repo/") {
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'")
		}
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Log.Error("panique", "valeur", v, "pile", string(debug.Stack()))
				http.Error(w, "erreur interne", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

// clientIP rend l'adresse du client, X-Forwarded-For compris si la connexion
// vient d'un mandataire déclaré — jamais sinon, l'en-tête se forge.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || len(s.trusted) == 0 {
		return host
	}
	trusted := false
	for _, n := range s.trusted {
		if n.Contains(ip) {
			trusted = true
			break
		}
	}
	if !trusted {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	cand := strings.TrimSpace(parts[len(parts)-1])
	if net.ParseIP(cand) != nil {
		return cand
	}
	return host
}

// baseURL rend l'URL publique du service.
func (s *Server) baseURL(r *http.Request) string {
	if s.Cfg.PublicURL != "" {
		return strings.TrimRight(s.Cfg.PublicURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// --- authentification des requêtes -------------------------------------------

// authenticateRequest reconnaît, dans l'ordre : session web, Bearer, Basic.
// ok=false : des identifiants ont été présentés et sont faux.
func (s *Server) authenticateRequest(r *http.Request) (*auth.Principal, bool) {
	ip := s.clientIP(r)
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, cred, _ := strings.Cut(h, " ")
		switch strings.ToLower(scheme) {
		case "bearer":
			p, ok := s.Auth.FromToken(strings.TrimSpace(cred), ip)
			return p, ok
		case "basic":
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
			if err != nil {
				return nil, false
			}
			u, pw, found := strings.Cut(string(raw), ":")
			if !found {
				return nil, false
			}
			p, err := s.Auth.Basic(u, pw, ip)
			if err != nil {
				if errors.Is(err, auth.ErrUnavailable) {
					s.Log.Error("auth: annuaire injoignable", "err", err)
				}
				return nil, false
			}
			return p, true
		default:
			return nil, false
		}
	}
	if sess, ok := s.session(r); ok {
		return sess.Principal, true
	}
	return auth.Anonymous, true
}

func (s *Server) session(r *http.Request) (*auth.Session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, false
	}
	return s.Auth.Sessions.Get(c.Value)
}

func withPrincipal(ctx context.Context, p *auth.Principal) context.Context {
	return context.WithValue(ctx, keyPrincipal, p)
}

func principalFrom(r *http.Request) *auth.Principal {
	if p, ok := r.Context().Value(keyPrincipal).(*auth.Principal); ok && p != nil {
		return p
	}
	return auth.Anonymous
}

func repoView(r catalog.Repo) auth.RepoView {
	return auth.RepoView{Public: r.Public, Readers: r.Readers, Publishers: r.Publishers}
}

// challenge répond 401 avec une invitation Basic (dnf, apt, curl la suivent).
func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Vaultaire Nexus", charset="UTF-8"`)
	http.Error(w, "authentification requise", http.StatusUnauthorized)
}
