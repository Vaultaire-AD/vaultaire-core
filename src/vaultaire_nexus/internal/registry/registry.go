// Package registry implémente l'API de distribution Docker/OCI (v2), assez
// complète pour docker, podman, skopeo, crane et containerd :
//
//	GET    /v2/                                    découverte, authentification
//	HEAD   /v2/<nom>/blobs/<condensat>             existence d'une couche
//	GET    /v2/<nom>/blobs/<condensat>             téléchargement (Range accepté)
//	POST   /v2/<nom>/blobs/uploads/[?digest=|?mount=&from=]
//	PATCH  /v2/<nom>/blobs/uploads/<id>            envoi par morceaux
//	PUT    /v2/<nom>/blobs/uploads/<id>?digest=    fin d'envoi
//	GET    /v2/<nom>/blobs/uploads/<id>            reprise
//	DELETE /v2/<nom>/blobs/uploads/<id>            abandon
//	GET|HEAD /v2/<nom>/manifests/<tag|condensat>
//	PUT    /v2/<nom>/manifests/<tag|condensat>
//	DELETE /v2/<nom>/manifests/<tag|condensat>
//	GET    /v2/<nom>/tags/list[?n=&last=]
//	GET    /v2/_catalog[?n=&last=]
//
// # Correspondance des noms
//
// Le premier segment du nom est le DÉPÔT Nexus, le reste le nom de l'image :
//
//	nexus.acme.lan:8843/docker/vaultaire/core:2.1.0
//	                    ^^^^^^ ^^^^^^^^^^^^^^ ^^^^^
//	                    dépôt  image           tag
//
// Plusieurs dépôts Docker peuvent ainsi coexister avec des droits distincts.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vaultaire_nexus/internal/auth"
	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/store"
	"vaultaire_nexus/internal/usage"
)

// Deps est ce que le registre attend du reste du service.
type Deps struct {
	Cat      *catalog.Catalog
	Blobs    *store.Blobs
	Usage    *usage.Tracker
	Log      *slog.Logger
	Realm    string
	MaxBytes int64
	// Authenticate rend l'appelant (Anonymous si aucun en-tête) ; ok=false si
	// des identifiants ont été présentés et refusés.
	Authenticate func(r *http.Request) (p *auth.Principal, ok bool)
	ClientIP     func(r *http.Request) string
}

// Registry est le gestionnaire HTTP.
type Registry struct {
	d       Deps
	upDir   string
	uploads sync.Map // id -> *sync.Mutex

	pullMu   sync.Mutex
	lastPull map[string]time.Time // ip|user|image -> dernier pull compté
}

// New crée le registre.
func New(d Deps) (*Registry, error) {
	up := filepath.Join(d.Blobs.TmpDir(), "uploads")
	if err := os.MkdirAll(up, 0o750); err != nil {
		return nil, err
	}
	return &Registry{d: d, upDir: up, lastPull: map[string]time.Time{}}, nil
}

var (
	nameComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	tagRe         = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	uploadIDRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
)

// Codes d'erreur de la spécification.
const (
	codeBlobUnknown      = "BLOB_UNKNOWN"
	codeBlobUploadInv    = "BLOB_UPLOAD_INVALID"
	codeBlobUploadUnk    = "BLOB_UPLOAD_UNKNOWN"
	codeDigestInvalid    = "DIGEST_INVALID"
	codeManifestInvalid  = "MANIFEST_INVALID"
	codeManifestUnknown  = "MANIFEST_UNKNOWN"
	codeManifestBlobUnk  = "MANIFEST_BLOB_UNKNOWN"
	codeNameInvalid      = "NAME_INVALID"
	codeNameUnknown      = "NAME_UNKNOWN"
	codeSizeInvalid      = "SIZE_INVALID"
	codeUnauthorized     = "UNAUTHORIZED"
	codeDenied           = "DENIED"
	codeUnsupported      = "UNSUPPORTED"
	codeTagInvalid       = "TAG_INVALID"
	codeTooManyRequests  = "TOOMANYREQUESTS"
	mediaDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerList      = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex        = "application/vnd.oci.image.index.v1+json"
	maxManifestBytes     = 4 << 20
	headerAPIVersion     = "Docker-Distribution-API-Version"
	headerContentDigest  = "Docker-Content-Digest"
	headerUploadUUID     = "Docker-Upload-UUID"
	apiVersionValue      = "registry/2.0"
	errUnauthorizedTitle = "authentification requise"
)

func (g *Registry) fail(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, g.d.Realm))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": msg}},
	})
}

type target struct {
	repo  catalog.Repo
	image string
	full  string
}

// ServeHTTP route /v2/…
func (g *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerAPIVersion, apiVersionValue)
	p, ok := g.d.Authenticate(r)
	if !ok {
		g.fail(w, r, http.StatusUnauthorized, codeUnauthorized, "identifiants refusés")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v2/")
	if rest == "" || r.URL.Path == "/v2" {
		// docker login appelle /v2/ et attend 401 tant qu'il n'a rien présenté.
		if p.IsAnonymous() {
			g.fail(w, r, http.StatusUnauthorized, codeUnauthorized, errUnauthorizedTitle)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}
	if rest == "_catalog" {
		g.catalogList(w, r, p)
		return
	}

	// Le nom d'image peut lui-même contenir « blobs » ou « manifests » : c'est
	// l'occurrence la plus À DROITE qui sépare le nom de l'opération.
	var name, kind, ref string
	best := -1
	for _, k := range []string{"/blobs/uploads/", "/blobs/uploads", "/blobs/", "/manifests/", "/tags/list"} {
		i := strings.LastIndex(rest, k)
		if i <= 0 || i < best {
			continue
		}
		op := strings.Trim(k, "/")
		tail := rest[i+len(k):]
		if k == "/blobs/uploads" && tail != "" || k == "/tags/list" && tail != "" {
			continue
		}
		if i == best && len(op) < len(kind) {
			continue
		}
		best, name, kind, ref = i, rest[:i], op, tail
	}
	if kind == "blobs" && strings.Contains(ref, "/") {
		name = ""
	}
	if name == "" {
		g.fail(w, r, http.StatusNotFound, codeUnsupported, "chemin inconnu")
		return
	}
	t, status, code, msg := g.resolve(name)
	if status != 0 {
		g.fail(w, r, status, code, msg)
		return
	}
	view := auth.RepoView{Public: t.repo.Public, Readers: t.repo.Readers, Publishers: t.repo.Publishers}
	write := r.Method != http.MethodGet && r.Method != http.MethodHead
	if write && !auth.CanPublish(p, view) || !write && !auth.CanRead(p, view) {
		if p.IsAnonymous() {
			g.fail(w, r, http.StatusUnauthorized, codeUnauthorized, errUnauthorizedTitle)
		} else {
			g.fail(w, r, http.StatusForbidden, codeDenied, "accès refusé à "+t.full)
		}
		return
	}

	switch kind {
	case "blobs/uploads":
		g.uploads_(w, r, p, t, ref)
	case "blobs":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			g.getBlob(w, r, p, t, ref)
		case http.MethodDelete:
			// Les couches sont partagées : la suppression passe par les
			// manifestes et le ramasse-miettes.
			g.fail(w, r, http.StatusMethodNotAllowed, codeUnsupported, "supprimez le manifeste, le ramasse-miettes récupère les couches")
		default:
			g.fail(w, r, http.StatusMethodNotAllowed, codeUnsupported, "méthode non prise en charge")
		}
	case "manifests":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			g.getManifest(w, r, p, t, ref)
		case http.MethodPut:
			g.putManifest(w, r, p, t, ref)
		case http.MethodDelete:
			g.deleteManifest(w, r, p, t, ref)
		default:
			g.fail(w, r, http.StatusMethodNotAllowed, codeUnsupported, "méthode non prise en charge")
		}
	case "tags/list":
		if r.Method != http.MethodGet {
			g.fail(w, r, http.StatusMethodNotAllowed, codeUnsupported, "méthode non prise en charge")
			return
		}
		g.tags(w, r, t)
	}
}

func (g *Registry) resolve(name string) (target, int, string, string) {
	parts := strings.Split(name, "/")
	if len(parts) < 2 {
		return target{}, http.StatusNotFound, codeNameInvalid, "le nom doit être <dépôt>/<image>"
	}
	for _, c := range parts {
		if !nameComponent.MatchString(c) {
			return target{}, http.StatusBadRequest, codeNameInvalid, "nom invalide : " + name
		}
	}
	if len(name) > 255 {
		return target{}, http.StatusBadRequest, codeNameInvalid, "nom trop long"
	}
	repo, err := g.d.Cat.Repo(parts[0])
	if err != nil || repo.Type != config.RepoDocker {
		return target{}, http.StatusNotFound, codeNameUnknown, "aucun dépôt Docker « " + parts[0] + " »"
	}
	return target{repo: repo, image: strings.Join(parts[1:], "/"), full: name}, 0, "", ""
}

func (g *Registry) track(r *http.Request, p *auth.Principal, t target, action, version string, bytes int64, status int, start time.Time) {
	g.d.Usage.Record(usage.Event{
		Action: action, Repo: t.repo.Name, RepoType: config.RepoDocker, Name: t.image, Version: version,
		User: p.Username, IP: g.d.ClientIP(r), Agent: r.UserAgent(), Bytes: bytes, Status: status,
		Millis: time.Since(start).Milliseconds(),
	})
}

// --- blobs -----------------------------------------------------------------

func (g *Registry) getBlob(w http.ResponseWriter, r *http.Request, p *auth.Principal, t target, digest string) {
	if !store.ValidDigest(digest) {
		g.fail(w, r, http.StatusBadRequest, codeDigestInvalid, "condensat invalide")
		return
	}
	// Un blob n'est servi que s'il appartient à une image de CE dépôt, ou s'il
	// vient d'être poussé dedans (couches envoyées avant leur manifeste).
	// Sans ce contrôle, un droit de lecture sur un dépôt public ouvrirait
	// toutes les couches du stockage, dépôts privés compris.
	if !g.d.Cat.ImageBlobKnown(t.repo.Name, t.image, digest) && !g.recentlyPushed(t, digest) {
		g.fail(w, r, http.StatusNotFound, codeBlobUnknown, "couche inconnue")
		return
	}
	f, size, err := g.d.Blobs.Open(digest)
	if err != nil {
		g.fail(w, r, http.StatusNotFound, codeBlobUnknown, "couche inconnue")
		return
	}
	defer f.Close()
	w.Header().Set(headerContentDigest, digest)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set("Cache-Control", "max-age=31536000")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}
	// Les couches ne sont pas tracées une à une : le suivi compte les pulls
	// (lectures de manifeste par tag), qui disent qui récupère quelle image.
	http.ServeContent(w, r, "", time.Time{}, f)
}

// Un blob poussé mais pas encore référencé par un manifeste doit rester
// lisible le temps de l'envoi du manifeste (docker vérifie par HEAD).
func (g *Registry) recentlyPushed(t target, digest string) bool {
	_, err := os.Stat(g.pushMarker(t, digest))
	return err == nil
}

func (g *Registry) pushMarker(t target, digest string) string {
	safe := strings.NewReplacer("/", "_", ":", "_").Replace(t.full)
	return filepath.Join(g.upDir, "pushed", safe, strings.TrimPrefix(digest, "sha256:"))
}

func (g *Registry) markPushed(t target, digest string) {
	p := g.pushMarker(t, digest)
	_ = os.MkdirAll(filepath.Dir(p), 0o750)
	_ = os.WriteFile(p, nil, 0o640)
}

// --- envois ------------------------------------------------------------------

type uploadState struct {
	Repo    string    `json:"repo"`
	Image   string    `json:"image"`
	User    string    `json:"user"`
	Started time.Time `json:"started"`
}

func (g *Registry) uploadLock(id string) *sync.Mutex {
	v, _ := g.uploads.LoadOrStore(id, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (g *Registry) uploads_(w http.ResponseWriter, r *http.Request, p *auth.Principal, t target, id string) {
	if id == "" {
		if r.Method != http.MethodPost {
			g.fail(w, r, http.StatusMethodNotAllowed, codeUnsupported, "méthode non prise en charge")
			return
		}
		g.startUpload(w, r, p, t)
		return
	}
	if !uploadIDRe.MatchString(id) {
		g.fail(w, r, http.StatusNotFound, codeBlobUploadUnk, "envoi inconnu")
		return
	}
	lk := g.uploadLock(id)
	lk.Lock()
	defer lk.Unlock()
	st, ok := g.loadUpload(id)
	if !ok || st.Repo != t.repo.Name || st.Image != t.image || st.User != p.Username {
		g.fail(w, r, http.StatusNotFound, codeBlobUploadUnk, "envoi inconnu")
		return
	}
	switch r.Method {
	case http.MethodGet:
		g.uploadStatus(w, t, id, http.StatusNoContent)
	case http.MethodPatch:
		if _, err := g.appendUpload(w, r, id); err != nil {
			g.fail(w, r, http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInv, err.Error())
			return
		}
		g.uploadStatus(w, t, id, http.StatusAccepted)
	case http.MethodPut:
		g.finishUpload(w, r, p, t, id)
	case http.MethodDelete:
		g.dropUpload(id)
		w.WriteHeader(http.StatusNoContent)
	default:
		g.fail(w, r, http.StatusMethodNotAllowed, codeUnsupported, "méthode non prise en charge")
	}
}

func (g *Registry) dataPath(id string) string  { return filepath.Join(g.upDir, id+".data") }
func (g *Registry) statePath(id string) string { return filepath.Join(g.upDir, id+".json") }

func (g *Registry) loadUpload(id string) (uploadState, bool) {
	var st uploadState
	found, err := store.LoadJSON(g.statePath(id), &st)
	return st, found && err == nil
}

func (g *Registry) dropUpload(id string) {
	os.Remove(g.dataPath(id))
	os.Remove(g.statePath(id))
	g.uploads.Delete(id)
}

func (g *Registry) startUpload(w http.ResponseWriter, r *http.Request, p *auth.Principal, t target) {
	q := r.URL.Query()
	// Montage depuis une autre image : aucun octet ne voyage si l'appelant
	// peut lire la source.
	if mount := q.Get("mount"); mount != "" && store.ValidDigest(mount) {
		if from := q.Get("from"); from != "" {
			if src, status, _, _ := g.resolve(from); status == 0 {
				view := auth.RepoView{Public: src.repo.Public, Readers: src.repo.Readers, Publishers: src.repo.Publishers}
				if auth.CanRead(p, view) && g.d.Cat.ImageBlobKnown(src.repo.Name, src.image, mount) {
					if _, err := g.d.Blobs.Stat(mount); err == nil {
						g.markPushed(t, mount)
						w.Header().Set("Location", "/v2/"+t.full+"/blobs/"+mount)
						w.Header().Set(headerContentDigest, mount)
						w.WriteHeader(http.StatusCreated)
						return
					}
				}
			}
		}
		// Montage impossible : la spécification demande de retomber sur un envoi normal.
	}
	id := auth.RandomSecret(24)
	st := uploadState{Repo: t.repo.Name, Image: t.image, User: p.Username, Started: time.Now().UTC()}
	if err := store.SaveJSON(g.statePath(id), st); err != nil {
		g.fail(w, r, http.StatusInternalServerError, codeBlobUploadInv, "impossible de créer l'envoi")
		return
	}
	f, err := os.OpenFile(g.dataPath(id), os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		g.fail(w, r, http.StatusInternalServerError, codeBlobUploadInv, "impossible de créer l'envoi")
		return
	}
	f.Close()

	// Envoi monolithique : POST ?digest= avec le corps.
	if d := q.Get("digest"); d != "" {
		lk := g.uploadLock(id)
		lk.Lock()
		defer lk.Unlock()
		if _, err := g.appendUpload(w, r, id); err != nil {
			g.dropUpload(id)
			g.fail(w, r, http.StatusBadRequest, codeBlobUploadInv, err.Error())
			return
		}
		g.commit(w, r, p, t, id, d)
		return
	}
	g.uploadStatus(w, t, id, http.StatusAccepted)
}

func (g *Registry) uploadStatus(w http.ResponseWriter, t target, id string, status int) {
	var size int64
	if st, err := os.Stat(g.dataPath(id)); err == nil {
		size = st.Size()
	}
	w.Header().Set("Location", "/v2/"+t.full+"/blobs/uploads/"+id)
	w.Header().Set(headerUploadUUID, id)
	end := size - 1
	if end < 0 {
		end = 0
	}
	w.Header().Set("Range", fmt.Sprintf("0-%d", end))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

// appendUpload ajoute le corps à l'envoi, en vérifiant Content-Range s'il est fourni.
func (g *Registry) appendUpload(w http.ResponseWriter, r *http.Request, id string) (int64, error) {
	f, err := os.OpenFile(g.dataPath(id), os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if cr := r.Header.Get("Content-Range"); cr != "" {
		var from, to int64
		if _, err := fmt.Sscanf(strings.TrimPrefix(cr, "bytes "), "%d-%d", &from, &to); err != nil || from != st.Size() {
			return 0, fmt.Errorf("Content-Range %q ne suit pas les %d octets reçus", cr, st.Size())
		}
	}
	remaining := g.d.MaxBytes - st.Size()
	n, err := io.Copy(f, io.LimitReader(r.Body, remaining+1))
	if err != nil {
		return n, err
	}
	if n > remaining {
		return n, fmt.Errorf("couche trop volumineuse (limite %d Mo)", g.d.MaxBytes>>20)
	}
	return n, nil
}

func (g *Registry) finishUpload(w http.ResponseWriter, r *http.Request, p *auth.Principal, t target, id string) {
	d := r.URL.Query().Get("digest")
	if !store.ValidDigest(d) {
		g.fail(w, r, http.StatusBadRequest, codeDigestInvalid, "paramètre digest manquant ou invalide")
		return
	}
	if _, err := g.appendUpload(w, r, id); err != nil {
		g.fail(w, r, http.StatusBadRequest, codeBlobUploadInv, err.Error())
		return
	}
	g.commit(w, r, p, t, id, d)
}

func (g *Registry) commit(w http.ResponseWriter, r *http.Request, p *auth.Principal, t target, id, digest string) {
	start := time.Now()
	res, err := g.d.Blobs.Adopt(g.dataPath(id), digest)
	os.Remove(g.statePath(id))
	g.uploads.Delete(id)
	if err != nil {
		os.Remove(g.dataPath(id))
		g.fail(w, r, http.StatusBadRequest, codeDigestInvalid, err.Error())
		return
	}
	g.markPushed(t, res.Digest)
	g.track(r, p, t, usage.ActionUpload, "", res.Size, http.StatusCreated, start)
	w.Header().Set("Location", "/v2/"+t.full+"/blobs/"+res.Digest)
	w.Header().Set(headerContentDigest, res.Digest)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// --- manifestes ----------------------------------------------------------------

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}

type manifestDoc struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        *descriptor  `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`
	Subject       *descriptor  `json:"subject"`
}

func (g *Registry) putManifest(w http.ResponseWriter, r *http.Request, p *auth.Principal, t target, ref string) {
	start := time.Now()
	isDigest := strings.HasPrefix(ref, "sha256:")
	if isDigest && !store.ValidDigest(ref) {
		g.fail(w, r, http.StatusBadRequest, codeDigestInvalid, "condensat invalide")
		return
	}
	if !isDigest && !tagRe.MatchString(ref) {
		g.fail(w, r, http.StatusBadRequest, codeTagInvalid, "tag invalide")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxManifestBytes+1))
	if err != nil || len(body) > maxManifestBytes {
		g.fail(w, r, http.StatusBadRequest, codeManifestInvalid, "manifeste illisible ou trop gros")
		return
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil || doc.SchemaVersion != 2 {
		g.fail(w, r, http.StatusBadRequest, codeManifestInvalid, "manifeste invalide (schemaVersion 2 attendu)")
		return
	}
	mt := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if mt == "" {
		mt = doc.MediaType
	}
	if mt == "" {
		if len(doc.Manifests) > 0 {
			mt = mediaOCIIndex
		} else {
			mt = mediaOCIManifest
		}
	}
	var refs []string
	platform := ""
	switch mt {
	case mediaDockerManifest, mediaOCIManifest:
		if doc.Config == nil {
			g.fail(w, r, http.StatusBadRequest, codeManifestInvalid, "config absente")
			return
		}
		all := append([]descriptor{*doc.Config}, doc.Layers...)
		for _, d := range all {
			if !store.ValidDigest(d.Digest) {
				g.fail(w, r, http.StatusBadRequest, codeManifestInvalid, "condensat de couche invalide")
				return
			}
			// Couches « foreign » (images Windows) : non servies ici, non exigées.
			if strings.Contains(d.MediaType, "foreign") || strings.Contains(d.MediaType, "nondistributable") {
				continue
			}
			size, err := g.d.Blobs.Stat(d.Digest)
			if err != nil || !(g.d.Cat.ImageBlobKnown(t.repo.Name, t.image, d.Digest) || g.recentlyPushed(t, d.Digest)) {
				g.fail(w, r, http.StatusBadRequest, codeManifestBlobUnk, "couche absente : "+d.Digest)
				return
			}
			if d.Size != 0 && size != d.Size {
				g.fail(w, r, http.StatusBadRequest, codeSizeInvalid, "taille incohérente pour "+d.Digest)
				return
			}
			refs = append(refs, d.Digest)
		}
	case mediaDockerList, mediaOCIIndex:
		var plats []string
		for _, d := range doc.Manifests {
			if !g.d.Cat.HasManifest(t.repo.Name, t.image, d.Digest) {
				g.fail(w, r, http.StatusBadRequest, codeManifestBlobUnk, "manifeste référencé absent : "+d.Digest)
				return
			}
			refs = append(refs, d.Digest)
			if d.Platform != nil {
				plats = append(plats, d.Platform.OS+"/"+d.Platform.Architecture)
			}
		}
		sort.Strings(plats)
		platform = strings.Join(plats, ", ")
	default:
		// Artefacts OCI (signatures, SBOM) : acceptés tels quels.
		if doc.Config != nil {
			refs = append(refs, doc.Config.Digest)
		}
		for _, d := range doc.Layers {
			refs = append(refs, d.Digest)
		}
	}
	res, err := g.d.Blobs.Put(strings.NewReader(string(body)), "", maxManifestBytes)
	if err != nil {
		g.fail(w, r, http.StatusInternalServerError, codeManifestInvalid, "écriture impossible")
		return
	}
	if isDigest && ref != res.Digest {
		g.fail(w, r, http.StatusBadRequest, codeDigestInvalid, "le condensat ne correspond pas au contenu")
		return
	}
	tag := ""
	if !isDigest {
		tag = ref
	}
	if platform == "" && doc.Config != nil && (mt == mediaDockerManifest || mt == mediaOCIManifest) {
		platform = g.platformOf(doc.Config.Digest)
	}
	err = g.d.Cat.PutManifest(t.repo.Name, t.image, tag, catalog.Manifest{
		Digest: res.Digest, MediaType: mt, Size: res.Size, Refs: refs, Platform: platform, PushedBy: p.Username,
	})
	if err != nil {
		g.fail(w, r, http.StatusInternalServerError, codeManifestInvalid, err.Error())
		return
	}
	g.track(r, p, t, usage.ActionPush, firstNonEmpty(tag, res.Digest), res.Size, http.StatusCreated, start)
	g.d.Log.Info("registry: push", "image", t.full, "ref", ref, "user", p.Username)
	w.Header().Set("Location", "/v2/"+t.full+"/manifests/"+res.Digest)
	w.Header().Set(headerContentDigest, res.Digest)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

func (g *Registry) firstPull(r *http.Request, p *auth.Principal, image string) bool {
	key := g.d.ClientIP(r) + "|" + p.Username + "|" + image
	now := time.Now()
	g.pullMu.Lock()
	defer g.pullMu.Unlock()
	if last, ok := g.lastPull[key]; ok && now.Sub(last) < time.Minute {
		return false
	}
	g.lastPull[key] = now
	if len(g.lastPull) > 10000 {
		for k, v := range g.lastPull {
			if now.Sub(v) >= time.Minute {
				delete(g.lastPull, k)
			}
		}
	}
	return true
}

// tagFor rend un tag lisible pour un pull fait par condensat.
func (g *Registry) tagFor(t target, ref string) string {
	if !strings.HasPrefix(ref, "sha256:") {
		return ref
	}
	if img, err := g.d.Cat.Image(t.repo.Name, t.image); err == nil {
		best := ""
		for tag, dg := range img.Tags {
			if dg == ref && (best == "" || tag < best) {
				best = tag
			}
		}
		if best != "" {
			return best
		}
	}
	return ref
}

// platformOf lit os/architecture dans la configuration d'une image.
func (g *Registry) platformOf(digest string) string {
	b, err := g.d.Blobs.ReadAll(digest)
	if err != nil {
		return ""
	}
	var c struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}
	if json.Unmarshal(b, &c) != nil || c.OS == "" {
		return ""
	}
	return c.OS + "/" + c.Architecture
}

func (g *Registry) getManifest(w http.ResponseWriter, r *http.Request, p *auth.Principal, t target, ref string) {
	start := time.Now()
	m, err := g.d.Cat.ResolveManifest(t.repo.Name, t.image, ref)
	if err != nil {
		g.fail(w, r, http.StatusNotFound, codeManifestUnknown, "manifeste inconnu : "+ref)
		return
	}
	body, err := g.d.Blobs.ReadAll(m.Digest)
	if err != nil {
		g.fail(w, r, http.StatusNotFound, codeManifestUnknown, "manifeste illisible")
		return
	}
	w.Header().Set("Content-Type", m.MediaType)
	w.Header().Set(headerContentDigest, m.Digest)
	w.Header().Set("ETag", `"`+m.Digest+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(body)
		// Un pull = la première lecture de manifeste d'un client pour une image.
		// Docker fait HEAD sur le tag puis GET par condensat, et relit ensuite
		// chaque plateforme d'un index : on ne compte qu'une fois par minute.
		if g.firstPull(r, p, t.full) {
			g.track(r, p, t, usage.ActionPull, g.tagFor(t, ref), int64(len(body)), http.StatusOK, start)
		}
	}
}

func (g *Registry) deleteManifest(w http.ResponseWriter, r *http.Request, p *auth.Principal, t target, ref string) {
	start := time.Now()
	if err := g.d.Cat.DeleteManifest(t.repo.Name, t.image, ref); err != nil {
		g.fail(w, r, http.StatusNotFound, codeManifestUnknown, "manifeste inconnu : "+ref)
		return
	}
	g.track(r, p, t, usage.ActionDelete, ref, 0, http.StatusAccepted, start)
	g.d.Log.Info("registry: suppression", "image", t.full, "ref", ref, "user", p.Username)
	w.WriteHeader(http.StatusAccepted)
}

// --- listes --------------------------------------------------------------------

func paginate(all []string, r *http.Request) ([]string, string) {
	sort.Strings(all)
	q := r.URL.Query()
	if last := q.Get("last"); last != "" {
		i := sort.SearchStrings(all, last)
		if i < len(all) && all[i] == last {
			i++
		}
		all = all[i:]
	}
	n, _ := strconv.Atoi(q.Get("n"))
	if n <= 0 || n > 1000 {
		n = 1000
	}
	if len(all) > n {
		return all[:n], all[n-1]
	}
	return all, ""
}

func (g *Registry) tags(w http.ResponseWriter, r *http.Request, t target) {
	im, err := g.d.Cat.Image(t.repo.Name, t.image)
	if err != nil {
		g.fail(w, r, http.StatusNotFound, codeNameUnknown, "image inconnue")
		return
	}
	page, last := paginate(im.TagList(), r)
	if last != "" {
		w.Header().Set("Link", fmt.Sprintf(`</v2/%s/tags/list?n=%d&last=%s>; rel="next"`, t.full, len(page), last))
	}
	writeJSON(w, map[string]any{"name": t.full, "tags": nonNil(page)})
}

func (g *Registry) catalogList(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	var names []string
	for _, repo := range g.d.Cat.Repos() {
		if repo.Type != config.RepoDocker {
			continue
		}
		if !auth.CanRead(p, auth.RepoView{Public: repo.Public, Readers: repo.Readers, Publishers: repo.Publishers}) {
			continue
		}
		for _, im := range g.d.Cat.Images(repo.Name) {
			names = append(names, repo.Name+"/"+im.Name)
		}
	}
	page, last := paginate(names, r)
	if last != "" {
		w.Header().Set("Link", fmt.Sprintf(`</v2/_catalog?n=%d&last=%s>; rel="next"`, len(page), last))
	}
	writeJSON(w, map[string]any{"repositories": nonNil(page)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// ErrDisabled est rendu quand aucun dépôt Docker n'existe.
var ErrDisabled = errors.New("aucun dépôt Docker")

// CleanupUploads supprime les envois abandonnés depuis plus de 24 h.
func (g *Registry) CleanupUploads() int {
	n := 0
	entries, _ := os.ReadDir(g.upDir)
	cut := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || info.ModTime().After(cut) {
			continue
		}
		if e.IsDir() {
			// marqueurs « pushed » : on purge les fichiers anciens
			filepath.Walk(filepath.Join(g.upDir, e.Name()), func(p string, fi os.FileInfo, err error) error {
				if err == nil && !fi.IsDir() && fi.ModTime().Before(cut) {
					os.Remove(p)
				}
				return nil
			})
			continue
		}
		os.Remove(filepath.Join(g.upDir, e.Name()))
		n++
	}
	return n
}
