package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vaultaire_nexus/internal/auth"
	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/store"
	"vaultaire_nexus/internal/usage"
)

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// testServer : un dépôt docker « images », un éditeur, un lecteur.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	blobs, err := store.OpenBlobs(dir)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cat.EnsureRepo(config.RepoConfig{Name: "images", Type: config.RepoDocker}); err != nil {
		t.Fatal(err)
	}
	tr, err := usage.Open(dir, 1, false, log)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]*auth.Principal{
		"editeur": {Username: "editeur", Role: config.RolePublisher},
		"lecteur": {Username: "lecteur", Role: config.RoleReader},
	}
	g, err := New(Deps{
		Cat: cat, Blobs: blobs, Usage: tr, Log: log, Realm: "test", MaxBytes: 1 << 20,
		Authenticate: func(r *http.Request) (*auth.Principal, bool) {
			u, _, ok := r.BasicAuth()
			if !ok {
				return auth.Anonymous, true
			}
			p, ok := users[u]
			return p, ok
		},
		ClientIP: func(*http.Request) string { return "127.0.0.1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, method, url, user string, body []byte, hdr ...string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	if user != "" {
		req.SetBasicAuth(user, "x")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func want(t *testing.T, what string, resp *http.Response, code int) {
	t.Helper()
	if resp.StatusCode != code {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s : statut %d, attendu %d — %s", what, resp.StatusCode, code, b)
	}
}

func pushBlob(t *testing.T, base string, data []byte, chunked bool) string {
	t.Helper()
	d := digest(data)
	resp := do(t, "POST", base+"/v2/images/app/blobs/uploads/", "editeur", nil)
	want(t, "ouverture d'envoi", resp, http.StatusAccepted)
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/v2/images/app/blobs/uploads/") {
		t.Fatalf("Location = %q", loc)
	}
	if chunked {
		half := len(data) / 2
		resp = do(t, "PATCH", base+loc, "editeur", data[:half], "Content-Type", "application/octet-stream")
		want(t, "morceau 1", resp, http.StatusAccepted)
		loc = resp.Header.Get("Location")
		resp = do(t, "PATCH", base+loc, "editeur", data[half:], "Content-Type", "application/octet-stream")
		want(t, "morceau 2", resp, http.StatusAccepted)
		loc = resp.Header.Get("Location")
		sep := "?"
		if strings.Contains(loc, "?") {
			sep = "&"
		}
		resp = do(t, "PUT", base+loc+sep+"digest="+d, "editeur", nil)
	} else {
		sep := "?"
		if strings.Contains(loc, "?") {
			sep = "&"
		}
		resp = do(t, "PUT", base+loc+sep+"digest="+d, "editeur", data)
	}
	want(t, "clôture d'envoi", resp, http.StatusCreated)
	return d
}

func TestPushPull(t *testing.T) {
	srv := testServer(t)
	base := srv.URL

	want(t, "base sans compte", do(t, "GET", base+"/v2/", "", nil), http.StatusUnauthorized)
	want(t, "base avec compte", do(t, "GET", base+"/v2/", "lecteur", nil), http.StatusOK)

	layer := bytes.Repeat([]byte("couche "), 500)
	cfgBlob := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	ld := pushBlob(t, base, layer, true)
	cd := pushBlob(t, base, cfgBlob, false)

	// Un lecteur ne pousse pas.
	want(t, "envoi par un lecteur", do(t, "POST", base+"/v2/images/app/blobs/uploads/", "lecteur", nil), http.StatusForbidden)

	// Mauvais condensat : refusé.
	resp := do(t, "POST", base+"/v2/images/app/blobs/uploads/", "editeur", nil)
	loc := resp.Header.Get("Location")
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	resp = do(t, "PUT", base+loc+sep+"digest="+digest([]byte("autre chose")), "editeur", []byte("contenu"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("condensat faux accepté : %d", resp.StatusCode)
	}

	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd, "size": len(cfgBlob)},
		"layers":        []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": ld, "size": len(layer)}},
	})
	md := digest(manifest)
	ct := "application/vnd.oci.image.manifest.v1+json"

	// Manifeste citant une couche absente : refusé.
	bad := bytes.Replace(manifest, []byte(ld), []byte(digest([]byte("absente"))), 1)
	resp = do(t, "PUT", base+"/v2/images/app/manifests/cassé", "editeur", bad, "Content-Type", ct)
	if resp.StatusCode < 400 {
		t.Fatalf("manifeste incomplet accepté : %d", resp.StatusCode)
	}

	resp = do(t, "PUT", base+"/v2/images/app/manifests/1.0", "editeur", manifest, "Content-Type", ct)
	want(t, "manifeste", resp, http.StatusCreated)
	if resp.Header.Get("Docker-Content-Digest") != md {
		t.Fatalf("condensat annoncé %q, attendu %q", resp.Header.Get("Docker-Content-Digest"), md)
	}
	want(t, "tag latest", do(t, "PUT", base+"/v2/images/app/manifests/latest", "editeur", manifest, "Content-Type", ct), http.StatusCreated)

	// Lecture.
	resp = do(t, "HEAD", base+"/v2/images/app/manifests/1.0", "lecteur", nil)
	want(t, "HEAD manifeste", resp, http.StatusOK)
	resp = do(t, "GET", base+"/v2/images/app/manifests/"+md, "lecteur", nil)
	want(t, "GET manifeste par condensat", resp, http.StatusOK)
	if b, _ := io.ReadAll(resp.Body); !bytes.Equal(b, manifest) {
		t.Fatal("manifeste relu différent")
	}
	resp = do(t, "GET", base+"/v2/images/app/blobs/"+ld, "lecteur", nil)
	want(t, "couche", resp, http.StatusOK)
	if b, _ := io.ReadAll(resp.Body); !bytes.Equal(b, layer) {
		t.Fatal("couche relue différente")
	}
	want(t, "couche inconnue", do(t, "GET", base+"/v2/images/app/blobs/"+digest([]byte("?")), "lecteur", nil), http.StatusNotFound)
	want(t, "anonyme", do(t, "GET", base+"/v2/images/app/manifests/1.0", "", nil), http.StatusUnauthorized)

	var tags struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	resp = do(t, "GET", base+"/v2/images/app/tags/list", "lecteur", nil)
	want(t, "tags", resp, http.StatusOK)
	json.NewDecoder(resp.Body).Decode(&tags)
	if tags.Name != "images/app" || strings.Join(tags.Tags, ",") != "1.0,latest" {
		t.Fatalf("tags : %+v", tags)
	}

	// Pagination.
	resp = do(t, "GET", base+"/v2/images/app/tags/list?n=1", "lecteur", nil)
	if !strings.Contains(resp.Header.Get("Link"), "last=1.0") {
		t.Fatalf("Link = %q", resp.Header.Get("Link"))
	}

	// Montage inter-images : la couche est connue, pas de réenvoi.
	resp = do(t, "POST", base+"/v2/images/autre/blobs/uploads/?mount="+ld+"&from=images/app", "editeur", nil)
	want(t, "montage", resp, http.StatusCreated)

	// Suppression d'un tag : l'autre reste.
	want(t, "suppression du tag", do(t, "DELETE", base+"/v2/images/app/manifests/latest", "editeur", nil), http.StatusAccepted)
	want(t, "tag supprimé", do(t, "GET", base+"/v2/images/app/manifests/latest", "lecteur", nil), http.StatusNotFound)
	want(t, "tag restant", do(t, "GET", base+"/v2/images/app/manifests/1.0", "lecteur", nil), http.StatusOK)
}

func TestNotADockerRepo(t *testing.T) {
	srv := testServer(t)
	want(t, "dépôt inconnu", do(t, "GET", srv.URL+"/v2/inconnu/app/tags/list", "lecteur", nil), http.StatusNotFound)
}
