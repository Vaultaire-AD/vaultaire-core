package webserveur

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSanteSansBaseRend503(t *testing.T) {
	ancien := baseDeSante
	defer func() { baseDeSante = ancien }()
	baseDeSante = func() *sql.DB { return nil }

	rec := httptest.NewRecorder()
	SanteHandler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d, attendu 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sql") || strings.Contains(rec.Body.String(), "dial") {
		t.Fatalf("la cause fuit dans une réponse anonyme : %q", rec.Body.String())
	}
}

func TestSanteRefuseLesMethodesQuiEcrivent(t *testing.T) {
	rec := httptest.NewRecorder()
	SanteHandler(rec, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code %d, attendu 405", rec.Code)
	}
}

func TestSanteEstEnregistreeSurLePortail(t *testing.T) {
	if !strings.Contains(lireSource(t, "startWEBserver.go"), `http.HandleFunc("/healthz", SanteHandler)`) {
		t.Fatal("/healthz n'est plus servi par le portail : les sondes Kubernetes échoueraient")
	}
}

func lireSource(t *testing.T, nom string) string {
	t.Helper()
	b, err := os.ReadFile(nom)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
