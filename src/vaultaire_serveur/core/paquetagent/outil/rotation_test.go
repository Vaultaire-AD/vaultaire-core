package outil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire/core/paquetagent"
)

type magasinTest struct {
	cles   map[string]paquetagent.CleStockee
	jeux   []paquetagent.JeuStocke
	agents []paquetagent.AgentJeu
}

func cle3072() paquetagent.CleStockee {
	k, _ := rsa.GenerateKey(rand.Reader, 3072)
	return paquetagent.CleStockee{Publique: &k.PublicKey, Privee: k}
}

func (m *magasinTest) Cle(r string) (paquetagent.CleStockee, bool, error) {
	c, ok := m.cles[r]
	return c, ok, nil
}
func (m *magasinTest) GenererSuivante() (paquetagent.CleStockee, error) {
	m.cles[paquetagent.RoleSuivante] = cle3072()
	return m.cles[paquetagent.RoleSuivante], nil
}
func (m *magasinTest) Basculer() error {
	m.cles[paquetagent.RolePrecedente] = m.cles[paquetagent.RoleActive]
	m.cles[paquetagent.RoleActive] = m.cles[paquetagent.RoleSuivante]
	delete(m.cles, paquetagent.RoleSuivante)
	return nil
}
func (m *magasinTest) OublierPrecedente() error {
	delete(m.cles, paquetagent.RolePrecedente)
	return nil
}
func (m *magasinTest) RemplacerCompromise() (paquetagent.CleStockee, error) {
	m.cles = map[string]paquetagent.CleStockee{paquetagent.RoleActive: cle3072()}
	return m.cles[paquetagent.RoleActive], nil
}
func (m *magasinTest) DernierJeu() (paquetagent.JeuStocke, bool, error) {
	if len(m.jeux) == 0 {
		return paquetagent.JeuStocke{}, false, nil
	}
	return m.jeux[len(m.jeux)-1], true, nil
}
func (m *magasinTest) JeuApres(n int) (paquetagent.JeuStocke, bool, error) {
	for _, j := range m.jeux {
		if j.Numero > n {
			return j, true, nil
		}
	}
	return paquetagent.JeuStocke{}, false, nil
}
func (m *magasinTest) AjouterJeu(j paquetagent.JeuStocke) error {
	m.jeux = append(m.jeux, j)
	return nil
}
func (m *magasinTest) Agents() ([]paquetagent.AgentJeu, error) { return m.agents, nil }

func avecMagasin(m *magasinTest) func() (Cles, error) {
	return func() (Cles, error) { return Cles{Magasin: m}, nil }
}

func TestLaRotationEnLigneDeCommande(t *testing.T) {
	m := &magasinTest{cles: map[string]paquetagent.CleStockee{paquetagent.RoleActive: cle3072()}}
	m.agents = []paquetagent.AgentJeu{{ComputeurID: "id-a", Nom: "web01"}}
	o := avecMagasin(m)

	if code, sortie, _ := executer([]string{"--pkg-key", "rotate-status"}, o); code != 0 ||
		!strings.Contains(sortie, "Rotation    : stable") || !strings.Contains(sortie, "aucun (clé de l'installation)") {
		t.Fatalf("%d %s", code, sortie)
	}
	if code, sortie, _ := executer([]string{"--pkg-key", "rotate-add"}, o); code != 0 || !strings.Contains(sortie, "Jeu n°1 publié") {
		t.Fatalf("%d %s", code, sortie)
	}
	code, _, erreurs := executer([]string{"--pkg-key", "rotate-switch"}, o)
	if code != 1 || !strings.Contains(erreurs, "web01 (jeu n°0)") || !strings.Contains(erreurs, "--force") {
		t.Fatalf("%d %s", code, erreurs)
	}
	_, sortie, _ := executer([]string{"--pkg-key", "rotate-status"}, o)
	if !strings.Contains(sortie, "en retard : web01 (id-a) — jeu n°0") || !strings.Contains(sortie, "0 sur 1") {
		t.Errorf("%s", sortie)
	}
	m.agents[0].Numero = 1
	if code, _, e := executer([]string{"--pkg-key", "rotate-switch"}, o); code != 0 {
		t.Fatalf("%s", e)
	}
	if code, sortie, _ := executer([]string{"--pkg-key", "rotate-retire"}, o); code != 0 || !strings.Contains(sortie, "Jeu n°2") {
		t.Fatalf("%d %s", code, sortie)
	}
}

func TestRotationHorsLigneParFichier(t *testing.T) {
	active := cle3072()
	m := &magasinTest{cles: map[string]paquetagent.CleStockee{paquetagent.RoleActive: {Publique: active.Publique}}}
	o := avecMagasin(m)
	if code, _, e := executer([]string{"--pkg-key", "rotate-add"}, o); code != 1 || !strings.Contains(e, "--key") {
		t.Fatalf("%d %s", code, e)
	}
	f := filepath.Join(t.TempDir(), "active.pem")
	_ = os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(active.Privee)}), 0o600)
	if code, _, e := executer([]string{"--pkg-key", "rotate-add", "--key", f}, o); code != 0 {
		t.Fatalf("%s", e)
	}
}

func TestCompromisedDemandeConfirmation(t *testing.T) {
	m := &magasinTest{cles: map[string]paquetagent.CleStockee{paquetagent.RoleActive: cle3072()}}
	o := avecMagasin(m)
	avant := m.cles[paquetagent.RoleActive]
	if code, _, e := executer([]string{"--pkg-key", "compromised"}, o); code != 1 || !strings.Contains(e, "--confirm") {
		t.Fatalf("%d %s", code, e)
	}
	if m.cles[paquetagent.RoleActive] != avant {
		t.Fatal("clé remplacée sans --confirm")
	}
	code, sortie, _ := executer([]string{"--pkg-key", "compromised", "--confirm"}, o)
	if code != 0 || !strings.Contains(sortie, "ne l'accepteront PAS par le réseau") || !strings.Contains(sortie, "-join") {
		t.Fatalf("%d %s", code, sortie)
	}
}

func TestRotationSyntaxe(t *testing.T) {
	o := avecMagasin(&magasinTest{cles: map[string]paquetagent.CleStockee{paquetagent.RoleActive: cle3072()}})
	for _, a := range [][]string{{"--pkg-key", "rotate-switch", "--key", "x"}, {"--pkg-key", "rotate-add", "--force"},
		{"--pkg-key", "rotate-status", "en-trop"}} {
		if code, _, _ := executer(a, o); code != 2 {
			t.Errorf("%v : %d", a, code)
		}
	}
}
