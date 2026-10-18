package paquetagent

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

// Le magasin en mémoire, et des agents qui jouent le rôle de l'agent réel :
// ils tiennent un jeu, demandent le suivant, le vérifient avec leurs clés.

type magasinMemoire struct {
	cles   map[string]CleStockee
	jeux   []JeuStocke
	agents []AgentJeu
}

func cleTest3072(t *testing.T) CleStockee {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	return CleStockee{Publique: &k.PublicKey, Privee: k}
}

func nouveauMagasin(t *testing.T) *magasinMemoire {
	return &magasinMemoire{cles: map[string]CleStockee{RoleActive: cleTest3072(t)}}
}

func (m *magasinMemoire) Cle(r string) (CleStockee, bool, error) {
	c, ok := m.cles[r]
	return c, ok, nil
}
func (m *magasinMemoire) GenererSuivante() (CleStockee, error) {
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return CleStockee{}, err
	}
	m.cles[RoleSuivante] = CleStockee{Publique: &k.PublicKey, Privee: k}
	return m.cles[RoleSuivante], nil
}
func (m *magasinMemoire) Basculer() error {
	m.cles[RolePrecedente], m.cles[RoleActive] = m.cles[RoleActive], m.cles[RoleSuivante]
	delete(m.cles, RoleSuivante)
	return nil
}
func (m *magasinMemoire) OublierPrecedente() error { delete(m.cles, RolePrecedente); return nil }
func (m *magasinMemoire) RemplacerCompromise() (CleStockee, error) {
	k, _ := rsa.GenerateKey(rand.Reader, 3072)
	m.cles = map[string]CleStockee{RoleActive: {Publique: &k.PublicKey, Privee: k}}
	return m.cles[RoleActive], nil
}
func (m *magasinMemoire) DernierJeu() (JeuStocke, bool, error) {
	if len(m.jeux) == 0 {
		return JeuStocke{}, false, nil
	}
	return m.jeux[len(m.jeux)-1], true, nil
}
func (m *magasinMemoire) JeuApres(n int) (JeuStocke, bool, error) {
	for _, j := range m.jeux {
		if j.Numero > n {
			return j, true, nil
		}
	}
	return JeuStocke{}, false, nil
}
func (m *magasinMemoire) AjouterJeu(j JeuStocke) error { m.jeux = append(m.jeux, j); return nil }
func (m *magasinMemoire) Agents() ([]AgentJeu, error)  { return m.agents, nil }

// agent : ce que fait vaultaire_client — demander, vérifier, appliquer.
type agent struct {
	numero int
	cles   []*rsa.PublicKey
	refus  []string
}

func installer(t *testing.T, m Magasin) *agent {
	j, err := JeuDeLInstallation(m)
	if err != nil {
		t.Fatal(err)
	}
	return &agent{numero: j.Numero, cles: j.Cles}
}

func (a *agent) rattraper(m Magasin) {
	for i := 0; i < 20; i++ {
		s, ok, _ := m.JeuApres(a.numero)
		if !ok {
			return
		}
		env, _ := LireEnveloppe(s.Enveloppe)
		j, err := VerifierJeu(s.Corps, env, a.cles)
		if err != nil {
			a.refus = append(a.refus, err.Error())
			return
		}
		a.numero, a.cles = j.Numero, j.Cles
	}
}

// accepte : un paquet signé par l'active du magasin passerait-il ?
func (a *agent) accepte(m Magasin) bool {
	active, _, _ := m.Cle(RoleActive)
	e, _ := EmpreinteCle(active.Publique)
	for _, c := range a.cles {
		if f, _ := EmpreinteCle(c); f == e {
			return true
		}
	}
	return false
}

func TestLaRotationEnTroisGestes(t *testing.T) {
	m := nouveauMagasin(t)
	ancien := installer(t, m) // numéro 0, une clé
	if ancien.numero != 0 || len(ancien.cles) != 1 {
		t.Fatalf("%+v", ancien)
	}
	endormi := installer(t, m) // ne se connectera qu'à la fin

	// 1. ajouter
	j1, err := Ajouter(m, nil)
	if err != nil || j1.Numero != 1 {
		t.Fatalf("%+v %v", j1, err)
	}
	if e, _ := LireEtat(m); e.Phase != PhaseAjoutee || e.ClesDuJeu != 2 {
		t.Fatalf("%+v", e)
	}
	if _, err := Ajouter(m, nil); err == nil {
		t.Error("deux rotations en même temps")
	}
	// Une machine installée PENDANT la rotation reçoit le jeu n°1 directement.
	neuve := installer(t, m)
	if neuve.numero != 1 || len(neuve.cles) != 2 {
		t.Fatalf("installation en cours de rotation : %+v", neuve)
	}
	ancien.rattraper(m)
	if ancien.numero != 1 || !ancien.accepte(m) {
		t.Fatalf("%+v", ancien)
	}

	// 2. basculer — refusé tant qu'un agent est en retard.
	m.agents = []AgentJeu{{ComputeurID: "a", Nom: "web01", Numero: 1}, {ComputeurID: "b", Nom: "web02", Numero: 0}}
	var retard *ErrParcEnRetard
	if err := Basculer(m, false); !errors.As(err, &retard) || !strings.Contains(err.Error(), "web02 (jeu n°0)") {
		t.Fatalf("%v", err)
	}
	m.agents[1].Numero = 1
	if err := Basculer(m, false); err != nil {
		t.Fatal(err)
	}
	if !ancien.accepte(m) || !neuve.accepte(m) {
		t.Error("une machine à jour refuse les paquets de la nouvelle active")
	}
	if endormi.accepte(m) {
		t.Error("l'endormi accepterait déjà : le test ne prouve rien")
	}

	// 3. retirer
	j2, err := Retirer(m, nil)
	if err != nil || j2.Numero != 2 {
		t.Fatalf("%+v %v", j2, err)
	}
	if e, _ := LireEtat(m); e.Phase != PhaseStable || e.ClesDuJeu != 1 {
		t.Fatalf("%+v", e)
	}
	ancien.rattraper(m)
	if ancien.numero != 2 || len(ancien.cles) != 1 || !ancien.accepte(m) {
		t.Fatalf("%+v", ancien)
	}
	// L'endormi rattrape la chaîne entière, jeu après jeu.
	endormi.rattraper(m)
	if endormi.numero != 2 || !endormi.accepte(m) || len(endormi.refus) != 0 {
		t.Fatalf("%+v", endormi)
	}

	// Une seconde rotation repart de là.
	if j3, err := Ajouter(m, nil); err != nil || j3.Numero != 3 {
		t.Fatalf("%+v %v", j3, err)
	}
}

func TestBasculerForce(t *testing.T) {
	m := nouveauMagasin(t)
	_, _ = Ajouter(m, nil)
	m.agents = []AgentJeu{{Nom: "en-retard", Numero: 0}}
	if err := Basculer(m, true); err != nil {
		t.Fatal(err)
	}
	if err := Basculer(m, true); err == nil {
		t.Error("basculer deux fois")
	}
}

func TestLesGestesDansLOrdre(t *testing.T) {
	m := nouveauMagasin(t)
	if err := Basculer(m, true); err == nil {
		t.Error("basculer sans ajouter")
	}
	if _, err := Retirer(m, nil); err == nil {
		t.Error("retirer sans basculer")
	}
	_, _ = Ajouter(m, nil)
	if _, err := Retirer(m, nil); err == nil {
		t.Error("retirer avant de basculer")
	}
}

// Hors ligne : la clé fournie doit être l'active.
func TestHorsLigne(t *testing.T) {
	m := nouveauMagasin(t)
	active := m.cles[RoleActive]
	m.cles[RoleActive] = CleStockee{Publique: active.Publique}
	if _, err := Ajouter(m, nil); err == nil || !strings.Contains(err.Error(), "--key") {
		t.Fatalf("%v", err)
	}
	autre := cleTest3072(t)
	if _, err := Ajouter(m, autre.Privee); err == nil || !strings.Contains(err.Error(), "n'est pas l'active") {
		t.Fatalf("%v", err)
	}
	if _, ok := m.cles[RoleSuivante]; ok {
		t.Error("suivante tirée malgré le refus")
	}
	if _, err := Ajouter(m, active.Privee); err != nil {
		t.Fatal(err)
	}
}

// Compromission : le jeu est signé par la NOUVELLE clé, qu'aucune machine en
// service ne tient — le canal ne peut pas l'imposer, la machine doit être
// réinstallée.
func TestCompromiseNePassePasParLeCanal(t *testing.T) {
	m := nouveauMagasin(t)
	enService := installer(t, m)
	j, err := Compromise(m)
	if err != nil || j.Numero != 1 {
		t.Fatalf("%+v %v", j, err)
	}
	enService.rattraper(m)
	if enService.numero != 0 || len(enService.refus) != 1 || !strings.Contains(enService.refus[0], "clé inconnue") {
		t.Fatalf("%+v", enService)
	}
	if enService.accepte(m) {
		t.Error("une machine en service accepte la nouvelle clé sans réinstallation")
	}
	reinstallee := installer(t, m)
	if reinstallee.numero != 1 || !reinstallee.accepte(m) {
		t.Fatalf("%+v", reinstallee)
	}
	if _, ok := m.cles[RoleSuivante]; ok {
		t.Error("une suivante survit à la compromission")
	}
}

// Un jeu ne vaut pas manifeste, ni l'inverse.
func TestJeuEtManifesteNeSeConfondentPas(t *testing.T) {
	k := cleTest3072(t)
	corps, env, err := SignerJeu(Jeu{Numero: 1, Cles: []*rsa.PublicKey{k.Publique}}, k.Privee)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verifier(corps, env, []*rsa.PublicKey{k.Publique}); err == nil {
		t.Error("un jeu vérifié comme manifeste")
	}
	if _, err := LireJeu(strings.Replace(corps, "\n1\n", "\n01\n", 1)); err == nil {
		t.Error("numéro non canonique accepté")
	}
	if _, err := LireJeu(EnteteJeu + "\n1\n"); err == nil {
		t.Error("jeu sans clé accepté")
	}
	if _, err := (Jeu{Numero: 1, Cles: []*rsa.PublicKey{k.Publique, k.Publique}}).Corps(); err == nil {
		t.Error("clé en double acceptée")
	}
}
