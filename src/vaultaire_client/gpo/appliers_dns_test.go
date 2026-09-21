package gpo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// machineDNS simule une machine : quelles unités sont actives, quelles
// commandes échouent. Les commandes lancées sont relevées.
type machineDNS struct {
	actives  map[string]bool
	echecs   map[string]bool
	binaires map[string]bool
	lancees  []string
}

func (m *machineDNS) installer(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	anciens := []string{resolvedDropIn, nmDropIn, resolvConf, resolvConfAvant}
	ancienRun, ancienExists := runCommand, commandExists
	t.Cleanup(func() {
		resolvedDropIn, nmDropIn, resolvConf, resolvConfAvant = anciens[0], anciens[1], anciens[2], anciens[3]
		runCommand, commandExists = ancienRun, ancienExists
	})
	resolvedDropIn = filepath.Join(dir, "resolved.conf.d", "99-vaultaire-gpo.conf")
	nmDropIn = filepath.Join(dir, "NetworkManager", "conf.d", "99-vaultaire-gpo.conf")
	resolvConf = filepath.Join(dir, "resolv.conf")
	resolvConfAvant = filepath.Join(dir, "state", "resolv.conf.avant-gpo")

	commandExists = func(name string) bool { return m.binaires[name] }
	runCommand = func(name string, args ...string) (string, error) {
		ligne := name + " " + strings.Join(args, " ")
		m.lancees = append(m.lancees, ligne)
		if name == "systemctl" && len(args) == 3 && args[0] == "is-active" {
			if m.actives[args[2]] {
				return "", nil
			}
			return "", errors.New("inactive")
		}
		if m.echecs[ligne] {
			return "", errors.New("echec simule")
		}
		return "", nil
	}
}

func (m *machineDNS) aLance(prefixe string) bool {
	for _, l := range m.lancees {
		if strings.HasPrefix(l, prefixe) {
			return true
		}
	}
	return false
}

func moduleDNS(params map[string]string) Module {
	return Module{Type: ModuleDNSResolver, Params: params}
}

// Rocky 9 : NetworkManager actif, resolved absent. Aucun `systemctl restart`
// ne doit partir — c'est lui qui « plantait ».
func TestRocky9PasseParNetworkManager(t *testing.T) {
	m := &machineDNS{
		actives:  map[string]bool{"NetworkManager": true},
		binaires: map[string]bool{"systemctl": true, "nmcli": true},
	}
	m.installer(t)

	detail, err := applyDNSResolver(Context{}, moduleDNS(map[string]string{
		"servers": "10.0.0.1, 10.0.0.2", "search_domain": "acme.lan",
	}))
	if err != nil {
		t.Fatalf("échec sur une machine NetworkManager : %v", err)
	}
	if !strings.Contains(detail, "NetworkManager") {
		t.Errorf("détail %q ne nomme pas le moteur", detail)
	}
	if m.aLance("systemctl restart") {
		t.Errorf("un service a été redémarré : %v", m.lancees)
	}
	if !m.aLance("nmcli general reload") {
		t.Errorf("NetworkManager non rechargé : %v", m.lancees)
	}
	contenu, _ := os.ReadFile(nmDropIn)
	for _, attendu := range []string{"[global-dns]", "searches=acme.lan", "[global-dns-domain-*]", "servers=10.0.0.1,10.0.0.2"} {
		if !strings.Contains(string(contenu), attendu) {
			t.Errorf("%q absent de la configuration NetworkManager :\n%s", attendu, contenu)
		}
	}
	if _, err := os.Stat(resolvedDropIn); err == nil {
		t.Error("un drop-in resolved a été écrit sur une machine sans resolved")
	}
}

// Un rechargement refusé restaure l'état précédent.
func TestNetworkManagerRestaureSurEchec(t *testing.T) {
	m := &machineDNS{
		actives:  map[string]bool{"NetworkManager": true},
		binaires: map[string]bool{"systemctl": true, "nmcli": true},
		echecs:   map[string]bool{"nmcli general reload": true, "systemctl reload NetworkManager": true},
	}
	m.installer(t)
	if _, err := applyDNSResolver(Context{}, moduleDNS(map[string]string{"servers": "10.0.0.1"})); err == nil {
		t.Fatal("un rechargement impossible doit faire échouer le module")
	}
	if _, err := os.Stat(nmDropIn); err == nil {
		t.Error("la configuration n'a pas été retirée après l'échec")
	}
}

// Debian/Ubuntu : resolved actif — le comportement historique est conservé,
// même si NetworkManager tourne aussi.
func TestResolvedPrimeSurNetworkManager(t *testing.T) {
	m := &machineDNS{
		actives:  map[string]bool{"systemd-resolved": true, "NetworkManager": true},
		binaires: map[string]bool{"systemctl": true, "nmcli": true},
	}
	m.installer(t)
	if _, err := applyDNSResolver(Context{}, moduleDNS(map[string]string{"servers": "10.0.0.1"})); err != nil {
		t.Fatal(err)
	}
	if !m.aLance("systemctl restart systemd-resolved") {
		t.Errorf("resolved non redémarré : %v", m.lancees)
	}
	if _, err := os.Stat(nmDropIn); err == nil {
		t.Error("NetworkManager configuré alors que resolved tient la résolution")
	}
}

// Ni l'un ni l'autre : resolv.conf est écrit, puis rendu tel qu'il était.
func TestResolvConfSeulEtRetrait(t *testing.T) {
	m := &machineDNS{binaires: map[string]bool{}}
	m.installer(t)
	origine := "nameserver 192.168.1.1\n"
	if err := os.WriteFile(resolvConf, []byte(origine), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := applyDNSResolver(Context{}, moduleDNS(map[string]string{"servers": "10.0.0.1,10.0.0.2"})); err != nil {
		t.Fatal(err)
	}
	contenu, _ := os.ReadFile(resolvConf)
	if got := serveursDeResolvConf(string(contenu)); strings.Join(got, ",") != "10.0.0.1,10.0.0.2" {
		t.Fatalf("resolv.conf porte %v", got)
	}
	// Réappliquer ne doit pas écraser la sauvegarde d'origine.
	if _, err := applyDNSResolver(Context{}, moduleDNS(map[string]string{"servers": "10.0.0.3"})); err != nil {
		t.Fatal(err)
	}

	if _, err := applyDNSResolver(Context{}, moduleDNS(map[string]string{"state": "absent"})); err != nil {
		t.Fatal(err)
	}
	contenu, _ = os.ReadFile(resolvConf)
	if string(contenu) != origine {
		t.Fatalf("resolv.conf non restauré : %q", contenu)
	}
	if len(m.lancees) != 0 {
		t.Errorf("des commandes ont été lancées sans systemctl : %v", m.lancees)
	}
}

func TestVerificationLitResolvConfHorsResolved(t *testing.T) {
	m := &machineDNS{binaires: map[string]bool{}}
	m.installer(t)
	_ = os.WriteFile(resolvConf, []byte("search acme.lan\nnameserver 10.0.0.2\nnameserver 10.0.0.1\n"), 0o644)

	ok, _, err := verifierServeursDNS(SystemCheck{Kind: CheckDNSServers, Target: moteurNetworkManager, Expect: "10.0.0.1 10.0.0.2"})
	if err != nil || !ok {
		t.Fatalf("conforme attendu : ok=%v err=%v", ok, err)
	}
	ok, ecart, _ := verifierServeursDNS(SystemCheck{Kind: CheckDNSServers, Target: moteurResolvConf, Expect: "10.0.0.9"})
	if ok || ecart == "" {
		t.Fatal("un écart devait être signalé")
	}
}
