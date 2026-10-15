package action

import (
	"errors"
	"strings"
	"testing"
	"time"

	clusterdatabase "vaultaire/cluster/cluster_database"
)

// Oubli, maintenance, purge — TO-DO 146 et 147. Sans base.

type clusterSimule struct {
	maintenances  map[string]bool
	coresRestants int
	roles         map[string]string
	purges        []string
	oubli         clusterdatabase.BilanOubli
	errOubli      error
	errPurge      error
}

func simulerCluster(t *testing.T) *clusterSimule {
	t.Helper()
	c := &clusterSimule{maintenances: map[string]bool{}, roles: map[string]string{
		"core-1": "core", "core-2": "core", "proxy-1": "proxy"}}
	a1, a2, a3, a4, a5 := oublierEnBase, poserMaintenanceEnBase, coresDisponiblesHors, roleDuNoeud, demanderPurgeEnBase
	oublierEnBase = func(h string, s time.Duration) (clusterdatabase.BilanOubli, error) { return c.oubli, c.errOubli }
	poserMaintenanceEnBase = func(h string, on bool, par string) error { c.maintenances[h] = on; return nil }
	coresDisponiblesHors = func(string) (int, error) { return c.coresRestants, nil }
	roleDuNoeud = func(h string) (string, error) {
		r, ok := c.roles[h]
		if !ok {
			return "", clusterdatabase.ErrNoeudInconnu
		}
		return r, nil
	}
	demanderPurgeEnBase = func(h, par string, e int) error {
		if c.errPurge != nil {
			return c.errPurge
		}
		c.purges = append(c.purges, h)
		return nil
	}
	t.Cleanup(func() {
		oublierEnBase, poserMaintenanceEnBase, coresDisponiblesHors, roleDuNoeud, demanderPurgeEnBase = a1, a2, a3, a4, a5
	})
	return c
}

// LE garde-fou : le dernier core servi ne passe pas en maintenance sans
// confirmation — c'est la commande qui coupe le parc.
func TestLeDernierCoreDemandeConfirmation(t *testing.T) {
	c := simulerCluster(t)
	c.coresRestants = 0

	_, err := reglerMaintenance(quelquun, Params{"node": "core-1", "mode": "on"})
	var attente *ErrConfirmationRequise
	if !errors.As(err, &attente) || c.maintenances["core-1"] {
		t.Fatalf("dernier core mis en maintenance sans confirmation (err=%v)", err)
	}
	if !strings.Contains(attente.Motif, "DERNIER core") || attente.Rejouer.Get("confirm") != "yes" {
		t.Errorf("motif/rejeu : %q %v", attente.Motif, attente.Rejouer)
	}
	if _, err := reglerMaintenance(quelquun, Params{"node": "core-1", "mode": "on", "confirm": "yes"}); err != nil || !c.maintenances["core-1"] {
		t.Fatalf("confirmé : err=%v", err)
	}
}

func TestUnCoreParmiDAutresPasseSansQuestion(t *testing.T) {
	c := simulerCluster(t)
	c.coresRestants = 1
	res, err := reglerMaintenance(quelquun, Params{"node": "core-1", "mode": "on"})
	if err != nil || !c.maintenances["core-1"] {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(res.Message, "cluster purge core-1") {
		t.Errorf("le message ne dit pas comment déplacer les sessions : %s", res.Message)
	}
}

// Un proxy n'est pas soumis au garde-fou : sans lui, les agents se rabattent
// sur les cores.
func TestUnProxyNEstPasLeDernierCore(t *testing.T) {
	c := simulerCluster(t)
	c.coresRestants = 0
	if _, err := reglerMaintenance(quelquun, Params{"node": "proxy-1", "mode": "on"}); err != nil {
		t.Fatalf("proxy : %v", err)
	}
}

// Lever la maintenance ne demande jamais rien.
func TestLeverLaMaintenance(t *testing.T) {
	c := simulerCluster(t)
	c.maintenances["core-1"] = true
	if _, err := reglerMaintenance(quelquun, Params{"node": "core-1", "mode": "off"}); err != nil || c.maintenances["core-1"] {
		t.Fatalf("err=%v", err)
	}
	if _, err := reglerMaintenance(quelquun, Params{"node": "core-1", "mode": "peut-etre"}); err == nil {
		t.Error("un mode illisible a été accepté")
	}
	if _, err := reglerMaintenance(quelquun, Params{"node": "inconnu", "mode": "on"}); err == nil {
		t.Error("un nœud inconnu a été accepté")
	}
}

func TestLaPurgeNommeSesRefus(t *testing.T) {
	c := simulerCluster(t)
	for errBase, attendu := range map[error]string{
		clusterdatabase.ErrPurgeHorsMaintenance: "cluster maintenance core-1 on",
		clusterdatabase.ErrPurgePasUnCore:       "ni un core ni un proxy",
		clusterdatabase.ErrNoeudInconnu:         "aucun nœud",
	} {
		c.errPurge = errBase
		if _, err := purgerNoeud(quelquun, Params{"node": "core-1"}); err == nil || !strings.Contains(err.Error(), attendu) {
			t.Errorf("%v : refus %v, attendu « %s »", errBase, err, attendu)
		}
	}
	c.errPurge = nil
	for _, mauvais := range []string{"-1", "3601", "dix"} {
		if _, err := purgerNoeud(quelquun, Params{"node": "core-1", "spread": mauvais}); err == nil {
			t.Errorf("étalement %q accepté", mauvais)
		}
	}
	res, err := purgerNoeud(quelquun, Params{"node": "core-1", "spread": "120"})
	if err != nil || len(c.purges) != 1 || !strings.Contains(res.Message, "sur 120 s") {
		t.Fatalf("purge : %v, %v, %q", err, c.purges, res.Message)
	}
	if !strings.Contains(res.Message, "portail web") {
		t.Error("le message ne dit pas que le portail n'est pas touché")
	}
}

// Un proxy se purge aussi (TO-DO 176) : le message dit que ce sont les cores
// qui ferment, et que le proxy garde sa session.
func TestLaPurgeDUnProxyDitQueLesCoresLaFont(t *testing.T) {
	c := simulerCluster(t)
	c.roles["proxy-1"] = "proxy"
	res, err := purgerNoeud(quelquun, Params{"node": "proxy-1"})
	if err != nil || len(c.purges) != 1 {
		t.Fatalf("purge du proxy : %v, %v", err, c.purges)
	}
	for _, attendu := range []string{"Purge du proxy proxy-1", "Chaque core", "relayée", "il bat toujours", "par défaut (60 s)"} {
		if !strings.Contains(res.Message, attendu) {
			t.Errorf("message sans %q : %s", attendu, res.Message)
		}
	}
}

// L'oubli dit tout ce qui part avec la ligne.
func TestLOubliNommeCeQuiPart(t *testing.T) {
	c := simulerCluster(t)
	c.oubli = clusterdatabase.BilanOubli{Hostname: "proxy-1", Role: "proxy",
		DernierBattement: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC),
		AdresseDeclaree:  "203.0.113.5", PortPublic: 16666, Priorite: 2, HorsRotation: true,
		Groupes: []string{"Infra"}, Relais: []string{"ldaps", "nexus"}}
	res, err := oublierNoeud(quelquun, Params{"node": "proxy-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, attendu := range []string{"203.0.113.5:16666", "priorité 2", "retrait de la rotation",
		"affinité Infra", "relais demandés ldaps, nexus", "se réinscrira seul"} {
		if !strings.Contains(res.Message, attendu) {
			t.Errorf("le compte rendu ne dit pas %q :\n%s", attendu, res.Message)
		}
	}
	c.errOubli = clusterdatabase.ErrNoeudVivant
	if _, err := oublierNoeud(quelquun, Params{"node": "proxy-1"}); !errors.Is(err, clusterdatabase.ErrNoeudVivant) {
		t.Errorf("nœud vivant : %v", err)
	}
}
