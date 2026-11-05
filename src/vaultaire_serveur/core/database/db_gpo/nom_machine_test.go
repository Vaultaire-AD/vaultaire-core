package dbgpo

import (
	"strings"
	"testing"
	"time"
)

// TO-DO 215 : le nom d'hôte d'une machine, en premier.

func TestNomDeMachine(t *testing.T) {
	cas := []struct {
		brut, affiche string
		vrai          bool
	}{
		{"web01", "web01", true},
		{"  web01.acme.lan ", "web01.acme.lan", true},
		{"", LibelleNomInconnu, false},
		{"localhost.localdomain", LibelleNomGenerique + " (localhost.localdomain)", false},
		{"LOCALHOST", LibelleNomGenerique + " (LOCALHOST)", false},
	}
	for _, c := range cas {
		n, v := NomDeMachine(c.brut)
		if n != c.affiche || v != c.vrai {
			t.Errorf("NomDeMachine(%q) = %q, %v ; attendu %q, %v", c.brut, n, v, c.affiche, c.vrai)
		}
	}
}

func TestRegrouperGardeLeNomDHote(t *testing.T) {
	maintenant := time.Now()
	rows := []ComplianceRow{
		{ComputeurID: "A", Scope: "user", TargetUser: "alice", ReportedAt: maintenant},
		{ComputeurID: "A", Scope: "machine", ReportedAt: maintenant, Hostname: "web01"},
	}
	m := RegrouperParMachine(rows, maintenant)
	if len(m) != 1 || m[0].Hostname != "web01" || m[0].Nom() != "web01" {
		t.Fatalf("machine regroupée sans son nom : %+v", m)
	}
}

func TestTrierParNomRangeLesSansNomALaFin(t *testing.T) {
	machines := []LigneMachine{
		{ComputeurID: "z1", Hostname: "localhost.localdomain"},
		{ComputeurID: "b1", Hostname: "Zeta"},
		{ComputeurID: "a1", Hostname: ""},
		{ComputeurID: "c1", Hostname: "alpha"},
	}
	TrierParNom(machines)
	var ordre []string
	for _, m := range machines {
		ordre = append(ordre, m.ComputeurID)
	}
	if strings.Join(ordre, " ") != "c1 b1 a1 z1" {
		t.Errorf("ordre par nom = %v, attendu c1 b1 a1 z1 (alpha, Zeta, puis les sans-nom par identifiant)", ordre)
	}
}

func TestCorrespondSurLeNomEtLIdentifiant(t *testing.T) {
	m := LigneMachine{ComputeurID: "svmAFOFVMs2n-25-10-2026", Hostname: "web01.acme.lan"}
	for _, r := range []string{"", "WEB01", "acme", "svmafo", "25-10"} {
		if !m.Correspond(r) {
			t.Errorf("%q devrait trouver la machine", r)
		}
	}
	if m.Correspond("db01") {
		t.Error("« db01 » ne devrait pas trouver web01")
	}
}

func TestMachinesNommees(t *testing.T) {
	rows := []ComplianceRow{
		{ComputeurID: "A", Hostname: "web01"},
		{ComputeurID: "A", Hostname: "web01", Scope: "user"},
		{ComputeurID: "B", Hostname: "WEB01"},
		{ComputeurID: "C", Hostname: "db01"},
		{ComputeurID: "D", Hostname: "localhost.localdomain"},
	}
	if ids := MachinesNommees(rows, "web01"); strings.Join(ids, ",") != "A,B" {
		t.Errorf("web01 → %v, attendu A,B (sans casse, sans doublon)", ids)
	}
	if ids := MachinesNommees(rows, "db01"); strings.Join(ids, ",") != "C" {
		t.Errorf("db01 → %v", ids)
	}
	if ids := MachinesNommees(rows, "localhost.localdomain"); len(ids) != 0 {
		t.Errorf("un nom générique ne désigne personne, rendu %v", ids)
	}
	if ids := MachinesNommees(rows, "web"); len(ids) != 0 {
		t.Errorf("le nom est cherché EXACTEMENT, « web » a rendu %v", ids)
	}
}
