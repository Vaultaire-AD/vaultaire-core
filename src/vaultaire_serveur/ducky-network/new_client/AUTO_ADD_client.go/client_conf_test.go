package autoaddclientgo

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

func TestSeulsLesCoresSontEcritsDansLOrdre(t *testing.T) {
	ancien := noeudsPourInstallation
	defer func() { noeudsPourInstallation = ancien }()
	noeudsPourInstallation = func(*sql.DB) ([]clusterstorage.Node, error) {
		return []clusterstorage.Node{
			{Hostname: "proxy-lyon", IPAddress: "10.0.1.5", Port: 6666, Role: "proxy"},
			{Hostname: "core-b", IPAddress: "10.0.0.11", Port: 6666, Role: "core", AdressePublique: "203.0.113.4", PortPublic: 16666},
			{Hostname: "core-a", IPAddress: "10.0.0.10", Port: 6666, Role: "core"},
			{Hostname: "core-a-bis", IPAddress: "10.0.0.10", Port: 6666, Role: "core"},
		}, nil
	}
	dir := t.TempDir()
	n, err := EcrireConfClient(nil, dir)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var c confClient
	data, _ := os.ReadFile(filepath.Join(dir, NomConfClient))
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.Servers[0].IP != "203.0.113.4" || c.Servers[0].Port != 16666 || c.Servers[1].IP != "10.0.0.10" {
		t.Fatalf("%+v", c.Servers)
	}
}

func TestSansCoreRienNEstEcrit(t *testing.T) {
	ancien := noeudsPourInstallation
	defer func() { noeudsPourInstallation = ancien }()
	noeudsPourInstallation = func(*sql.DB) ([]clusterstorage.Node, error) { return nil, nil }
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, NomConfClient), []byte("{}"), 0o600)
	if n, err := EcrireConfClient(nil, dir); n != 0 || err != nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, NomConfClient)); err == nil {
		t.Fatal("un fichier périmé est resté")
	}
}
