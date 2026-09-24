package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La configuration du SDK, depuis le passage à yaml.v3 (TO-DO 93).
//
// # Ce que ces tests gardent
//
//   - ce qu'on écrit se relit à l'identique : SaveConfig réécrit le fichier
//     des proxies et de Nexus ;
//   - l'indentation reste de deux espaces, celle de yaml.v2 : un diff de
//     configuration qui ne montre que de l'indentation cache la ligne qui a
//     vraiment changé.

func TestAllerRetourEtIndentation(t *testing.T) {
	ancien := configPath
	t.Cleanup(func() { configPath = ancien })
	configPath = filepath.Join(t.TempDir(), "config.yaml")

	voulu := Config{
		Servers:    []ServerConfig{{IP: "10.0.0.1", Port: 6666}, {IP: "10.0.0.2", Port: 7777}},
		Enrollment: EnrollmentConfig{Key: "cle", Label: "proxy-01"},
	}
	if err := SaveConfig(voulu); err != nil {
		t.Fatal(err)
	}
	brut, _ := os.ReadFile(configPath)
	if !strings.Contains(string(brut), "\n  key: cle") {
		t.Fatalf("sous-clé non indentée de deux espaces — yaml.v3 en met quatre "+
			"par défaut :\n%s", brut)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatal(err)
	}
	configMutex.Lock()
	relu := Configuration
	configMutex.Unlock()
	if len(relu.Servers) != 2 || relu.Servers[1].Port != 7777 || relu.Enrollment.Label != "proxy-01" {
		t.Fatalf("relu = %+v : ce qui est écrit ne se relit pas à l'identique", relu)
	}
}
