package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La lecture du fichier de Nexus, depuis le passage à yaml.v3 (TO-DO 93).
//
// # Ce que ces tests gardent
//
// yaml.v2 offrait UnmarshalStrict ; v3 demande un décodeur avec KnownFields.
// Deux comportements dépendent de ce détail et aucun ne se voit en lisant le
// code :
//
//   - un champ inconnu — une faute de frappe — doit être REFUSÉ. Ignoré, il
//     laisserait Nexus tourner avec un réglage qu'on croit posé ;
//   - un fichier vide doit donner les défauts, comme avant : le décodeur v3
//     rend io.EOF là où v2 ne disait rien, et un Nexus qui refuserait de
//     démarrer sur un fichier vide changerait de comportement sans raison.

func ecrire(t *testing.T, contenu string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUnChampInconnuEstRefuse(t *testing.T) {
	_, err := Load(ecrire(t, "listen: \":8843\"\nlisten_typo: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "listen_typo") {
		t.Fatalf("err = %v : une faute de frappe doit être refusée en la nommant", err)
	}
}

func TestUnFichierVideGardeLesDefauts(t *testing.T) {
	cfg, err := Load(ecrire(t, ""))
	if err != nil && strings.Contains(err.Error(), "EOF") {
		t.Fatalf("fichier vide refusé (%v) : il donnait les défauts avec yaml.v2", err)
	}
	if cfg.Listen != Default().Listen {
		t.Fatalf("écoute = %q, attendu le défaut %q", cfg.Listen, Default().Listen)
	}
}
