package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fichier(t *testing.T, contenu string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client_conf.json")
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// L'ancien format — une seule liste — se lit toujours.
func TestAncienFormatLu(t *testing.T) {
	p := fichier(t, `{"servers":[{"ip":"10.0.0.1","port":6666}]}`)
	if err := LoadConfig(p); err != nil {
		t.Fatal(err)
	}
	if got := AdressesConnues(); !reflect.DeepEqual(got, []string{"10.0.0.1:6666"}) {
		t.Fatalf("%v", got)
	}
	if d := GetDebug(); d.Enabled || d.IntervalSeconds != IntervalleDebugParDefaut {
		t.Fatalf("debug par défaut : %+v", d)
	}
}

// La liste apprise est écrite dans le fichier ET en mémoire, sans toucher à
// celle de l'installation ; elle passe devant.
func TestAppriseEcriteEtPrioritaire(t *testing.T) {
	p := fichier(t, `{"servers":[{"ip":"10.0.0.1","port":6666}],"debug":{"enabled":true,"interval_seconds":30}}`)
	if err := LoadConfig(p); err != nil {
		t.Fatal(err)
	}
	appris := []ServerConfig{{IP: "10.0.0.2", Port: 6666, Hostname: "core-b", Role: "core"}, {IP: "10.0.0.1", Port: 6666}}
	ecrit, err := MettreAJourAppris(appris)
	if err != nil || !ecrit {
		t.Fatalf("ecrit=%v err=%v", ecrit, err)
	}
	if got := AdressesConnues(); !reflect.DeepEqual(got, []string{"10.0.0.2:6666", "10.0.0.1:6666"}) {
		t.Fatalf("ordre : %v", got)
	}
	// Relu depuis le disque : les deux listes et le réglage de debug survivent.
	var relu Config
	data, _ := os.ReadFile(p)
	if err := json.Unmarshal(data, &relu); err != nil {
		t.Fatal(err)
	}
	if len(relu.Servers) != 1 || len(relu.Learned) != 2 || relu.Debug == nil || relu.Debug.IntervalSeconds != 30 {
		t.Fatalf("fichier : %+v", relu)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("droits changés : %v", st.Mode().Perm())
	}
	// Même liste : pas de réécriture.
	if ecrit, _ := MettreAJourAppris(appris); ecrit {
		t.Fatal("liste identique réécrite")
	}
	// Liste vide : rien n'est perdu.
	if ecrit, _ := MettreAJourAppris(nil); ecrit || len(GetLearned()) != 2 {
		t.Fatal("une liste vide a effacé la liste apprise")
	}
}

// Une écriture impossible ne change pas la mémoire.
func TestEchecDEcritureLaisseLaMemoire(t *testing.T) {
	p := fichier(t, `{"servers":[{"ip":"10.0.0.1","port":6666}]}`)
	if err := LoadConfig(p); err != nil {
		t.Fatal(err)
	}
	configMutex.Lock()
	configPath = filepath.Join(t.TempDir(), "absent", "client_conf.json")
	configMutex.Unlock()
	if _, err := MettreAJourAppris([]ServerConfig{{IP: "10.0.0.9", Port: 1}}); err == nil {
		t.Fatal("écriture dans un répertoire absent acceptée")
	}
	if len(GetLearned()) != 0 {
		t.Fatal("la mémoire a changé malgré l'échec")
	}
}
