package gpo

import (
	"os"
	"path/filepath"
	"testing"
)

// préparerÉtat installe un état local dans un répertoire temporaire.
//
// StatePath est une constante : le test la contourne en remplaçant la variable
// de répertoire, ce qui suppose que les deux soient des variables. Elles ne le
// sont pas — on écrit donc réellement dans le chemin attendu seulement si le
// test tourne en root. Ici on teste ScanScope à partir d'un état FOURNI, ce qui
// n'exige aucun accès privilégié.
func écrireFichier(t *testing.T, path, contenu string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contenu), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestScanDetecteLesQuatreEcarts couvre le point 4 de la TO-DO.
//
// C'est le scénario exact décrit : « un admin qui modifie manuellement
// sshd_config.d/99-vaultaire-gpo.conf en SSH direct fausserait l'état sans que
// rien ne le détecte ».
func TestScanDetecteLesQuatreEcarts(t *testing.T) {
	dir := t.TempDir()

	conforme := filepath.Join(dir, "conforme.conf")
	modifié := filepath.Join(dir, "modifie.conf")
	supprimé := filepath.Join(dir, "supprime.conf")
	droits := filepath.Join(dir, "droits.conf")

	écrireFichier(t, conforme, "contenu attendu\n", 0o644)
	écrireFichier(t, modifié, "contenu attendu\n", 0o644)
	écrireFichier(t, droits, "contenu attendu\n", 0o644)

	// L'inventaire tel que l'application l'aurait laissé.
	hash, _ := HashFile(conforme)
	état := &ScopeState{
		Modules: map[string]string{"ssh": "fp-ssh", "fichiers": "fp-fichiers"},
		Files: map[string]FileState{
			conforme: {SHA256: hash, Mode: 0o644, StateKey: "ssh"},
			modifié:  {SHA256: hash, Mode: 0o644, StateKey: "ssh"},
			supprimé: {SHA256: hash, Mode: 0o644, StateKey: "fichiers"},
			droits:   {SHA256: hash, Mode: 0o600, StateKey: "fichiers"},
		},
	}

	// Un administrateur passe par là.
	écrireFichier(t, modifié, "contenu modifie a la main\n", 0o644)

	rapport := scanFromState(état, "machine", "")

	if rapport.Checked != 4 {
		t.Errorf("fichiers examines = %d, attendu 4", rapport.Checked)
	}
	if rapport.Conforming() {
		t.Fatal("aucune derive detectee alors que trois fichiers ont change")
	}

	parChemin := map[string]DriftItem{}
	for _, item := range rapport.Items {
		parChemin[item.Path] = item
	}

	if _, dérivé := parChemin[conforme]; dérivé {
		t.Error("un fichier intact est signale comme derive")
	}
	if parChemin[modifié].Kind != DriftModified {
		t.Errorf("fichier modifie : %q, attendu %q", parChemin[modifié].Kind, DriftModified)
	}
	if parChemin[supprimé].Kind != DriftMissing {
		t.Errorf("fichier supprime : %q, attendu %q", parChemin[supprimé].Kind, DriftMissing)
	}
	if parChemin[droits].Kind != DriftPermissions {
		t.Errorf("mode change : %q, attendu %q", parChemin[droits].Kind, DriftPermissions)
	}

	// Les deux modules concernes doivent etre identifies, sans doublon.
	modules := rapport.ModulesConcerned()
	if len(modules) != 2 || modules[0] != "fichiers" || modules[1] != "ssh" {
		t.Errorf("modules concernes = %v, attendu [fichiers ssh]", modules)
	}
}

// TestScanSansInventaireNeSignaleRien.
//
// Un état écrit par une version antérieure n'a pas d'inventaire de fichiers.
// Signaler une dérive dans ce cas ferait réappliquer tout le parc à la mise à
// jour, sur la seule base d'une information manquante.
func TestScanSansInventaireNeSignaleRien(t *testing.T) {
	état := &ScopeState{Modules: map[string]string{"ssh": "fp"}}
	rapport := scanFromState(état, "machine", "")

	if !rapport.Conforming() {
		t.Errorf("derive signalee sans inventaire : %d ecart(s)", len(rapport.Items))
	}
	if rapport.Checked != 0 {
		t.Errorf("fichiers examines = %d, attendu 0", rapport.Checked)
	}
}

// TestModeAuditNeCorrigePas : le mode décide de l'effet, pas de la détection.
func TestModeAuditNeCorrigePas(t *testing.T) {
	original := CurrentDriftMode
	defer func() { CurrentDriftMode = original }()

	rapport := DriftReport{
		Scope: "machine",
		Items: []DriftItem{{Path: "/etc/x.conf", StateKey: "ssh", Kind: DriftModified}},
	}

	CurrentDriftMode = DriftAudit
	if n := EnforceDrift("machine", "", rapport); n != 0 {
		t.Errorf("mode audit : %d module(s) marque(s), attendu 0", n)
	}
}
