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
//
// L'ancienne version de ce test posait une variable globale du paquet et
// vérifiait qu'EnforceDrift rendait zéro. Elle passait pour une raison qui
// n'avait rien à voir avec le mode : EnforceDrift lit /var/lib/vaultaire,
// absent en test, donc l'état était nil et la fonction sortait avant même
// d'examiner le mode. Le test aurait continué de passer si la règle avait été
// inversée.
func TestModeAuditNeCorrigePas(t *testing.T) {
	état := &ScopeState{
		Modules: map[string]string{"ssh": "fp1", "fichiers": "fp2"},
		Modes:   map[string]string{"ssh": string(DriftAudit)},
	}

	corriges, audites := partitionByMode(état, []string{"fichiers", "ssh"})

	if len(audites) != 1 || audites[0] != "ssh" {
		t.Errorf("modules audites = %v, attendu [ssh]", audites)
	}
	if len(corriges) != 1 || corriges[0] != "fichiers" {
		t.Errorf("modules corriges = %v, attendu [fichiers]", corriges)
	}
}

// TestModeInconnuVautEnforce.
//
// Le défaut d'un mécanisme de conformité doit être de faire respecter la
// configuration. Un core plus récent peut introduire un troisième mode, un état
// peut avoir été écrit par une version antérieure, une valeur peut être
// tronquée : aucun de ces trous d'information ne doit désarmer la correction en
// silence.
func TestModeInconnuVautEnforce(t *testing.T) {
	cas := map[string]*ScopeState{
		"etat sans modes":  {Modules: map[string]string{"ssh": "fp"}},
		"cle absente":      {Modes: map[string]string{"autre": string(DriftAudit)}},
		"valeur inconnue":  {Modes: map[string]string{"ssh": "observe"}},
		"valeur vide":      {Modes: map[string]string{"ssh": ""}},
		"enforce explicit": {Modes: map[string]string{"ssh": string(DriftEnforce)}},
	}

	for nom, état := range cas {
		t.Run(nom, func(t *testing.T) {
			if mode := état.ModuleMode("ssh"); mode != DriftEnforce {
				t.Errorf("mode = %q, attendu %q", mode, DriftEnforce)
			}
			corriges, audites := partitionByMode(état, []string{"ssh"})
			if len(corriges) != 1 || len(audites) != 0 {
				t.Errorf("corriges = %v, audites = %v, attendu [ssh] et []", corriges, audites)
			}
		})
	}
}

// TestModeVientDeLaPolitiqueCourante.
//
// Le mode enregistré doit refléter la politique qui vient d'être appliquée, et
// non celle de l'état précédent. Hériter de l'ancien laisserait une machine en
// audit après un retour en enforce — c'est-à-dire exactement au moment où
// l'administrateur vient de décider le contraire.
func TestModeVientDeLaPolitiqueCourante(t *testing.T) {
	précédent := &ScopeState{
		Modules: map[string]string{"ssh": "fp1"},
		Modes:   map[string]string{"ssh": string(DriftAudit)},
	}
	politique := &Policy{
		Scope:       ScopeMachine,
		Fingerprint: "fp-politique",
		Modules: []Module{
			{Type: "ssh_server_config", StateKey: "ssh", Fingerprint: "fp1"},
			{Type: "sysctl", StateKey: "sysctl", Fingerprint: "fp2", DriftMode: string(DriftAudit)},
		},
	}
	rapport := Report{
		Scope:  ScopeMachine,
		Status: StatusApplied,
		Modules: []ModuleOutcome{
			{StateKey: "ssh", Result: ResultUnchanged},
			{StateKey: "sysctl", Result: ResultApplied},
		},
	}

	état := BuildScopeState(politique, précédent, rapport)

	if mode := état.ModuleMode("ssh"); mode != DriftEnforce {
		t.Errorf("ssh repasse en %q, attendu %q — l'ancien mode a ete herite", mode, DriftEnforce)
	}
	if mode := état.ModuleMode("sysctl"); mode != DriftAudit {
		t.Errorf("sysctl = %q, attendu %q", mode, DriftAudit)
	}
	// Enforce n'est pas écrit : seules les entrées qui s'écartent du défaut le
	// sont, sinon le fichier d'état de tous les parcs grossirait d'une ligne par
	// module pour ne rien dire.
	if _, écrit := état.Modes["ssh"]; écrit {
		t.Error("le mode enforce a ete ecrit dans l'etat, il doit rester implicite")
	}
}
