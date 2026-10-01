package gpo

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Ce que ces tests gardent : le scan utilisateur existe, il ne part pas à
// chaque `sudo`, et deux connexions du même compte ne se marchent pas dessus.

// avecMemoireDesScansVide isole un test de ceux qui l'ont précédé : la mémoire
// des scans est un état de paquet, et un instant laissé derrière ferait sauter
// le scan du test suivant.
func avecMemoireDesScansVide(t *testing.T) {
	t.Helper()
	scansMu.Lock()
	ancienne := dernierScanUtilisateur
	dernierScanUtilisateur = map[string]time.Time{}
	scansMu.Unlock()
	t.Cleanup(func() {
		scansMu.Lock()
		dernierScanUtilisateur = ancienne
		scansMu.Unlock()
	})
}

// LE test du scope : le scan est le même code que côté machine, mais il n'était
// appelé que pour elle. Un inventaire utilisateur doit être examiné comme un
// autre — c'est tout l'objet du point.
func TestLaDeriveEstDetecteeDansUnHome(t *testing.T) {
	home := t.TempDir()

	envFile := filepath.Join(home, ".config", "vaultaire", "env.sh")
	hook := filepath.Join(home, ".profile.d", "vaultaire.sh")
	depose := filepath.Join(home, "Documents", "charte.txt")

	écrireFichier(t, envFile, "export EDITOR=vi\n", 0o644)
	écrireFichier(t, hook, ". ~/.config/vaultaire/env.sh\n", 0o644)
	écrireFichier(t, depose, "charte\n", 0o644)

	hEnv, _ := HashFile(envFile)
	hHook, _ := HashFile(hook)
	hDepose, _ := HashFile(depose)

	état := &ScopeState{
		Modules: map[string]string{"user_env": "fp-env", "file_deploy": "fp-fichiers"},
		Files: map[string]FileState{
			envFile: {SHA256: hEnv, Mode: 0o644, StateKey: "user_env"},
			hook:    {SHA256: hHook, Mode: 0o644, StateKey: "user_env"},
			depose:  {SHA256: hDepose, Mode: 0o644, StateKey: "file_deploy"},
		},
	}

	// L'utilisateur fait ce qu'il a parfaitement le droit de faire chez lui.
	écrireFichier(t, envFile, "export EDITOR=emacs\n", 0o644)

	rapport := scanFromState(état, ScopeUser, "alice")

	if rapport.Scope != ScopeUser || rapport.Username != "alice" {
		t.Errorf("rapport pour %q/%q, attendu %q/alice — le core range par ces deux champs",
			rapport.Scope, rapport.Username, ScopeUser)
	}
	if rapport.Checked != 3 {
		t.Errorf("elements examines = %d, attendu 3", rapport.Checked)
	}
	if rapport.Conforming() {
		t.Fatal("aucune derive detectee alors que le fichier d'environnement a change")
	}
	if modules := rapport.ModulesConcerned(); len(modules) != 1 || modules[0] != "user_env" {
		t.Errorf("modules concernes = %v, attendu [user_env] : le module intact ne doit pas "+
			"etre reapplique pour rien", modules)
	}
}

// Le mode vient de la GPO, module par module, et ne connaît pas le scope. Une
// GPO utilisateur en audit doit donc être signalée sans être corrigée — c'est
// ce qui permet un parc où les interventions dans les HOME sont légitimes.
func TestLeModeAuditVautAussiPourUnCompte(t *testing.T) {
	état := &ScopeState{
		Modules: map[string]string{"user_env": "fp-env", "file_deploy": "fp-fichiers"},
		Modes: map[string]string{
			"user_env":    string(DriftAudit),
			"file_deploy": string(DriftEnforce),
		},
	}

	corriges, audites := partitionByMode(état, []string{"user_env", "file_deploy"})

	if len(audites) != 1 || audites[0] != "user_env" {
		t.Errorf("modules audites = %v, attendu [user_env]", audites)
	}
	if len(corriges) != 1 || corriges[0] != "file_deploy" {
		t.Errorf("modules corriges = %v, attendu [file_deploy]", corriges)
	}
}

// LA raison de la borne : PAM est sollicité à chaque `ssh` ET à chaque `sudo`.
// Sans elle, un poste d'administration hacherait tout l'inventaire et enverrait
// une trame 05_15 par commande privilégiée.
func TestUnSecondPassageRapprocheNeRescannePas(t *testing.T) {
	avecMemoireDesScansVide(t)

	base := time.Now()
	if !scanDuADeja("alice", base) {
		t.Fatal("le premier passage doit scanner")
	}
	if scanDuADeja("alice", base.Add(intervalleScanUtilisateur()/2)) {
		t.Error("un second passage dans l'intervalle a relance un scan")
	}
}

// La borne rend au scope utilisateur la garantie de la machine : une
// vérification par cadence. Passé l'intervalle, le scan doit repartir.
func TestPasseLIntervalleLeScanRepart(t *testing.T) {
	avecMemoireDesScansVide(t)

	base := time.Now()
	scanDuADeja("alice", base)
	if !scanDuADeja("alice", base.Add(intervalleScanUtilisateur()+time.Second)) {
		t.Error("aucun scan apres un intervalle complet : la conformite du compte ne serait plus verifiee")
	}
}

// La borne est PAR COMPTE : sur un serveur partagé, la connexion de l'un ne
// doit pas dispenser l'autre de sa vérification.
func TestLaBorneEstParCompte(t *testing.T) {
	avecMemoireDesScansVide(t)

	base := time.Now()
	scanDuADeja("alice", base)
	if !scanDuADeja("bob", base) {
		t.Error("la connexion d'alice a dispense bob de son scan")
	}
}

// Le marquage se fait à l'ENTRÉE : deux connexions quasi simultanées ne
// doivent pas scanner toutes les deux parce que la première n'a pas fini.
func TestDeuxPassagesSimultanesNeScannentQuUneFois(t *testing.T) {
	avecMemoireDesScansVide(t)

	const passages = 20
	var attente sync.WaitGroup
	var compteurMu sync.Mutex
	scans := 0

	maintenant := time.Now()
	attente.Add(passages)
	for i := 0; i < passages; i++ {
		go func() {
			defer attente.Done()
			if scanDuADeja("alice", maintenant) {
				compteurMu.Lock()
				scans++
				compteurMu.Unlock()
			}
		}()
	}
	attente.Wait()

	if scans != 1 {
		t.Errorf("%d scans lances pour %d passages simultanes, attendu 1", scans, passages)
	}
}

// Un compte recréé sous le même nom a un HOME neuf, dont on ne sait rien :
// garder l'instant du précédent ferait sauter sa première vérification.
func TestOublierUnCompteRendSonProchainScan(t *testing.T) {
	avecMemoireDesScansVide(t)

	base := time.Now()
	scanDuADeja("alice", base)
	oublierScansUtilisateur("alice")

	if !scanDuADeja("alice", base) {
		t.Error("le compte oublie n'a pas retrouve son scan immediat")
	}
}

// Le verrou sérialise un MÊME compte et seulement lui : deux personnes qui se
// connectent en même temps sur un serveur partagé ne doivent pas s'attendre.
func TestLeVerrouEstParCompte(t *testing.T) {
	if verrouDe("alice") != verrouDe("alice") {
		t.Error("deux verrous differents pour le meme compte : rien ne serait serialise")
	}
	if verrouDe("alice") == verrouDe("bob") {
		t.Error("un seul verrou pour deux comptes : une connexion en attendrait une autre sans raison")
	}
}

// Ce que le verrou empêche : deux cycles du même compte entrelacés sur le même
// état local, dont l'un perdrait la correction de l'autre.
func TestLeVerrouSerialiseUnMemeCompte(t *testing.T) {
	verrou := verrouDe("carole")

	var enCours, maxSimultane int
	var compteurMu sync.Mutex
	var attente sync.WaitGroup

	attente.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer attente.Done()
			verrou.Lock()
			defer verrou.Unlock()

			compteurMu.Lock()
			enCours++
			if enCours > maxSimultane {
				maxSimultane = enCours
			}
			compteurMu.Unlock()

			time.Sleep(time.Millisecond)

			compteurMu.Lock()
			enCours--
			compteurMu.Unlock()
		}()
	}
	attente.Wait()

	if maxSimultane != 1 {
		t.Errorf("%d cycles simultanes sur le meme compte, attendu 1", maxSimultane)
	}
}

// Un utilisateur de passage sans GPO ne doit produire AUCUN rapport : un
// rapport vide ferait croire à une vérification réelle, et partirait à chaque
// connexion.
func TestUnCompteSansPolitiqueNeRapporteRien(t *testing.T) {
	rapport := scanFromState(nil, ScopeUser, "invite")

	if rapport.Checked != 0 {
		t.Errorf("elements examines = %d, attendu 0", rapport.Checked)
	}
	if !rapport.Conforming() {
		t.Errorf("derive signalee pour un compte sans inventaire : %v", rapport.Items)
	}
}
