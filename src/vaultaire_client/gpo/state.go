package gpo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vaultaire_client/logs"
)

// État local des politiques appliquées.
//
// Fichier /var/lib/vaultaire/applied_policies.json, en 0600 root:root. Ce chemin
// est refusé à TOUTES les GPO par les règles de restriction du serveur,
// précisément pour qu'une politique ne puisse pas réécrire l'état qui décide de
// son application.
//
// Deux niveaux d'empreinte y sont conservés, et les deux sont nécessaires :
//   - l'empreinte de politique évite de retélécharger ce qui n'a pas changé ;
//   - l'empreinte par module évite de réappliquer un module dont les paramètres
//     sont identiques. Sans elle, la moindre modification d'une politique
//     relancerait tous ses services et réinstallerait tous ses paquets.

// StateDir et StatePath localisent l'état.
const (
	StateDir  = "/var/lib/vaultaire"
	StatePath = StateDir + "/applied_policies.json"
)

// ScopeState est l'état appliqué pour un scope (ou pour un utilisateur).
type ScopeState struct {
	Fingerprint string            `json:"fingerprint"`
	Version     int               `json:"version"`
	AppliedAt   string            `json:"applied_at"`
	Status      string            `json:"status,omitempty"`
	Modules     map[string]string `json:"modules"`

	// Files associe chaque fichier déposé à son hachage attendu et au module
	// qui l'a écrit. C'est ce qui permet au scan de conformité de détecter
	// qu'un fichier a été modifié à la main, et de savoir quel module
	// réappliquer.
	//
	// CHAMP AJOUTÉ, avec omitempty : un état écrit par une version antérieure
	// n'a pas cette clé, se relit sans erreur, et le premier cycle la
	// renseigne. Aucune migration, aucune réapplication forcée.
	Files map[string]FileState `json:"files,omitempty"`
}

// ModuleFingerprint retourne l'empreinte appliquée d'un module, si connue.
func (s *ScopeState) ModuleFingerprint(stateKey string) (string, bool) {
	if s == nil || s.Modules == nil {
		return "", false
	}
	fp, ok := s.Modules[stateKey]
	return fp, ok
}

// FilesForModule rend les fichiers déposés par un module.
func (s *ScopeState) FilesForModule(stateKey string) map[string]FileState {
	if s == nil || s.Files == nil {
		return nil
	}
	out := map[string]FileState{}
	for path, state := range s.Files {
		if state.StateKey == stateKey {
			out[path] = state
		}
	}
	return out
}

// ForgetModule retire l'empreinte d'un module de l'état.
//
// Le module sera donc réapplique au prochain cycle : c'est exactement ce que
// fait la correction d'une dérive. Ses fichiers restent inventoriés, puisque
// c'est la réapplication qui les remettra à jour.
func (s *ScopeState) ForgetModule(stateKey string) {
	if s == nil || s.Modules == nil {
		return
	}
	delete(s.Modules, stateKey)
}

// State est le contenu complet du fichier d'état.
type State struct {
	Machine *ScopeState            `json:"machine,omitempty"`
	Users   map[string]*ScopeState `json:"users,omitempty"`
}

var stateMu sync.Mutex

// LoadState lit l'état local.
//
// Un fichier absent est un cas normal (premier démarrage) et retourne un état
// vide. Un fichier illisible est en revanche signalé et traité comme vide : il
// vaut mieux tout réappliquer que de se fier à un état corrompu et laisser des
// modules dans un état inconnu.
func LoadState() *State {
	stateMu.Lock()
	defer stateMu.Unlock()
	return loadStateLocked(true)
}

// loadStateLocked lit l'état sous verrou.
//
// verbose distingue une lecture demandée par un cycle d'une relecture interne
// faite avant écriture : la seconde répéterait le même message et donnerait
// l'impression que l'état est relu en boucle.
func loadStateLocked(verbose bool) *State {
	empty := &State{Users: map[string]*ScopeState{}}

	data, err := os.ReadFile(StatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logs.Write_log("WARNING", fmt.Sprintf(
				"GPO: etat local illisible (%s), toutes les GPO seront reappliquees : %v", StatePath, err))
		} else if verbose {
			logs.Write_log("DEBUG", "GPO: aucun etat local, premier demarrage")
		}
		return empty
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: etat local corrompu (%s), toutes les GPO seront reappliquees : %v", StatePath, err))
		return empty
	}
	if state.Users == nil {
		state.Users = map[string]*ScopeState{}
	}
	return &state
}

// AppliedFingerprint retourne l'empreinte appliquée pour un scope.
// Retourne "none" quand rien n'a encore été appliqué : c'est la valeur attendue
// par le protocole dans les trames 05_01 et 05_05.
func AppliedFingerprint(scope, username string) string {
	state := LoadState()
	scopeState := state.Scope(scope, username)
	if scopeState == nil || scopeState.Fingerprint == "" {
		return "none"
	}
	return scopeState.Fingerprint
}

// Scope retourne l'état d'un scope, ou nil s'il n'y en a pas.
func (s *State) Scope(scope, username string) *ScopeState {
	if s == nil {
		return nil
	}
	if scope == ScopeUser {
		if s.Users == nil {
			return nil
		}
		return s.Users[username]
	}
	return s.Machine
}

// SaveScopeState enregistre l'état appliqué d'un scope.
//
// La lecture et l'écriture sont refaites sous le même verrou : deux connexions
// utilisateur simultanées écrivent dans le même fichier, et une lecture faite
// avant l'attente du verrou perdrait l'écriture de l'autre.
func SaveScopeState(scope, username string, scopeState *ScopeState) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	state := loadStateLocked(false)
	scopeState.AppliedAt = time.Now().UTC().Format(time.RFC3339)

	if scope == ScopeUser {
		if state.Users == nil {
			state.Users = map[string]*ScopeState{}
		}
		state.Users[username] = scopeState
	} else {
		state.Machine = scopeState
	}

	return writeStateLocked(state)
}

// writeStateLocked écrit l'état de façon atomique.
//
// Écriture dans un fichier temporaire puis renommage : une coupure pendant
// l'écriture laisserait sinon un état tronqué, que le démarrage suivant
// interpréterait comme corrompu et qui provoquerait une réapplication complète
// de toutes les politiques du parc.
func writeStateLocked(state *State) error {
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return fmt.Errorf("creation de %s impossible : %v", StateDir, err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encodage de l'etat impossible : %v", err)
	}

	tmp, err := os.CreateTemp(StateDir, ".applied_policies-*.tmp")
	if err != nil {
		return fmt.Errorf("fichier temporaire d'etat impossible : %v", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("ecriture de l'etat impossible : %v", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("synchronisation de l'etat impossible : %v", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("fermeture de l'etat impossible : %v", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("permissions de l'etat impossibles : %v", err)
	}
	if err := os.Rename(tmpName, StatePath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("remplacement de l'etat impossible : %v", err)
	}

	logs.Write_log("DEBUG", "GPO: etat local mis a jour ("+filepath.Base(StatePath)+")")
	return nil
}

// ForgetUser retire l'état d'un utilisateur.
// Utile après suppression d'un compte local, pour que l'état ne grossisse pas
// indéfiniment avec des utilisateurs qui ne se connectent plus.
func ForgetUser(username string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	state := loadStateLocked(false)
	if state.Users == nil {
		return nil
	}
	if _, ok := state.Users[username]; !ok {
		return nil
	}
	delete(state.Users, username)
	logs.Write_log("DEBUG", "GPO: etat local de l'utilisateur "+username+" oublie")
	return writeStateLocked(state)
}
