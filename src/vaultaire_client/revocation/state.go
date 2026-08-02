// Package revocation applique les ordres du kill switch reçus du serveur
// (catégorie de trames 06).
//
// Un ordre dit QUOI faire — verrouiller, déverrouiller, supprimer — et sur QUI.
// Jamais COMMENT : aucune commande ne circule sur le réseau. C'est ce paquet
// qui choisit les outils locaux, exactement comme les appliqueurs de GPO. Un
// ordre venu du réseau ne doit jamais pouvoir devenir du code exécuté en root.
package revocation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vaultaire_client/logs"
)

// État local des ordres déjà appliqués.
//
// Même emplacement et mêmes protections que l'état des GPO : /var/lib/vaultaire
// est refusé à toutes les politiques par les restrictions du serveur, pour
// qu'une GPO ne puisse pas réécrire l'état qui décide de son application. La
// même règle vaut ici, à plus forte raison : une politique capable d'effacer
// les révocations appliquées rouvrirait un compte coupé.
const (
	stateDir  = "/var/lib/vaultaire"
	statePath = stateDir + "/applied_revocations.json"
)

// AppliedOrder garde la trace d'un ordre exécuté.
type AppliedOrder struct {
	Mode      string `json:"mode"`
	Username  string `json:"username"`
	Result    string `json:"result"`
	AppliedAt string `json:"applied_at"`
}

// State est l'ensemble des ordres appliqués, indexés par identifiant.
type State struct {
	Orders map[string]AppliedOrder `json:"orders"`
}

var stateMu sync.Mutex

// LoadState lit l'état local.
//
// Un fichier absent n'est pas une erreur : c'est le cas au premier démarrage.
// Un fichier CORROMPU non plus — on repart d'un état vide, ce qui fera
// réappliquer les ordres. C'est sans danger, les trois modes étant idempotents,
// et infiniment préférable à un agent qui refuserait d'appliquer une révocation
// parce qu'il ne sait plus lire son propre fichier.
func LoadState() *State {
	stateMu.Lock()
	defer stateMu.Unlock()
	return loadStateLocked()
}

func loadStateLocked() *State {
	empty := &State{Orders: map[string]AppliedOrder{}}

	raw, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logs.Write_log("WARNING", "revocation: état local illisible, on repart de zéro : "+err.Error())
		}
		return empty
	}

	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		logs.Write_log("WARNING", "revocation: état local corrompu, on repart de zéro : "+err.Error())
		return empty
	}
	if s.Orders == nil {
		s.Orders = map[string]AppliedOrder{}
	}
	return &s
}

// AlreadyApplied dit si un ordre a déjà été exécuté.
//
// Un même ordre peut arriver deux fois : poussé par le serveur puis rejoué au
// démarrage, ou réémis après un acquittement perdu. On ne le rejoue pas, mais
// on le ré-acquitte — sans quoi le serveur le rejouerait indéfiniment.
func AlreadyApplied(orderID int) (AppliedOrder, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	s := loadStateLocked()
	o, ok := s.Orders[fmt.Sprint(orderID)]
	return o, ok
}

// RecordApplied enregistre un ordre exécuté.
func RecordApplied(orderID int, mode, username, result string) {
	stateMu.Lock()
	defer stateMu.Unlock()

	s := loadStateLocked()
	s.Orders[fmt.Sprint(orderID)] = AppliedOrder{
		Mode:      mode,
		Username:  username,
		Result:    result,
		AppliedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := saveStateLocked(s); err != nil {
		// L'ordre a été appliqué, seule sa trace manque : le serveur le
		// renverra, et il sera réexécuté sans dommage. On journalise sans
		// remonter d'erreur, pour ne pas transformer un succès en échec.
		logs.Write_log("WARNING", "revocation: écriture de l'état local échouée : "+err.Error())
	}
}

// saveStateLocked écrit l'état de façon atomique.
//
// Fichier temporaire puis renommage : une coupure de courant en pleine écriture
// laisserait sinon un JSON tronqué, et l'agent repartirait d'un état vide au
// prochain démarrage.
func saveStateLocked(s *State) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("création de %s : %w", stateDir, err)
	}

	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("sérialisation de l'état : %w", err)
	}

	tmp, err := os.CreateTemp(stateDir, ".applied_revocations-*.tmp")
	if err != nil {
		return fmt.Errorf("fichier temporaire : %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // sans effet après un renommage réussi

	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("écriture : %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fermeture : %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("permissions : %w", err)
	}
	if err := os.Rename(tmpName, filepath.Clean(statePath)); err != nil {
		return fmt.Errorf("renommage : %w", err)
	}
	return nil
}
