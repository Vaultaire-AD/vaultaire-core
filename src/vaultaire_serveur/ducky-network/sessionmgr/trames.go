package sessionmgr

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	networksecurity "vaultaire/ducky-network/networkSecurity"
)

// GenerateIntegrityKey génère un SessionIntegritykey unique : 32 caractères
// hexadécimaux, utilisés tels quels comme clé AES-256 une fois convertis en
// []byte (32 caractères ASCII = 32 octets). L'unicité est vérifiée
// directement contre le registre de sessions actif — plus besoin d'une map
// séparée pour ça (remplace ducky-network/sync.AddConnectionToMap /
// generateRandomKey).
func (m *Manager) GenerateIntegrityKey() (string, error) {
	const length = 32
	const maxRetries = 5

	for i := 0; i < maxRetries; i++ {
		raw := make([]byte, length)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("erreur lors de la génération de la clé : %v", err)
		}
		key := hex.EncodeToString(raw)[:length]

		m.mu.RLock()
		_, exists := m.sessions[key]
		m.mu.RUnlock()

		if !exists {
			return key, nil
		}
	}
	return "", fmt.Errorf("échec de la génération d'une clé unique après %d tentatives", maxRetries)
}

// SeedTrame initialise le suivi de l'ordre des trames pour une session,
// typiquement juste après la poignée de main initiale (Rekey vers le
// SessionIntegritykey réel). initialTrame est la trame qui vient d'être
// traitée (ex "01_01") : UpdateConnectionTrame validera tout ce qui suit à
// partir de là.
func (m *Manager) SeedTrame(sessionID, initialTrame string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.ActualTrame = initialTrame
		s.TrameIsSafe = false
	}
}

// UpdateConnectionTrame vérifie qu'une nouvelle trame suit bien l'ordre
// attendu pour cette session, et met à jour son état (remplace
// ducky-network/sync.UpdateConnectionTrame, qui faisait la même chose sur
// une sync.Map séparée et indépendante du reste de l'état de session).
//
// Une fois la séquence obligatoire terminée (TrameIsSafe == true), l'ordre
// n'est plus vérifié : les trames applicatives (GPO, host, etc.) peuvent
// arriver dans n'importe quel ordre après un login complet.
func (m *Manager) UpdateConnectionTrame(sessionID, newTrame string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session %s introuvable", sessionID)
	}

	if s.TrameIsSafe {
		return nil
	}

	if !networksecurity.IsValidNextTrame(s.ActualTrame, newTrame) {
		return fmt.Errorf("ordre de trame invalide : reçu %s après %s", newTrame, s.ActualTrame)
	}

	s.ActualTrame = newTrame

	if newTrame == networksecurity.ExpectedTrames[len(networksecurity.ExpectedTrames)-1] {
		s.TrameIsSafe = true
	}
	if newTrame == "04_01" {
		s.TrameIsSafe = true
	}

	return nil
}
