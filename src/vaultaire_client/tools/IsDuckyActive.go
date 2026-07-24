package tools

import "vaultaire_client/storage"

// IsDuckySessionActive vérifie si la session globale DuckySession existe et est prête à l'emploi.
func IsDuckySessionActive() bool {
	if storage.DuckySessionLive == nil || storage.DuckySessionLive.Conn == nil {
		return false
	}
	if !storage.DuckySessionLive.IsSafe {
		return false
	}
	return true
}
