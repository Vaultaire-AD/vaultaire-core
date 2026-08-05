package pamcommunication

import "strings"

// Requête unifiée reçue depuis PAM
type PamPayload struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// Réponse unifiée renvoyée vers PAM
type Response struct {
	Status  string   `json:"status"`
	IsAdmin bool     `json:"is_admin"`
	SSHKeys []string `json:"ssh_keys"`
}

// Helper pour nettoyer les clés SSH reçues (brutes avec \n)
func parseSSHKeys(rawKey string) []string {
	if rawKey == "" {
		return []string{}
	}
	var keys []string
	for _, k := range strings.Split(rawKey, "\n") {
		trimmed := strings.TrimSpace(k)
		if trimmed != "" {
			keys = append(keys, trimmed)
		}
	}
	return keys
}
