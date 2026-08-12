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

// parseSSHKeys nettoie les clés SSH reçues (brutes, séparées par \n).
//
// Le résultat n'est JAMAIS nil, y compris quand le compte n'a plus aucune clé.
//
// La raison est dans le JSON, pas ici : encoding/json sérialise une tranche nil
// en `null` et une tranche vide en `[]`. Or le module PAM qui lit cette réponse
// réécrit authorized_keys à partir du tableau, et refuse d'écrire quoi que ce
// soit s'il ne trouve pas de tableau — précaution volontaire, une réponse
// tronquée ne doit pas effacer les clés d'un ayant droit.
//
// Rendre nil faisait donc passer « ce compte n'a plus de clé » pour « réponse
// illisible », et les clés révoquées restaient en place sur la machine. Un
// `[]string{}` explicite est la différence entre une révocation qui prend effet
// et une qui ne prend jamais effet.
func parseSSHKeys(rawKey string) []string {
	keys := []string{}
	if rawKey == "" {
		return keys
	}
	for _, k := range strings.Split(rawKey, "\n") {
		trimmed := strings.TrimSpace(k)
		if trimmed != "" {
			keys = append(keys, trimmed)
		}
	}
	return keys
}
