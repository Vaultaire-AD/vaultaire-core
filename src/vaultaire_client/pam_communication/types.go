package pamcommunication

import "strings"

// Requête unifiée reçue depuis PAM
type PamPayload struct {
	User     string `json:"user"`
	Password string `json:"password"`

	// Otp est le code de second facteur saisi à la seconde invite PAM
	// (TO-DO 95). « 0000 » quand le compte n'en a pas — c'est ce que dit
	// l'invite.
	//
	// `omitempty` est VOLONTAIREMENT ABSENT côté C : le module envoie toujours
	// le champ dès qu'il est à jour, et c'est sa PRÉSENCE qui dit au core qu'il
	// parle à un agent récent. Un champ omis parce que vide se confondrait avec
	// un agent ancien, et le core laisserait passer.
	//
	// Il n'est NI journalisé, NI mémorisé dans pamstate.AuthResult : c'est la
	// règle déjà tenue pour le mot de passe.
	Otp string `json:"otp"`
}

// Réponse unifiée renvoyée vers PAM
type Response struct {
	Status  string   `json:"status"`
	IsAdmin bool     `json:"is_admin"`
	SSHKeys []string `json:"ssh_keys"`

	// Notice est le message à afficher à l'utilisateur au moment où sa session
	// s'ouvre — mot de passe provisoire, expiration prochaine (TO-DO 99).
	//
	// `omitempty` : un module PAM resté à l'ancienne version ne lit pas ce
	// champ, et son analyseur JSON artisanal ne doit pas rencontrer une clé de
	// plus quand il n'y a rien à dire. Le cas ordinaire est l'absence.
	//
	// Ce n'est PAS un motif de refus : la réponse qui le porte vaut
	// « success ». Un motif de refus voyagerait dans `status`, que le module
	// compare déjà.
	Notice string `json:"notice,omitempty"`
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
